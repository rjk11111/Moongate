//! Client registry: registered relying parties and their exact redirect URIs.

use std::fmt;

use sqlx::PgPool;
use url::Url;

use crate::{audit, crypto};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientId(String);

impl ClientId {
    /// Lowercase letters, digits, and hyphens; mirrors the database CHECK.
    pub fn parse(value: &str) -> Option<Self> {
        let valid = (1..=63).contains(&value.len())
            && !value.starts_with('-')
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        valid.then(|| Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A redirect URI accepted for registration. Absolute, no fragment (RFC 6749 §3.1.2),
/// https unless the host is local, and already canonical so the stored string is
/// exactly what the client will send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectUri(String);

impl RedirectUri {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        let url = Url::parse(value).map_err(|_| "is not an absolute URL")?;
        match url.scheme() {
            "https" => {}
            "http" if crate::is_local_host(&url) => {}
            _ => return Err("must use https (http is allowed only for localhost)"),
        }
        if url.fragment().is_some() || value.contains('#') {
            return Err("must not contain a fragment");
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("must not contain credentials");
        }
        if url.as_str() != value {
            return Err("is not in canonical form");
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientType {
    Confidential,
    Public,
}

impl ClientType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Confidential => "confidential",
            Self::Public => "public",
        }
    }
}

/// Plaintext client secret, shown once at registration. Never logged.
pub struct ClientSecret(String);

impl ClientSecret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientSecret(<redacted>)")
    }
}

/// display_name, client_type, secret_hash, allowed_scopes, redirect_uris, post_logout_redirect_uris
type ClientRow = (
    String,
    String,
    Option<String>,
    Vec<String>,
    Vec<String>,
    Vec<String>,
);

#[derive(Debug)]
pub struct Client {
    pub id: ClientId,
    pub display_name: String,
    pub client_type: ClientType,
    pub allowed_scopes: Vec<String>,
    secret_hash: Option<String>,
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Vec<String>,
}

impl Client {
    /// Unknown and disabled clients are indistinguishable to callers.
    pub async fn find_enabled(pool: &PgPool, id: &ClientId) -> sqlx::Result<Option<Self>> {
        let row: Option<ClientRow> = sqlx::query_as(
            "SELECT c.display_name, c.client_type, c.secret_hash, c.allowed_scopes, \
                    ARRAY(SELECT redirect_uri FROM client_redirect_uris r \
                          WHERE r.client_id = c.client_id), \
                    ARRAY(SELECT redirect_uri FROM client_post_logout_redirect_uris p \
                          WHERE p.client_id = c.client_id) \
             FROM clients c WHERE c.client_id = $1 AND c.enabled",
        )
        .bind(id.as_str())
        .fetch_optional(pool)
        .await?;

        let Some((
            display_name,
            client_type,
            secret_hash,
            allowed_scopes,
            redirect_uris,
            post_logout_redirect_uris,
        )) = row
        else {
            return Ok(None);
        };
        let client_type = match client_type.as_str() {
            "confidential" => ClientType::Confidential,
            "public" => ClientType::Public,
            _ => return Err(sqlx::Error::Decode("unknown client_type".into())),
        };
        Ok(Some(Self {
            id: id.clone(),
            display_name,
            client_type,
            allowed_scopes,
            secret_hash,
            redirect_uris,
            post_logout_redirect_uris,
        }))
    }

    /// Exact string match only: no prefix, suffix, case, or normalization tolerance.
    pub fn is_registered_redirect_uri(&self, candidate: &str) -> bool {
        self.redirect_uris.iter().any(|uri| uri == candidate)
    }

    /// Exact string match against post-logout redirect URIs only.
    pub fn is_registered_post_logout_uri(&self, candidate: &str) -> bool {
        self.post_logout_redirect_uris
            .iter()
            .any(|uri| uri == candidate)
    }

    pub fn verify_secret(&self, presented: &str) -> bool {
        self.secret_hash
            .as_deref()
            .is_some_and(|hash| crypto::hash_matches(presented, hash))
    }
}

pub struct NewClient {
    pub id: ClientId,
    pub display_name: String,
    pub client_type: ClientType,
    pub redirect_uris: Vec<RedirectUri>,
    pub post_logout_redirect_uris: Vec<RedirectUri>,
}

#[derive(Debug)]
pub enum RegisterError {
    Rng,
    Database(sqlx::Error),
}

impl fmt::Display for RegisterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rng => f.write_str("random number generator failed"),
            Self::Database(error) => write!(f, "database error: {error}"),
        }
    }
}

impl std::error::Error for RegisterError {}

impl From<sqlx::Error> for RegisterError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

/// Creates a client. Returns the plaintext secret for confidential clients; it is
/// not recoverable afterwards. Fails if the client_id already exists.
pub async fn register(
    pool: &PgPool,
    new: &NewClient,
) -> Result<Option<ClientSecret>, RegisterError> {
    let secret = match new.client_type {
        ClientType::Confidential => Some(ClientSecret(
            crypto::random_token().map_err(|_| RegisterError::Rng)?,
        )),
        ClientType::Public => None,
    };

    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO clients (client_id, display_name, client_type, secret_hash) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(new.id.as_str())
    .bind(&new.display_name)
    .bind(new.client_type.as_str())
    .bind(secret.as_ref().map(|s| crypto::sha256_hex(s.expose())))
    .execute(&mut *tx)
    .await?;
    for uri in &new.redirect_uris {
        sqlx::query("INSERT INTO client_redirect_uris (client_id, redirect_uri) VALUES ($1, $2)")
            .bind(new.id.as_str())
            .bind(&uri.0)
            .execute(&mut *tx)
            .await?;
    }
    for uri in &new.post_logout_redirect_uris {
        sqlx::query(
            "INSERT INTO client_post_logout_redirect_uris (client_id, redirect_uri) VALUES ($1, $2)",
        )
        .bind(new.id.as_str())
        .bind(&uri.0)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    audit::record(
        pool,
        audit::Event::new(audit::Kind::ClientCreated).client(new.id.as_str()),
    )
    .await;
    Ok(secret)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const TEST_REDIRECT: &str = "https://rp.test/callback";
    pub(crate) const TEST_POST_LOGOUT: &str = "https://rp.test/logged-out";

    pub(crate) async fn register_test_client(
        pool: &PgPool,
        id: &str,
        client_type: ClientType,
    ) -> Option<ClientSecret> {
        let new = NewClient {
            id: ClientId::parse(id).unwrap(),
            display_name: "Test RP".into(),
            client_type,
            redirect_uris: vec![RedirectUri::parse(TEST_REDIRECT).unwrap()],
            post_logout_redirect_uris: vec![RedirectUri::parse(TEST_POST_LOGOUT).unwrap()],
        };
        register(pool, &new).await.unwrap()
    }

    async fn find(pool: &PgPool, id: &str) -> Option<Client> {
        Client::find_enabled(pool, &ClientId::parse(id).unwrap())
            .await
            .unwrap()
    }

    #[test]
    fn client_id_validation() {
        for ok in ["outlands-forums", "rp1", "a"] {
            assert!(ClientId::parse(ok).is_some(), "rejected {ok:?}");
        }
        for bad in ["", "-x", "Forums", "a b", "a_b", "é", &"a".repeat(64)] {
            assert!(ClientId::parse(bad).is_none(), "accepted {bad:?}");
        }
    }

    #[test]
    fn redirect_uri_registration_validation() {
        for ok in [
            "https://forums.uooutlands.com/connected_account.php",
            "https://rp.test/callback?x=1",
            "http://forum.localhost:9000/callback",
        ] {
            assert!(RedirectUri::parse(ok).is_ok(), "rejected {ok:?}");
        }
        for bad in [
            "http://forums.uooutlands.com/callback",
            "https://rp.test/callback#frag",
            "https://rp.test/callback#",
            "https://user:pw@rp.test/callback",
            "https://RP.test/callback",
            "https://rp.test",
            "/callback",
            "javascript:alert(1)",
        ] {
            assert!(RedirectUri::parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn client_secret_debug_is_redacted() {
        let secret = ClientSecret("hunter2".into());
        assert!(!format!("{secret:?}").contains("hunter2"));
    }

    #[sqlx::test]
    async fn confidential_client_secret_verifies(pool: PgPool) {
        let secret = register_test_client(&pool, "rp", ClientType::Confidential)
            .await
            .unwrap();
        let client = find(&pool, "rp").await.unwrap();
        assert_eq!(client.client_type, ClientType::Confidential);
        assert!(client.verify_secret(secret.expose()));
        assert!(!client.verify_secret("wrong"));
        assert!(!client.verify_secret(""));
    }

    #[sqlx::test]
    async fn client_secret_is_not_stored_in_plaintext(pool: PgPool) {
        let secret = register_test_client(&pool, "rp", ClientType::Confidential)
            .await
            .unwrap();
        let stored: String =
            sqlx::query_scalar("SELECT secret_hash FROM clients WHERE client_id = 'rp'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_ne!(stored, secret.expose());
        assert_eq!(stored, crypto::sha256_hex(secret.expose()));
    }

    #[sqlx::test]
    async fn public_client_has_no_secret(pool: PgPool) {
        assert!(
            register_test_client(&pool, "spa", ClientType::Public)
                .await
                .is_none()
        );
        let client = find(&pool, "spa").await.unwrap();
        assert_eq!(client.client_type, ClientType::Public);
        assert!(!client.verify_secret(""));
    }

    #[sqlx::test]
    async fn unknown_client_is_not_found(pool: PgPool) {
        assert!(find(&pool, "nobody").await.is_none());
    }

    #[sqlx::test]
    async fn disabled_client_is_not_found(pool: PgPool) {
        register_test_client(&pool, "rp", ClientType::Confidential).await;
        sqlx::query("UPDATE clients SET enabled = false WHERE client_id = 'rp'")
            .execute(&pool)
            .await
            .unwrap();
        assert!(find(&pool, "rp").await.is_none());
    }

    #[sqlx::test]
    async fn redirect_uri_must_match_exactly(pool: PgPool) {
        register_test_client(&pool, "rp", ClientType::Confidential).await;
        let client = find(&pool, "rp").await.unwrap();
        assert!(client.is_registered_redirect_uri(TEST_REDIRECT));
        assert!(
            !client.is_registered_redirect_uri(TEST_POST_LOGOUT),
            "post-logout URIs are not login redirect URIs"
        );
        assert!(client.is_registered_post_logout_uri(TEST_POST_LOGOUT));
        assert!(!client.is_registered_post_logout_uri(TEST_REDIRECT));
        for bad in [
            "https://rp.test/callback/",
            "https://rp.test/callback?x=1",
            "https://rp.test/callbackx",
            "https://rp.test/callback/../evil",
            "https://RP.test/callback",
            "https://rp.test/call",
            "https://evil.test/https://rp.test/callback",
            "https://rp.test.evil.test/callback",
            "http://rp.test/callback",
            "",
        ] {
            assert!(!client.is_registered_redirect_uri(bad), "matched {bad:?}");
        }
    }

    #[sqlx::test]
    async fn redirect_uris_are_scoped_to_their_client(pool: PgPool) {
        register_test_client(&pool, "rp", ClientType::Confidential).await;
        let other = NewClient {
            id: ClientId::parse("other").unwrap(),
            display_name: "Other".into(),
            client_type: ClientType::Confidential,
            redirect_uris: vec![RedirectUri::parse("https://other.test/cb").unwrap()],
            post_logout_redirect_uris: vec![],
        };
        register(&pool, &other).await.unwrap();
        let client = find(&pool, "rp").await.unwrap();
        assert!(!client.is_registered_redirect_uri("https://other.test/cb"));
    }

    #[sqlx::test]
    async fn duplicate_client_id_is_rejected(pool: PgPool) {
        register_test_client(&pool, "rp", ClientType::Confidential).await;
        let again = NewClient {
            id: ClientId::parse("rp").unwrap(),
            display_name: "Again".into(),
            client_type: ClientType::Public,
            redirect_uris: vec![],
            post_logout_redirect_uris: vec![],
        };
        assert!(register(&pool, &again).await.is_err());
    }

    #[sqlx::test]
    async fn database_requires_secret_for_confidential_clients(pool: PgPool) {
        let result = sqlx::query(
            "INSERT INTO clients (client_id, display_name, client_type) \
             VALUES ('rp', 'RP', 'confidential')",
        )
        .execute(&pool)
        .await;
        assert!(result.is_err());
    }
}
