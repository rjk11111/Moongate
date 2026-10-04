//! Moongate SSO sessions: server-side state behind an opaque, host-only cookie.

use std::fmt;

use axum::http::{HeaderMap, HeaderValue, header};
use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::Issuer;
use crate::identity::SubjectId;
use crate::{audit, crypto};

/// Absolute session lifetime; there is no sliding renewal.
// ponytail: no idle timeout; add one if 12h absolute sessions prove too long.
pub const SESSION_LIFETIME_SECS: i64 = 12 * 60 * 60;

/// Plaintext session token. Lives only in the cookie and in memory, never logged.
pub struct SessionToken(String);

impl SessionToken {
    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken(<redacted>)")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Session {
    pub subject: SubjectId,
    /// Seconds since the epoch; becomes the ID token's `auth_time`.
    pub authenticated_at: i64,
}

#[derive(Debug)]
pub enum SessionError {
    Rng,
    Database(sqlx::Error),
}

impl From<sqlx::Error> for SessionError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

/// Starts a new session. Callers rotate: revoke any session the browser already
/// presented before issuing this one, so a pre-login token never becomes authenticated.
pub async fn create(
    pool: &PgPool,
    subject: SubjectId,
) -> Result<(SessionToken, Session), SessionError> {
    let token = SessionToken(crypto::random_token().map_err(|_| SessionError::Rng)?);
    let authenticated_at: i64 = sqlx::query_scalar(
        "INSERT INTO sessions (token_hash, subject_id, expires_at) \
         VALUES ($1, $2, now() + make_interval(secs => $3)) \
         RETURNING extract(epoch FROM authenticated_at)::bigint",
    )
    .bind(crypto::sha256_hex(token.expose()))
    .bind(subject.as_uuid())
    .bind(SESSION_LIFETIME_SECS as f64)
    .fetch_one(pool)
    .await?;
    audit::record(
        pool,
        audit::Event::new(audit::Kind::SessionCreated).subject(subject),
    )
    .await;
    Ok((
        token,
        Session {
            subject,
            authenticated_at,
        },
    ))
}

/// The live session for `token`, if it exists, is unexpired, unrevoked, and its
/// subject is not disabled. Touches `last_seen_at`.
pub async fn find_active(pool: &PgPool, token: &str) -> sqlx::Result<Option<Session>> {
    let row: Option<(Uuid, i64)> = sqlx::query_as(
        "UPDATE sessions s SET last_seen_at = now() \
         FROM subjects sub \
         WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now() \
           AND sub.id = s.subject_id AND sub.disabled_at IS NULL \
         RETURNING s.subject_id, extract(epoch FROM s.authenticated_at)::bigint",
    )
    .bind(crypto::sha256_hex(token))
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(subject, authenticated_at)| Session {
        subject: SubjectId::from_uuid(subject),
        authenticated_at,
    }))
}

pub async fn revoke(pool: &PgPool, token: &str) -> sqlx::Result<()> {
    let revoked: Option<Uuid> = sqlx::query_scalar(
        "UPDATE sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL \
         RETURNING subject_id",
    )
    .bind(crypto::sha256_hex(token))
    .fetch_optional(pool)
    .await?;
    if let Some(subject) = revoked {
        audit::record(
            pool,
            audit::Event::new(audit::Kind::SessionDestroyed).subject(SubjectId::from_uuid(subject)),
        )
        .await;
    }
    Ok(())
}

/// How a Moongate cookie is named and flagged for this deployment.
/// https issuers get `__Host-` (Secure, Path=/, no Domain: the browser refuses it from
/// any other host, including sibling `*.uooutlands.com` apps). Plain-http localhost
/// development gets an unprefixed, non-Secure cookie that browsers will accept.
#[derive(Clone, Debug)]
pub struct CookiePolicy {
    name: &'static str,
    secure: bool,
    same_site: &'static str,
    max_age: i64,
}

impl CookiePolicy {
    /// The SSO session cookie. Lax, because relying parties reach `/authorize` by
    /// cross-site top-level navigation and the session must be visible there.
    pub fn session(issuer: &Issuer) -> Self {
        let https = issuer.as_str().starts_with("https://");
        Self {
            name: if https {
                "__Host-moongate_session"
            } else {
                "moongate_session"
            },
            secure: https,
            same_site: "Lax",
            max_age: SESSION_LIFETIME_SECS,
        }
    }

    /// The login-form CSRF cookie. Strict: it is only ever needed on the same-site
    /// POST from Moongate's own login page, so a cross-site form post never carries it.
    pub fn csrf(issuer: &Issuer) -> Self {
        let https = issuer.as_str().starts_with("https://");
        Self {
            name: if https {
                "__Host-moongate_csrf"
            } else {
                "moongate_csrf"
            },
            secure: https,
            same_site: "Strict",
            max_age: 60 * 60,
        }
    }

    pub fn set_cookie(&self, token: &SessionToken) -> HeaderValue {
        self.set(token.expose())
    }

    /// `value` must be a token from `crypto::random_token`.
    pub(crate) fn set(&self, value: &str) -> HeaderValue {
        self.header(value, self.max_age)
    }

    pub fn clear_cookie(&self) -> HeaderValue {
        self.header("", 0)
    }

    fn header(&self, value: &str, max_age: i64) -> HeaderValue {
        let secure = if self.secure { "; Secure" } else { "" };
        let cookie = format!(
            "{}={value}; Path=/; HttpOnly; SameSite={}; Max-Age={max_age}{secure}",
            self.name, self.same_site
        );
        // Name and value are fixed ASCII or hex, so this cannot fail.
        HeaderValue::from_str(&cookie).unwrap_or_else(|_| HeaderValue::from_static(""))
    }

    /// The token from the request, if exactly one well-formed one is present.
    /// Duplicates are refused: a second cookie with our name means something other
    /// than Moongate set it.
    pub fn read(&self, headers: &HeaderMap) -> Option<String> {
        let mut found = headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .filter(|(name, _)| *name == self.name)
            .map(|(_, value)| value);
        let token = found.next()?;
        let well_formed = token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit());
        (found.next().is_none() && well_formed).then(|| token.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::resolve_subject;
    use crate::upstream::{OutlandsId, UpstreamIdentity};

    async fn subject(pool: &PgPool) -> SubjectId {
        let identity = UpstreamIdentity {
            outlands_id: OutlandsId::parse("10001").unwrap(),
            email: "player@moongate.localhost".into(),
            role: "player".into(),
        };
        resolve_subject(pool, &identity).await.unwrap()
    }

    fn https() -> CookiePolicy {
        CookiePolicy::session(&Issuer::parse("https://moongate.test").unwrap())
    }

    fn cookies(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(header::COOKIE, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[sqlx::test]
    async fn created_session_is_found(pool: PgPool) {
        let subject = subject(&pool).await;
        let (token, created) = create(&pool, subject).await.unwrap();
        let session = find_active(&pool, token.expose()).await.unwrap().unwrap();
        assert_eq!(session, created);
        assert_eq!(session.subject, subject);
        assert!(session.authenticated_at > 0);
    }

    #[sqlx::test]
    async fn unknown_token_is_not_found(pool: PgPool) {
        let token = crypto::random_token().unwrap();
        assert!(find_active(&pool, &token).await.unwrap().is_none());
    }

    #[sqlx::test]
    async fn revoked_session_is_not_found(pool: PgPool) {
        let token = create(&pool, subject(&pool).await).await.unwrap().0;
        revoke(&pool, token.expose()).await.unwrap();
        assert!(find_active(&pool, token.expose()).await.unwrap().is_none());
    }

    #[sqlx::test]
    async fn revoke_affects_only_that_session(pool: PgPool) {
        let subject = subject(&pool).await;
        let (a, b) = (
            create(&pool, subject).await.unwrap().0,
            create(&pool, subject).await.unwrap().0,
        );
        revoke(&pool, a.expose()).await.unwrap();
        assert!(find_active(&pool, b.expose()).await.unwrap().is_some());
    }

    #[sqlx::test]
    async fn expired_session_is_not_found(pool: PgPool) {
        let token = create(&pool, subject(&pool).await).await.unwrap().0;
        sqlx::query(
            "UPDATE sessions SET created_at = now() - interval '2 days', \
                                 expires_at = now() - interval '1 second'",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(find_active(&pool, token.expose()).await.unwrap().is_none());
    }

    #[sqlx::test]
    async fn disabled_subject_session_is_not_found(pool: PgPool) {
        let token = create(&pool, subject(&pool).await).await.unwrap().0;
        sqlx::query("UPDATE subjects SET disabled_at = now()")
            .execute(&pool)
            .await
            .unwrap();
        assert!(find_active(&pool, token.expose()).await.unwrap().is_none());
    }

    #[sqlx::test]
    async fn session_token_is_stored_hashed(pool: PgPool) {
        let token = create(&pool, subject(&pool).await).await.unwrap().0;
        let stored: String = sqlx::query_scalar("SELECT token_hash FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_ne!(stored, token.expose());
        assert_eq!(stored, crypto::sha256_hex(token.expose()));
    }

    #[test]
    fn session_token_debug_is_redacted() {
        let token = SessionToken("a".repeat(64));
        assert!(!format!("{token:?}").contains("aaaa"));
    }

    #[test]
    fn https_cookie_is_host_only_secure_httponly_lax() {
        let cookie = https().set_cookie(&SessionToken("a".repeat(64)));
        let cookie = cookie.to_str().unwrap();
        assert!(cookie.starts_with("__Host-moongate_session="));
        for attribute in ["; Path=/", "; HttpOnly", "; SameSite=Lax", "; Secure"] {
            assert!(cookie.contains(attribute), "missing {attribute}");
        }
        assert!(!cookie.to_ascii_lowercase().contains("domain"));
    }

    #[test]
    fn local_http_cookie_is_not_secure_or_host_prefixed() {
        let policy =
            CookiePolicy::session(&Issuer::parse("http://moongate.localhost:8090").unwrap());
        let cookie = policy.set_cookie(&SessionToken("a".repeat(64)));
        let cookie = cookie.to_str().unwrap();
        assert!(cookie.starts_with("moongate_session="));
        assert!(!cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
    }

    #[test]
    fn csrf_cookie_is_strict_and_host_only() {
        let policy = CookiePolicy::csrf(&Issuer::parse("https://moongate.test").unwrap());
        let cookie = policy.set(&"a".repeat(64));
        let cookie = cookie.to_str().unwrap();
        assert!(cookie.starts_with("__Host-moongate_csrf="));
        assert!(cookie.contains("; SameSite=Strict"));
        assert!(cookie.contains("; Secure"));
        assert!(cookie.contains("; HttpOnly"));
    }

    #[test]
    fn clear_cookie_expires_immediately() {
        let cookie = https().clear_cookie();
        assert!(cookie.to_str().unwrap().contains("Max-Age=0"));
    }

    #[test]
    fn read_finds_token_among_other_cookies() {
        let token = "ab".repeat(32);
        let headers = cookies(&[&format!(
            "xf_session=1; __Host-moongate_session={token}; y=2"
        )]);
        assert_eq!(https().read(&headers), Some(token));
    }

    #[test]
    fn read_refuses_duplicate_cookies() {
        let (a, b) = ("ab".repeat(32), "cd".repeat(32));
        let headers = cookies(&[&format!(
            "__Host-moongate_session={a}; __Host-moongate_session={b}"
        )]);
        assert_eq!(https().read(&headers), None);
        let split = cookies(&[
            &format!("__Host-moongate_session={a}"),
            &format!("__Host-moongate_session={b}"),
        ]);
        assert_eq!(https().read(&split), None);
    }

    #[test]
    fn read_refuses_malformed_or_lookalike_cookies() {
        for value in [
            "__Host-moongate_session=short".to_string(),
            format!("__Host-moongate_session={}", "z".repeat(64)),
            format!("x__Host-moongate_session={}", "ab".repeat(32)),
            format!("moongate_session={}", "ab".repeat(32)),
            String::new(),
        ] {
            assert_eq!(
                https().read(&cookies(&[&value])),
                None,
                "accepted {value:?}"
            );
        }
    }
}
