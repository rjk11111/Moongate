//! Token signing keys.
//!
//! The private key comes from a PEM file (config) and stays in process memory.
//! Only the public JWK is stored in `signing_keys`, which is the source of truth
//! for JWKS so every instance publishes every key that may still verify a token.

use std::fmt;

use jsonwebtoken::jwk::{Jwk, JwkSet, PublicKeyUse, ThumbprintHash};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use sqlx::PgPool;
use sqlx::types::Json;

use crate::audit;

/// The only algorithm Moongate signs with. RS256 is the OIDC default every RP supports.
pub const ALGORITHM: Algorithm = Algorithm::RS256;

pub struct SigningKey {
    kid: String,
    key: EncodingKey,
    public_jwk: Jwk,
}

/// Never print key material.
impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Parses an RSA private key (PKCS#1 or PKCS#8 PEM). Signs a probe token so an
    /// unusable key (e.g. too small for aws-lc) fails at startup, not on first login.
    pub fn from_pem(pem: &[u8]) -> Result<Self, jsonwebtoken::errors::Error> {
        let key = EncodingKey::from_rsa_pem(pem)?;
        let mut public_jwk = Jwk::from_encoding_key(&key, ALGORITHM)?;
        let kid = public_jwk.thumbprint(ThumbprintHash::SHA256)?;
        public_jwk.common.key_id = Some(kid.clone());
        public_jwk.common.public_key_use = Some(PublicKeyUse::Signature);

        let signing_key = Self {
            kid,
            key,
            public_jwk,
        };
        signing_key.sign(&serde_json::json!({}))?;
        Ok(signing_key)
    }

    pub fn public_jwk(&self) -> &Jwk {
        &self.public_jwk
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn sign(&self, claims: &impl Serialize) -> Result<String, jsonwebtoken::errors::Error> {
        let mut header = Header::new(ALGORITHM);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, claims, &self.key)
    }

    /// Makes this key the single active key. Any other active key becomes
    /// `retiring` and stays published, so tokens it signed keep validating.
    /// Idempotent: restarting with the same key changes nothing.
    pub async fn activate(&self, pool: &PgPool) -> sqlx::Result<()> {
        let mut tx = pool.begin().await?;
        // Serialize concurrent instance startups so they can't race on the single-active index.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('moongate.signing_keys'))")
            .execute(&mut *tx)
            .await?;

        let demoted: Vec<String> = sqlx::query_scalar(
            "UPDATE signing_keys SET status = 'retiring', retiring_at = now() \
             WHERE status = 'active' AND kid <> $1 RETURNING kid",
        )
        .bind(&self.kid)
        .fetch_all(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO signing_keys (kid, algorithm, public_jwk, status) \
             VALUES ($1, 'RS256', $2, 'active') \
             ON CONFLICT (kid) DO UPDATE SET \
                 status = 'active', \
                 retiring_at = NULL, \
                 retired_at = NULL, \
                 activated_at = CASE WHEN signing_keys.status = 'active' \
                                     THEN signing_keys.activated_at ELSE now() END",
        )
        .bind(&self.kid)
        .bind(Json(&self.public_jwk))
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        if !demoted.is_empty() {
            tracing::info!(previous = ?demoted, "previous signing keys now retiring");
            audit::record(
                pool,
                audit::Event::new(audit::Kind::SigningKeyRotated).kid(&self.kid),
            )
            .await;
        }
        Ok(())
    }
}

/// Every public key that may still verify a live token.
pub async fn published_jwks(pool: &PgPool) -> sqlx::Result<JwkSet> {
    let keys: Vec<Json<Jwk>> = sqlx::query_scalar(
        "SELECT public_jwk FROM signing_keys \
         WHERE status IN ('active', 'retiring') ORDER BY activated_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(JwkSet {
        keys: keys.into_iter().map(|Json(jwk)| jwk).collect(),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::{KeyPair, KeySize};
    use jsonwebtoken::{DecodingKey, Validation};
    use serde_json::{Value, json};

    use super::*;

    /// Fresh throwaway key per call; no private keys are committed as fixtures.
    pub(crate) fn test_key() -> SigningKey {
        let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let der = AsDer::as_der(&pair).unwrap();
        let pem = pem::encode(&pem::Pem::new("PRIVATE KEY", der.as_ref()));
        SigningKey::from_pem(pem.as_bytes()).unwrap()
    }

    fn token(key: &SigningKey) -> String {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;
        key.sign(&json!({ "sub": "test", "exp": exp })).unwrap()
    }

    /// Verifies the way an RP does: find the token's kid in the published JWKS.
    fn verify_with(jwks: &JwkSet, token: &str) -> jsonwebtoken::errors::Result<Value> {
        let kid = jsonwebtoken::decode_header(token)?.kid.unwrap();
        let jwk = jwks
            .find(&kid)
            .ok_or(jsonwebtoken::errors::ErrorKind::InvalidToken)?;
        let key = DecodingKey::from_jwk(jwk)?;
        jsonwebtoken::decode::<Value>(token, &key, &Validation::new(ALGORITHM)).map(|t| t.claims)
    }

    async fn status(pool: &PgPool, kid: &str) -> String {
        sqlx::query_scalar("SELECT status FROM signing_keys WHERE kid = $1")
            .bind(kid)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[test]
    fn kid_is_rfc7638_thumbprint() {
        let key = test_key();
        assert_eq!(
            key.public_jwk.thumbprint(ThumbprintHash::SHA256).unwrap(),
            key.kid()
        );
    }

    #[test]
    fn public_jwk_contains_no_private_material() {
        let jwk = serde_json::to_value(&test_key().public_jwk).unwrap();
        for private in ["d", "p", "q", "dp", "dq", "qi"] {
            assert!(jwk.get(private).is_none(), "JWK leaked {private}");
        }
        assert_eq!(jwk["kty"], "RSA");
        assert_eq!(jwk["alg"], "RS256");
        assert_eq!(jwk["use"], "sig");
    }

    #[test]
    fn debug_output_shows_only_kid() {
        let key = test_key();
        assert_eq!(
            format!("{key:?}"),
            format!("SigningKey {{ kid: {:?}, .. }}", key.kid())
        );
    }

    #[test]
    fn garbage_pem_is_rejected() {
        assert!(SigningKey::from_pem(b"not a key").is_err());
    }

    #[test]
    fn signed_token_carries_kid_and_rs256() {
        let key = test_key();
        let header = jsonwebtoken::decode_header(token(&key)).unwrap();
        assert_eq!(header.kid.as_deref(), Some(key.kid()));
        assert_eq!(header.alg, Algorithm::RS256);
    }

    #[sqlx::test]
    async fn active_key_validates_tokens_via_jwks(pool: PgPool) {
        let key = test_key();
        key.activate(&pool).await.unwrap();
        let jwks = published_jwks(&pool).await.unwrap();
        assert_eq!(verify_with(&jwks, &token(&key)).unwrap()["sub"], "test");
    }

    #[sqlx::test]
    async fn token_from_unpublished_key_is_rejected(pool: PgPool) {
        test_key().activate(&pool).await.unwrap();
        let jwks = published_jwks(&pool).await.unwrap();
        assert!(verify_with(&jwks, &token(&test_key())).is_err());
    }

    #[sqlx::test]
    async fn rotated_key_remains_published_and_valid(pool: PgPool) {
        let (old, new) = (test_key(), test_key());
        old.activate(&pool).await.unwrap();
        let old_token = token(&old);
        new.activate(&pool).await.unwrap();

        assert_eq!(status(&pool, old.kid()).await, "retiring");
        assert_eq!(status(&pool, new.kid()).await, "active");
        let jwks = published_jwks(&pool).await.unwrap();
        assert_eq!(jwks.keys.len(), 2);
        assert!(verify_with(&jwks, &old_token).is_ok());
        assert!(verify_with(&jwks, &token(&new)).is_ok());
    }

    #[sqlx::test]
    async fn retired_key_is_not_published(pool: PgPool) {
        let (old, new) = (test_key(), test_key());
        old.activate(&pool).await.unwrap();
        new.activate(&pool).await.unwrap();
        sqlx::query("UPDATE signing_keys SET status = 'retired' WHERE kid = $1")
            .bind(old.kid())
            .execute(&pool)
            .await
            .unwrap();

        let jwks = published_jwks(&pool).await.unwrap();
        assert!(jwks.find(old.kid()).is_none());
        assert!(jwks.find(new.kid()).is_some());
    }

    #[sqlx::test]
    async fn reactivating_same_key_is_idempotent(pool: PgPool) {
        let key = test_key();
        key.activate(&pool).await.unwrap();
        key.activate(&pool).await.unwrap();
        assert_eq!(published_jwks(&pool).await.unwrap().keys.len(), 1);
        assert_eq!(status(&pool, key.kid()).await, "active");
    }

    #[sqlx::test]
    async fn database_rejects_second_active_key(pool: PgPool) {
        test_key().activate(&pool).await.unwrap();
        let result = sqlx::query(
            "INSERT INTO signing_keys (kid, algorithm, public_jwk, status) \
             VALUES ('other', 'RS256', '{}', 'active')",
        )
        .execute(&pool)
        .await;
        assert!(result.is_err());
    }
}
