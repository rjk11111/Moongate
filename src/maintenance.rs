//! Periodic housekeeping. Every statement is idempotent, so any number of instances
//! may run it concurrently.

use std::time::Duration;

use sqlx::PgPool;

use crate::audit;
use crate::token::ID_TOKEN_LIFETIME_SECS;

pub const INTERVAL: Duration = Duration::from_secs(10 * 60);

/// How long a retiring key stays in JWKS after it stopped signing. Must exceed the
/// ID token lifetime plus the JWKS cache max-age (5 minutes), with margin for clock skew
/// and slow relying parties.
pub const KEY_VALIDATION_WINDOW_SECS: i64 = 60 * 60;
const _: () = assert!(KEY_VALIDATION_WINDOW_SECS > ID_TOKEN_LIFETIME_SECS + 300);

/// Consumed codes are kept this long after expiry so a replay is still recognized
/// (and logged) rather than looking like an unknown code.
const CODE_RETENTION_SECS: i64 = 60 * 60;
/// Ended sessions are kept briefly for incident review.
const SESSION_RETENTION_SECS: i64 = 24 * 60 * 60;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub codes_deleted: u64,
    pub sessions_deleted: u64,
    pub keys_retired: Vec<String>,
}

pub async fn run_once(pool: &PgPool) -> sqlx::Result<Report> {
    let codes_deleted = sqlx::query(
        "DELETE FROM authorization_codes WHERE expires_at < now() - make_interval(secs => $1)",
    )
    .bind(CODE_RETENTION_SECS as f64)
    .execute(pool)
    .await?
    .rows_affected();

    let sessions_deleted = sqlx::query(
        "DELETE FROM sessions \
         WHERE expires_at < now() - make_interval(secs => $1) \
            OR revoked_at < now() - make_interval(secs => $1)",
    )
    .bind(SESSION_RETENTION_SECS as f64)
    .execute(pool)
    .await?
    .rows_affected();

    let keys_retired: Vec<String> = sqlx::query_scalar(
        "UPDATE signing_keys SET status = 'retired', retired_at = now() \
         WHERE status = 'retiring' AND retiring_at < now() - make_interval(secs => $1) \
         RETURNING kid",
    )
    .bind(KEY_VALIDATION_WINDOW_SECS as f64)
    .fetch_all(pool)
    .await?;
    for kid in &keys_retired {
        audit::record(
            pool,
            audit::Event::new(audit::Kind::SigningKeyRetired).kid(kid),
        )
        .await;
    }

    Ok(Report {
        codes_deleted,
        sessions_deleted,
        keys_retired,
    })
}

/// Runs `run_once` now and then every `INTERVAL`, logging failures and carrying on.
pub fn spawn(pool: PgPool) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(INTERVAL);
        loop {
            ticker.tick().await;
            match run_once(&pool).await {
                Ok(report) => tracing::debug!(?report, "maintenance finished"),
                Err(error) => tracing::warn!(%error, "maintenance failed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::published_jwks;
    use crate::signing::tests::test_key;

    const HOUR: f64 = 3600.0;
    const DAY: f64 = 24.0 * HOUR;

    async fn seed_subject_and_client(pool: &PgPool) -> sqlx::types::Uuid {
        crate::client::tests::register_test_client(pool, "rp", crate::client::ClientType::Public)
            .await;
        sqlx::query_scalar("INSERT INTO subjects DEFAULT VALUES RETURNING id")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn insert_code(
        pool: &PgPool,
        subject: sqlx::types::Uuid,
        hash: &str,
        expired_secs_ago: f64,
    ) {
        sqlx::query(
            "INSERT INTO authorization_codes \
                 (code_hash, client_id, subject_id, redirect_uri, scopes, auth_time, created_at, expires_at) \
             VALUES ($1, 'rp', $2, 'https://rp.test/callback', '{openid}', now(), \
                     now() - make_interval(secs => $3 + 60), now() - make_interval(secs => $3))",
        )
        .bind(hash)
        .bind(subject)
        .bind(expired_secs_ago)
        .execute(pool)
        .await
        .unwrap();
    }

    #[sqlx::test]
    async fn deletes_only_long_expired_codes(pool: PgPool) {
        let subject = seed_subject_and_client(&pool).await;
        insert_code(&pool, subject, "old", 2.0 * HOUR).await;
        insert_code(&pool, subject, "recent", 300.0).await;
        let report = run_once(&pool).await.unwrap();
        assert_eq!(report.codes_deleted, 1);
        let left: String = sqlx::query_scalar("SELECT code_hash FROM authorization_codes")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, "recent");
    }

    #[sqlx::test]
    async fn deletes_only_long_ended_sessions(pool: PgPool) {
        let subject = seed_subject_and_client(&pool).await;
        // (hash, created secs ago, expires secs ago (negative = future), revoked secs ago)
        for (hash, created, expires, revoked) in [
            ("expired", 3.0 * DAY, 2.0 * DAY, None),
            ("revoked", 3.0 * DAY, -DAY, Some(2.0 * DAY)),
            ("live", HOUR, -11.0 * HOUR, None),
            ("just-revoked", HOUR, -11.0 * HOUR, Some(60.0)),
        ] {
            sqlx::query(
                "INSERT INTO sessions (token_hash, subject_id, created_at, expires_at, revoked_at) \
                 VALUES ($1, $2, now() - make_interval(secs => $3), now() - make_interval(secs => $4), \
                         now() - make_interval(secs => $5::float8))",
            )
            .bind(hash)
            .bind(subject)
            .bind(created)
            .bind(expires)
            .bind(revoked)
            .execute(&pool)
            .await
            .unwrap();
        }
        assert_eq!(run_once(&pool).await.unwrap().sessions_deleted, 2);
        let left: Vec<String> =
            sqlx::query_scalar("SELECT token_hash FROM sessions ORDER BY token_hash")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(left, ["just-revoked", "live"]);
    }

    #[sqlx::test]
    async fn retiring_key_is_retired_only_after_validation_window(pool: PgPool) {
        let (old, new) = (test_key(), test_key());
        old.activate(&pool).await.unwrap();
        new.activate(&pool).await.unwrap();

        // Just rotated: the old key must stay published.
        assert!(run_once(&pool).await.unwrap().keys_retired.is_empty());
        assert!(
            published_jwks(&pool)
                .await
                .unwrap()
                .find(old.kid())
                .is_some()
        );

        sqlx::query(
            "UPDATE signing_keys SET retiring_at = now() - interval '2 hours' WHERE kid = $1",
        )
        .bind(old.kid())
        .execute(&pool)
        .await
        .unwrap();
        let report = run_once(&pool).await.unwrap();
        assert_eq!(report.keys_retired, vec![old.kid().to_owned()]);
        let jwks = published_jwks(&pool).await.unwrap();
        assert!(jwks.find(old.kid()).is_none());
        assert!(
            jwks.find(new.kid()).is_some(),
            "active key is never retired"
        );
    }

    #[sqlx::test]
    async fn reactivated_key_clears_retiring_time(pool: PgPool) {
        let (a, b) = (test_key(), test_key());
        a.activate(&pool).await.unwrap();
        b.activate(&pool).await.unwrap();
        a.activate(&pool).await.unwrap();
        let retiring_at: Option<i64> = sqlx::query_scalar(
            "SELECT extract(epoch FROM retiring_at)::bigint FROM signing_keys WHERE kid = $1",
        )
        .bind(a.kid())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(retiring_at, None);
    }

    #[sqlx::test]
    async fn database_requires_retiring_time(pool: PgPool) {
        let result = sqlx::query(
            "INSERT INTO signing_keys (kid, algorithm, public_jwk, status) \
             VALUES ('k', 'RS256', '{}', 'retiring')",
        )
        .execute(&pool)
        .await;
        assert!(result.is_err());
    }
}
