//! Moongate subjects: the opaque, immutable identity behind every OIDC `sub`.

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::audit;
use crate::upstream::UpstreamIdentity;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubjectId(Uuid);

impl SubjectId {
    /// Only for values read back from the database, never from request input.
    pub(crate) fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// Returns the subject bound to this OutlandsID, creating it on first login.
/// Race-safe: concurrent first logins for the same OutlandsID serialize on an
/// advisory lock and all receive the same subject.
pub async fn resolve_subject(
    pool: &PgPool,
    identity: &UpstreamIdentity,
) -> sqlx::Result<SubjectId> {
    let provider_subject = identity.outlands_id.get().to_string();
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('outlands:' || $1, 0))")
        .bind(&provider_subject)
        .execute(&mut *tx)
        .await?;

    let existing: Option<Uuid> = sqlx::query_scalar(
        "UPDATE upstream_identities SET last_authenticated_at = now() \
         WHERE provider = 'outlands' AND provider_subject = $1 RETURNING subject_id",
    )
    .bind(&provider_subject)
    .fetch_optional(&mut *tx)
    .await?;

    let mut created = false;
    let subject = match existing {
        Some(subject) => subject,
        None => {
            let subject: Uuid =
                sqlx::query_scalar("INSERT INTO subjects DEFAULT VALUES RETURNING id")
                    .fetch_one(&mut *tx)
                    .await?;
            sqlx::query(
                "INSERT INTO upstream_identities \
                     (subject_id, provider, provider_subject, last_authenticated_at) \
                 VALUES ($1, 'outlands', $2, now())",
            )
            .bind(subject)
            .bind(&provider_subject)
            .execute(&mut *tx)
            .await?;
            created = true;
            subject
        }
    };
    tx.commit().await?;
    if created {
        audit::record(
            pool,
            audit::Event::new(audit::Kind::SubjectCreated).subject(SubjectId(subject)),
        )
        .await;
    }
    Ok(SubjectId(subject))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::OutlandsId;

    fn identity(id: &str) -> UpstreamIdentity {
        UpstreamIdentity {
            outlands_id: OutlandsId::parse(id).unwrap(),
            email: "player@moongate.localhost".into(),
            role: "player".into(),
        }
    }

    async fn subject_count(pool: &PgPool) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM subjects")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test]
    async fn same_outlands_id_resolves_to_same_subject(pool: PgPool) {
        let first = resolve_subject(&pool, &identity("10001")).await.unwrap();
        let second = resolve_subject(&pool, &identity("10001")).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(subject_count(&pool).await, 1);
    }

    #[sqlx::test]
    async fn different_outlands_ids_get_different_subjects(pool: PgPool) {
        let a = resolve_subject(&pool, &identity("10001")).await.unwrap();
        let b = resolve_subject(&pool, &identity("10002")).await.unwrap();
        assert_ne!(a, b);
    }

    #[sqlx::test]
    async fn email_change_does_not_change_subject(pool: PgPool) {
        let first = resolve_subject(&pool, &identity("10001")).await.unwrap();
        let mut changed = identity("10001");
        changed.email = "new@moongate.localhost".into();
        assert_eq!(resolve_subject(&pool, &changed).await.unwrap(), first);
    }

    #[sqlx::test]
    async fn subject_is_not_the_outlands_id(pool: PgPool) {
        let subject = resolve_subject(&pool, &identity("10001")).await.unwrap();
        assert!(!subject.as_uuid().to_string().contains("10001"));
    }

    #[sqlx::test]
    async fn concurrent_first_logins_create_one_subject(pool: PgPool) {
        let id = identity("10001");
        let results = spawn_logins(&pool, &id).await;
        assert!(results.windows(2).all(|w| w[0] == w[1]));
        assert_eq!(subject_count(&pool).await, 1);
    }

    async fn spawn_logins(pool: &PgPool, id: &UpstreamIdentity) -> Vec<SubjectId> {
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let (pool, id) = (pool.clone(), id.clone());
                tokio::spawn(async move { resolve_subject(&pool, &id).await.unwrap() })
            })
            .collect();
        let mut subjects = Vec::new();
        for task in tasks {
            subjects.push(task.await.unwrap());
        }
        subjects
    }
}
