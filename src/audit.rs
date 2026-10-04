//! Security audit trail, persisted in `audit_events` and mirrored to `tracing`.
//!
//! The types make leaking secrets hard: the event kind is a closed enum and `detail`
//! only accepts `&'static str` codes, so no request data, credential, or token can be
//! passed in. Identifiers recorded (subject UUID, client_id, kid, IP) are not secrets.

use std::net::IpAddr;

use sqlx::PgPool;

use crate::identity::SubjectId;

/// Everything Moongate audits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    SubjectCreated,
    ClientCreated,
    AuthenticationSucceeded,
    AuthenticationFailed,
    AuthenticationRateLimited,
    SessionCreated,
    SessionDestroyed,
    AuthorizationGranted,
    TokenIssued,
    TokenDenied,
    AuthorizationCodeReplay,
    SigningKeyRotated,
    SigningKeyRetired,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SubjectCreated => "subject_created",
            Self::ClientCreated => "client_created",
            Self::AuthenticationSucceeded => "authentication_succeeded",
            Self::AuthenticationFailed => "authentication_failed",
            Self::AuthenticationRateLimited => "authentication_rate_limited",
            Self::SessionCreated => "session_created",
            Self::SessionDestroyed => "session_destroyed",
            Self::AuthorizationGranted => "authorization_granted",
            Self::TokenIssued => "token_issued",
            Self::TokenDenied => "token_denied",
            Self::AuthorizationCodeReplay => "authorization_code_replay",
            Self::SigningKeyRotated => "signing_key_rotated",
            Self::SigningKeyRetired => "signing_key_retired",
        }
    }
}

#[derive(Debug)]
pub struct Event<'a> {
    kind: Kind,
    subject: Option<SubjectId>,
    client_id: Option<&'a str>,
    source_ip: Option<IpAddr>,
    kid: Option<&'a str>,
    detail: Option<&'static str>,
}

impl<'a> Event<'a> {
    pub fn new(kind: Kind) -> Self {
        Self {
            kind,
            subject: None,
            client_id: None,
            source_ip: None,
            kid: None,
            detail: None,
        }
    }

    pub fn subject(mut self, subject: SubjectId) -> Self {
        self.subject = Some(subject);
        self
    }

    /// Only a client_id that has been looked up in the registry, never raw input.
    pub fn client(mut self, client_id: &'a str) -> Self {
        self.client_id = Some(client_id);
        self
    }

    pub fn ip(mut self, ip: Option<IpAddr>) -> Self {
        self.source_ip = ip;
        self
    }

    pub fn kid(mut self, kid: &'a str) -> Self {
        self.kid = Some(kid);
        self
    }

    /// A short lowercase code such as `"pkce"`; enforced by the database too.
    pub fn detail(mut self, detail: &'static str) -> Self {
        self.detail = Some(detail);
        self
    }
}

/// Best effort: a failed audit write is logged loudly but does not fail the request.
// ponytail: switch to fail-closed (write inside the operation's transaction) if the
// audit trail must be complete; no retention policy yet, that is the operator's call.
pub async fn record(pool: &PgPool, event: Event<'_>) {
    tracing::info!(
        event = event.kind.as_str(),
        subject = event.subject.map(|s| s.as_uuid().to_string()),
        client_id = event.client_id,
        source_ip = event.source_ip.map(|ip| ip.to_string()),
        kid = event.kid,
        detail = event.detail,
        "audit"
    );
    let result = sqlx::query(
        "INSERT INTO audit_events (event_type, subject_id, client_id, source_ip, kid, detail) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(event.kind.as_str())
    .bind(event.subject.map(SubjectId::as_uuid))
    .bind(event.client_id)
    .bind(event.source_ip.map(|ip| ip.to_string()))
    .bind(event.kid)
    .bind(event.detail)
    .execute(pool)
    .await;
    if let Err(error) = result {
        tracing::error!(%error, event = event.kind.as_str(), "audit write failed");
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// (event_type, client_id, source_ip, detail, has_subject) in insertion order.
    pub(crate) type Row = (String, Option<String>, Option<String>, Option<String>, bool);

    pub(crate) async fn events(pool: &PgPool) -> Vec<Row> {
        sqlx::query_as(
            "SELECT event_type, client_id, source_ip, detail, subject_id IS NOT NULL \
             FROM audit_events ORDER BY id",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    pub(crate) async fn kinds(pool: &PgPool) -> Vec<String> {
        events(pool).await.into_iter().map(|row| row.0).collect()
    }

    #[sqlx::test]
    async fn record_persists_all_fields(pool: PgPool) {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        record(
            &pool,
            Event::new(Kind::TokenDenied)
                .client("rp")
                .ip(Some(ip))
                .kid("abc")
                .detail("pkce"),
        )
        .await;
        let row: (
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        ) = sqlx::query_as(
            "SELECT event_type, client_id, source_ip, kid, detail FROM audit_events",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            row,
            (
                "token_denied".into(),
                Some("rp".into()),
                Some("203.0.113.9".into()),
                Some("abc".into()),
                Some("pkce".into())
            )
        );
    }

    #[sqlx::test]
    async fn database_rejects_free_form_detail(pool: PgPool) {
        let result = sqlx::query(
            "INSERT INTO audit_events (event_type, detail) VALUES ('token_denied', 'password=hunter2')",
        )
        .execute(&pool)
        .await;
        assert!(result.is_err());
    }

    #[test]
    fn kind_names_are_database_safe() {
        for kind in [
            Kind::SubjectCreated,
            Kind::ClientCreated,
            Kind::AuthenticationSucceeded,
            Kind::AuthenticationFailed,
            Kind::AuthenticationRateLimited,
            Kind::SessionCreated,
            Kind::SessionDestroyed,
            Kind::AuthorizationGranted,
            Kind::TokenIssued,
            Kind::TokenDenied,
            Kind::AuthorizationCodeReplay,
            Kind::SigningKeyRotated,
            Kind::SigningKeyRetired,
        ] {
            let name = kind.as_str();
            assert!(
                name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{name}"
            );
        }
    }
}
