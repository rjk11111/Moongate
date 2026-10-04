//! The OutlandsID authentication boundary. The rest of Moongate sees only a
//! validated `UpstreamIdentity`, never upstream transport details or raw tokens.

use std::fmt;

mod outlands;

pub use outlands::OutlandsLogin;

/// The stable numeric OutlandsID. Upstream sends it as a JSON string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutlandsId(i64);

impl OutlandsId {
    pub fn parse(value: &str) -> Option<Self> {
        let id: i64 = value.parse().ok()?;
        // Reject "+1", "007", etc.: the canonical form is what binds the identity.
        (id > 0 && id.to_string() == value).then_some(Self(id))
    }

    pub fn get(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamIdentity {
    pub outlands_id: OutlandsId,
    pub email: String,
    pub role: String,
}

/// A password in transit to upstream. Never stored, never printed.
pub struct Password(String);

impl Password {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

/// Deliberately coarse: callers must not learn whether an account exists.
#[derive(Debug, PartialEq, Eq)]
pub enum UpstreamError {
    /// Credentials not accepted.
    Rejected,
    /// Upstream unreachable or returned something Moongate could not validate.
    Unavailable,
}

pub enum Upstream {
    /// Fixed development users. Only allowed with a localhost issuer (see `Config`).
    Mock,
    /// Portal's password login API (ADR 0001).
    Outlands(OutlandsLogin),
}

impl Upstream {
    pub async fn authenticate(
        &self,
        email: &str,
        password: Password,
    ) -> Result<UpstreamIdentity, UpstreamError> {
        match self {
            Self::Mock => mock_authenticate(email, &password),
            Self::Outlands(login) => login.authenticate(email, &password).await,
        }
    }
}

/// (email, password, outlands_id, role)
const MOCK_USERS: &[(&str, &str, i64, &str)] = &[
    ("player@moongate.localhost", "player", 1_000_001, "player"),
    ("staff@moongate.localhost", "staff", 1_000_002, "staff"),
];

fn mock_authenticate(email: &str, password: &Password) -> Result<UpstreamIdentity, UpstreamError> {
    MOCK_USERS
        .iter()
        .find(|(e, p, _, _)| e.eq_ignore_ascii_case(email) && *p == password.expose())
        .map(|&(email, _, id, role)| UpstreamIdentity {
            outlands_id: OutlandsId(id),
            email: email.to_owned(),
            role: role.to_owned(),
        })
        .ok_or(UpstreamError::Rejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn login(email: &str, password: &str) -> Result<UpstreamIdentity, UpstreamError> {
        Upstream::Mock
            .authenticate(email, Password::new(password.into()))
            .await
    }

    #[test]
    fn outlands_id_accepts_only_canonical_positive_integers() {
        assert_eq!(OutlandsId::parse("10001").map(OutlandsId::get), Some(10001));
        for bad in [
            "",
            "0",
            "-1",
            "+1",
            "007",
            "1.0",
            " 1",
            "1e3",
            "abc",
            "99999999999999999999",
        ] {
            assert!(OutlandsId::parse(bad).is_none(), "accepted {bad:?}");
        }
    }

    #[test]
    fn password_debug_is_redacted() {
        let password = Password::new("hunter2".into());
        assert!(!format!("{password:?}").contains("hunter2"));
    }

    #[tokio::test]
    async fn mock_accepts_known_user() {
        let identity = login("Player@Moongate.localhost", "player").await.unwrap();
        assert_eq!(identity.outlands_id.get(), 1_000_001);
        assert_eq!(identity.role, "player");
    }

    #[tokio::test]
    async fn mock_rejects_wrong_password_and_unknown_user_identically() {
        assert_eq!(
            login("player@moongate.localhost", "wrong").await,
            Err(UpstreamError::Rejected)
        );
        assert_eq!(
            login("nobody@moongate.localhost", "player").await,
            Err(UpstreamError::Rejected)
        );
        assert_eq!(
            login("player@moongate.localhost", "").await,
            Err(UpstreamError::Rejected)
        );
    }
}
