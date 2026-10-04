use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use sqlx::PgPool;
use url::{Host, Url};

pub mod audit;
pub mod authorize;
pub mod client;
pub mod crypto;
pub mod identity;
pub mod logout;
pub mod maintenance;
pub mod oidc;
pub mod ratelimit;
pub mod session;
pub mod signing;
pub mod token;
pub mod upstream;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

pub struct Config {
    pub database_url: String,
    pub bind: SocketAddr,
    pub issuer: Issuer,
    pub signing_key_file: PathBuf,
    pub upstream: upstream::Upstream,
    pub client_ip_header: Option<axum::http::HeaderName>,
}

impl Config {
    /// Reads typed config from the environment. Errors name the variable but
    /// never echo its value (DATABASE_URL carries a password).
    pub fn from_env() -> Result<Self, String> {
        let database_url = required("DATABASE_URL")?;
        let bind = required("MOONGATE_BIND")?
            .parse()
            .map_err(|_| "MOONGATE_BIND is not a valid socket address".to_string())?;
        let issuer = Issuer::parse(&required("MOONGATE_BASE_URL")?)
            .map_err(|e| format!("MOONGATE_BASE_URL {e}"))?;
        let signing_key_file = required("MOONGATE_SIGNING_KEY_FILE")?.into();
        let upstream = parse_upstream(
            &required("MOONGATE_UPSTREAM")?,
            &issuer,
            std::env::var("OUTLANDS_LOGIN_URL").ok().as_deref(),
        )?;
        let client_ip_header = match std::env::var("MOONGATE_CLIENT_IP_HEADER") {
            Ok(name) => Some(
                axum::http::HeaderName::try_from(name.as_str())
                    .map_err(|_| "MOONGATE_CLIENT_IP_HEADER is not a valid header name")?,
            ),
            Err(_) => None,
        };
        Ok(Self {
            database_url,
            bind,
            issuer,
            signing_key_file,
            upstream,
            client_ip_header,
        })
    }
}

/// The mock accepts fixed passwords, so it must never run on a public issuer.
/// The real adapter's URL must be https: Moongate's trust in the returned token rests
/// on that TLS connection (ADR 0001).
fn parse_upstream(
    value: &str,
    issuer: &Issuer,
    login_url: Option<&str>,
) -> Result<upstream::Upstream, String> {
    match value {
        "mock" if issuer.is_local() => Ok(upstream::Upstream::Mock),
        "mock" => Err("MOONGATE_UPSTREAM=mock is only allowed with a localhost issuer".into()),
        "outlands" => {
            let url = login_url
                .and_then(|u| Url::parse(u).ok())
                .filter(|u| {
                    u.scheme() == "https"
                        && u.query().is_none()
                        && u.fragment().is_none()
                        && u.username().is_empty()
                        && u.password().is_none()
                })
                .ok_or(
                    "OUTLANDS_LOGIN_URL must be set to an https URL without query or credentials",
                )?;
            upstream::OutlandsLogin::new(url)
                .map(upstream::Upstream::Outlands)
                .map_err(|_| "could not build the OutlandsID HTTP client".into())
        }
        _ => Err("MOONGATE_UPSTREAM must be one of: mock, outlands".into()),
    }
}

fn required(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} must be set"))
}

/// The OIDC `iss` value and base of every endpoint URL. Compared by exact string
/// match by relying parties, so it must already be in canonical form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issuer(String);

impl Issuer {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        let url = Url::parse(value).map_err(|_| "is not a valid URL")?;
        match url.scheme() {
            "https" => {}
            "http" if is_local_host(&url) => {}
            _ => return Err("must use https (http is allowed only for localhost)"),
        }
        if url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err("must not contain a query, fragment, or credentials");
        }
        if value.ends_with('/') {
            return Err("must not end with '/'");
        }
        // Url normalizes case, default ports, and dot segments; refuse anything it would rewrite.
        if url.as_str() != value && url.as_str() != format!("{value}/") {
            return Err("is not in canonical form");
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_local(&self) -> bool {
        Url::parse(&self.0).is_ok_and(|url| is_local_host(&url))
    }

    pub fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.0)
    }
}

/// Loopback or `*.localhost`, where plain http is acceptable for development.
pub(crate) fn is_local_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(d)) => d == "localhost" || d.ends_with(".localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    issuer: Issuer,
    discovery: Arc<serde_json::Value>,
    upstream: Arc<upstream::Upstream>,
    session_cookie: session::CookiePolicy,
    csrf_cookie: session::CookiePolicy,
    signing_key: Arc<signing::SigningKey>,
    client_ip_header: Option<axum::http::HeaderName>,
}

impl AppState {
    pub fn new(
        pool: PgPool,
        issuer: Issuer,
        upstream: upstream::Upstream,
        signing_key: Arc<signing::SigningKey>,
    ) -> Self {
        Self {
            pool,
            discovery: Arc::new(oidc::discovery_document(&issuer)),
            upstream: Arc::new(upstream),
            session_cookie: session::CookiePolicy::session(&issuer),
            csrf_cookie: session::CookiePolicy::csrf(&issuer),
            signing_key,
            issuer,
            client_ip_header: None,
        }
    }

    /// Trust this header for the client IP (see `ratelimit::client_ip`).
    pub fn with_client_ip_header(mut self, header: Option<axum::http::HeaderName>) -> Self {
        self.client_ip_header = header;
        self
    }
}

/// Request bodies here are small forms; refuse anything larger.
const MAX_BODY_BYTES: usize = 64 * 1024;

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/health/live", get(|| async { StatusCode::OK }))
        .route("/health/ready", get(ready))
        .route("/.well-known/openid-configuration", get(oidc::discovery))
        .route(
            "/.well-known/oauth-authorization-server",
            get(oidc::discovery),
        )
        .route("/jwks.json", get(oidc::jwks))
        .route(
            "/authorize",
            get(authorize::authorize_get).post(authorize::authorize_post),
        )
        .route("/login", post(authorize::login))
        .route("/token", post(token::token))
        .route("/logout", get(logout::logout_get).post(logout::logout_post))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

async fn ready(State(state): State<AppState>) -> StatusCode {
    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => StatusCode::OK,
        Err(error) => {
            tracing::warn!(%error, "readiness check failed");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::Request;
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use super::*;

    pub(crate) fn test_issuer() -> Issuer {
        Issuer::parse("https://moongate.test").unwrap()
    }

    /// One RSA key for the whole test run; generating one per test is slow.
    pub(crate) fn shared_test_key() -> Arc<signing::SigningKey> {
        static KEY: std::sync::OnceLock<Arc<signing::SigningKey>> = std::sync::OnceLock::new();
        KEY.get_or_init(|| Arc::new(signing::tests::test_key()))
            .clone()
    }

    pub(crate) fn test_app(pool: PgPool) -> Router {
        app(AppState::new(
            pool,
            test_issuer(),
            upstream::Upstream::Mock,
            shared_test_key(),
        ))
    }

    async fn status(app: Router, uri: &str) -> StatusCode {
        let request = Request::get(uri).body(Body::empty()).unwrap();
        app.oneshot(request).await.unwrap().status()
    }

    /// A pool pointing at nothing: proves an endpoint does not need the DB.
    fn unreachable_pool() -> PgPool {
        PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(500))
            .connect_lazy("postgres://nobody@127.0.0.1:1/none")
            .unwrap()
    }

    #[tokio::test]
    async fn liveness_does_not_depend_on_database() {
        assert_eq!(
            status(test_app(unreachable_pool()), "/health/live").await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn readiness_fails_without_database() {
        assert_eq!(
            status(test_app(unreachable_pool()), "/health/ready").await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[sqlx::test]
    async fn readiness_succeeds_with_database(pool: PgPool) {
        assert_eq!(
            status(test_app(pool), "/health/ready").await,
            StatusCode::OK
        );
    }

    async fn new_subject(pool: &PgPool) -> sqlx::types::Uuid {
        sqlx::query_scalar("INSERT INTO subjects DEFAULT VALUES RETURNING id")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn bind(
        pool: &PgPool,
        subject: sqlx::types::Uuid,
        outlands_id: &str,
    ) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO upstream_identities (subject_id, provider, provider_subject) \
             VALUES ($1, 'outlands', $2)",
        )
        .bind(subject)
        .bind(outlands_id)
        .execute(pool)
        .await
        .map(|_| ())
    }

    #[sqlx::test]
    async fn upstream_identity_cannot_link_to_two_subjects(pool: PgPool) {
        let (a, b) = (new_subject(&pool).await, new_subject(&pool).await);
        bind(&pool, a, "10001").await.unwrap();
        assert!(bind(&pool, b, "10001").await.is_err());
    }

    #[sqlx::test]
    async fn subject_cannot_hold_two_outlands_identities(pool: PgPool) {
        let subject = new_subject(&pool).await;
        bind(&pool, subject, "10001").await.unwrap();
        assert!(bind(&pool, subject, "40000").await.is_err());
    }

    #[sqlx::test]
    async fn unknown_provider_is_rejected(pool: PgPool) {
        let subject = new_subject(&pool).await;
        let result = sqlx::query(
            "INSERT INTO upstream_identities (subject_id, provider, provider_subject) \
             VALUES ($1, 'google', '1')",
        )
        .bind(subject)
        .execute(&pool)
        .await;
        assert!(result.is_err());
    }

    #[test]
    fn issuer_accepts_https_and_local_http() {
        for ok in [
            "https://moongate.uooutlands.com",
            "https://example.com/moongate",
            "http://moongate.localhost:8090",
            "http://127.0.0.1:8090",
        ] {
            assert_eq!(Issuer::parse(ok).unwrap().as_str(), ok);
        }
    }

    #[test]
    fn issuer_rejects_unsafe_or_non_canonical_values() {
        for bad in [
            "http://moongate.uooutlands.com",
            "https://moongate.uooutlands.com/",
            "https://moongate.uooutlands.com?x=1",
            "https://moongate.uooutlands.com#x",
            "https://user:pw@moongate.uooutlands.com",
            "https://MOONGATE.uooutlands.com",
            "https://moongate.uooutlands.com:443",
            "https://moongate.uooutlands.com/a/../b",
            "moongate.uooutlands.com",
            "",
        ] {
            assert!(Issuer::parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn mock_upstream_requires_local_issuer() {
        let local = Issuer::parse("http://moongate.localhost:8090").unwrap();
        assert!(parse_upstream("mock", &local, None).is_ok());
        assert!(parse_upstream("mock", &test_issuer(), None).is_err());
        let public = Issuer::parse("https://moongate.uooutlands.com").unwrap();
        assert!(parse_upstream("mock", &public, None).is_err());
        assert!(parse_upstream("ldap", &local, None).is_err());
        assert!(parse_upstream("", &local, None).is_err());
    }

    #[test]
    fn outlands_upstream_requires_https_login_url() {
        let issuer = test_issuer();
        let ok = Some("https://portal.uooutlands.com/api/user/login");
        assert!(parse_upstream("outlands", &issuer, ok).is_ok());
        for bad in [
            None,
            Some(""),
            Some("http://portal.uooutlands.com/api/user/login"),
            Some("https://portal.uooutlands.com/api/user/login?x=1"),
            Some("https://user:pw@portal.uooutlands.com/api/user/login"),
            Some("portal.uooutlands.com/api/user/login"),
        ] {
            assert!(
                parse_upstream("outlands", &issuer, bad).is_err(),
                "accepted {bad:?}"
            );
        }
    }
}
