//! OutlandsID compatibility adapter: Portal's password login API.
//!
//! See docs/adr/0001-outlandsid-compatibility-adapter.md. The returned JWT is HS256
//! and cannot be signature-verified by Moongate; it is trusted only because Moongate
//! fetched it itself over TLS from the configured URL. Claims are still checked so
//! upstream changes fail closed.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::Algorithm;
use reqwest::StatusCode;
use serde_json::{Value, json};
use url::Url;

use super::{OutlandsId, Password, UpstreamError, UpstreamIdentity};

/// Observed 2026-10-04 from Portal-issued tokens (see ADR 0001).
const ISSUER: &str = "https://login.uooutlands.com";
const AUDIENCE: &str = "https://login.uooutlands.com";
const PURPOSE: &str = "Portal";
const CLAIM_OUTLANDS_ID: &str = "http://uooutlands.com/identity/claims/outlandsid";
const CLAIM_EMAIL: &str = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
const CLAIM_ROLE: &str = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
const CLAIM_PURPOSE: &str = "http://uooutlands.com/identity/claims/purpose";

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

pub struct OutlandsLogin {
    url: Url,
    http: reqwest::Client,
}

impl OutlandsLogin {
    /// `url` comes from config only (https enforced there); never from request input.
    pub(crate) fn new(url: Url) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .user_agent(concat!("Moongate/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { url, http })
    }

    pub(crate) async fn authenticate(
        &self,
        email: &str,
        password: &Password,
    ) -> Result<UpstreamIdentity, UpstreamError> {
        let body = json!({ "email": email, "password": password.expose() });
        let mut response = self
            .http
            .post(self.url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|error| {
                // reqwest errors carry the URL but never the request body.
                tracing::warn!(error = %error.without_url(), "outlands login request failed");
                UpstreamError::Unavailable
            })?;
        drop(body);

        match response.status() {
            StatusCode::OK => {}
            // Observed 2026-10-04: 401 for wrong credentials, 400 for malformed input
            // (e.g. an email without '@'). Both mean "sign-in failed" to the user.
            StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err(UpstreamError::Rejected);
            }
            status => {
                tracing::warn!(%status, "outlands login returned unexpected status");
                return Err(UpstreamError::Unavailable);
            }
        }

        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| UpstreamError::Unavailable)?
        {
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                tracing::warn!("outlands login response too large");
                return Err(UpstreamError::Unavailable);
            }
            bytes.extend_from_slice(&chunk);
        }
        let body: Value = serde_json::from_slice(&bytes).map_err(|_| {
            tracing::warn!("outlands login response is not JSON");
            UpstreamError::Unavailable
        })?;
        let Some(jwt) = body.get("jwt").and_then(Value::as_str) else {
            // ASSUMPTION: a missing jwt may mean the account must accept a privacy policy
            // in Portal first (`forceAcceptPrivacyPolicy`). Unverified.
            tracing::warn!("outlands login response has no jwt");
            return Err(UpstreamError::Unavailable);
        };

        identity_from_token(jwt, now()).map_err(|reason| {
            tracing::warn!(reason, "outlands token failed validation");
            UpstreamError::Unavailable
        })
    }
}

/// Checks the claims of a token Moongate fetched itself (see module docs). Each
/// failure names the check, never the value.
fn identity_from_token(jwt: &str, now: i64) -> Result<UpstreamIdentity, &'static str> {
    // Not a signature check: HS256 cannot be verified here. Trust comes from the channel.
    let decoded =
        jsonwebtoken::dangerous::insecure_decode::<Value>(jwt).map_err(|_| "malformed")?;
    if decoded.header.alg != Algorithm::HS256 {
        return Err("unexpected alg");
    }
    let claims = decoded.claims;
    let text = |name: &str| claims.get(name).and_then(Value::as_str);

    if text("iss") != Some(ISSUER) {
        return Err("issuer");
    }
    if text("aud") != Some(AUDIENCE) {
        return Err("audience");
    }
    if text(CLAIM_PURPOSE) != Some(PURPOSE) {
        return Err("purpose");
    }
    match claims.get("exp").and_then(Value::as_i64) {
        Some(exp) if exp > now => {}
        Some(_) => return Err("expired"),
        None => return Err("exp missing"),
    }
    let outlands_id = text(CLAIM_OUTLANDS_ID)
        .and_then(OutlandsId::parse)
        .ok_or("outlandsid")?;
    let email = text(CLAIM_EMAIL)
        .filter(|e| e.contains('@'))
        .ok_or("email")?;
    let role = text(CLAIM_ROLE).filter(|r| !r.is_empty()).ok_or("role")?;

    Ok(UpstreamIdentity {
        outlands_id,
        email: email.to_owned(),
        role: role.to_owned(),
    })
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::Json;
    use axum::Router;
    use axum::http::{HeaderMap, StatusCode as AxumStatus, header};
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::{EncodingKey, Header};

    use super::*;

    const NOW: i64 = 1_791_000_000;

    fn claims() -> Value {
        json!({
            "jti": "0efa7a9c-e4f7-439e-aa27-e098751d51d5",
            CLAIM_OUTLANDS_ID: "10001",
            CLAIM_EMAIL: "player@example.test",
            CLAIM_ROLE: "player",
            CLAIM_PURPOSE: "Portal",
            "exp": NOW + 3600,
            "iss": ISSUER,
            "aud": AUDIENCE,
        })
    }

    /// Signed with an arbitrary key: Moongate does not (cannot) verify it.
    fn token(claims: &Value) -> String {
        jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            claims,
            &EncodingKey::from_secret(b"not-outlands-secret"),
        )
        .unwrap()
    }

    fn with(name: &str, value: Value) -> Value {
        let mut claims = claims();
        claims[name] = value;
        claims
    }

    #[test]
    fn valid_token_yields_identity() {
        let identity = identity_from_token(&token(&claims()), NOW).unwrap();
        assert_eq!(identity.outlands_id.get(), 10001);
        assert_eq!(identity.email, "player@example.test");
        assert_eq!(identity.role, "player");
    }

    #[test]
    fn token_rejects_wrong_issuer_audience_or_purpose() {
        for (name, value) in [
            ("iss", json!("https://evil.test")),
            ("aud", json!("https://moongate.test")),
            (CLAIM_PURPOSE, json!("Forums")),
        ] {
            assert!(
                identity_from_token(&token(&with(name, value)), NOW).is_err(),
                "{name}"
            );
        }
        let mut no_iss = claims();
        no_iss.as_object_mut().unwrap().remove("iss");
        assert!(identity_from_token(&token(&no_iss), NOW).is_err());
    }

    #[test]
    fn token_rejects_expired_or_missing_exp() {
        assert_eq!(
            identity_from_token(&token(&with("exp", json!(NOW))), NOW).unwrap_err(),
            "expired"
        );
        let mut no_exp = claims();
        no_exp.as_object_mut().unwrap().remove("exp");
        assert!(identity_from_token(&token(&no_exp), NOW).is_err());
    }

    #[test]
    fn token_rejects_bad_identity_claims() {
        for (name, value) in [
            (CLAIM_OUTLANDS_ID, json!("007")),
            (CLAIM_OUTLANDS_ID, json!(10001)),
            (CLAIM_OUTLANDS_ID, json!("-1")),
            (CLAIM_EMAIL, json!("not-an-email")),
            (CLAIM_ROLE, json!("")),
        ] {
            assert!(
                identity_from_token(&token(&with(name, value)), NOW).is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn token_rejects_unexpected_algorithms() {
        let rs = jsonwebtoken::encode(
            &Header::new(Algorithm::HS512),
            &claims(),
            &EncodingKey::from_secret(b"k"),
        )
        .unwrap();
        assert_eq!(identity_from_token(&rs, NOW).unwrap_err(), "unexpected alg");

        let payload = URL_SAFE_NO_PAD.encode(claims().to_string());
        let unsigned = format!(
            "{}.{payload}.",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#)
        );
        assert!(identity_from_token(&unsigned, NOW).is_err());
        assert!(identity_from_token("garbage", NOW).is_err());
    }

    // --- HTTP behaviour against a fake Portal ---

    #[derive(Clone)]
    struct Fake {
        reply: Arc<dyn Fn() -> Response + Send + Sync>,
        seen: Arc<Mutex<Option<(HeaderMap, Value)>>>,
    }

    async fn fake_portal(
        reply: impl Fn() -> Response + Send + Sync + 'static,
    ) -> (OutlandsLogin, Fake) {
        let fake = Fake {
            reply: Arc::new(reply),
            seen: Arc::new(Mutex::new(None)),
        };
        let state = fake.clone();
        let router = Router::new().route(
            "/api/user/login",
            post(move |headers: HeaderMap, Json(body): Json<Value>| {
                let state = state.clone();
                async move {
                    *state.seen.lock().unwrap() = Some((headers, body));
                    (state.reply)()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "http://{}/api/user/login",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (OutlandsLogin::new(url).unwrap(), fake)
    }

    async fn login(adapter: &OutlandsLogin) -> Result<UpstreamIdentity, UpstreamError> {
        adapter
            .authenticate("player@example.test", &Password::new("hunter2".into()))
            .await
    }

    fn live_claims() -> Value {
        with("exp", json!(now() + 3600))
    }

    #[tokio::test]
    async fn successful_login_sends_json_and_returns_identity() {
        let jwt = token(&live_claims());
        let (adapter, fake) = fake_portal(move || {
            Json(json!({ "jwt": jwt, "outlandsID": 10001, "email": "player@example.test" }))
                .into_response()
        })
        .await;
        let identity = login(&adapter).await.unwrap();
        assert_eq!(identity.outlands_id.get(), 10001);

        let (headers, body) = fake.seen.lock().unwrap().clone().unwrap();
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        assert_eq!(
            body,
            json!({ "email": "player@example.test", "password": "hunter2" })
        );
    }

    #[tokio::test]
    async fn rejected_credentials_map_to_rejected() {
        for status in [
            AxumStatus::BAD_REQUEST,
            AxumStatus::UNAUTHORIZED,
            AxumStatus::FORBIDDEN,
        ] {
            let (adapter, _) = fake_portal(move || {
                (
                    status,
                    Json(json!({ "title": "Bad Request", "status": 400 })),
                )
                    .into_response()
            })
            .await;
            assert_eq!(
                login(&adapter).await,
                Err(UpstreamError::Rejected),
                "{status}"
            );
        }
    }

    #[tokio::test]
    async fn upstream_failures_map_to_unavailable() {
        let expired = token(&with("exp", json!(now() - 1)));
        let cases: Vec<Box<dyn Fn() -> Response + Send + Sync>> = vec![
            Box::new(|| AxumStatus::INTERNAL_SERVER_ERROR.into_response()),
            Box::new(|| AxumStatus::TOO_MANY_REQUESTS.into_response()),
            Box::new(|| {
                (
                    AxumStatus::FOUND,
                    [(header::LOCATION, "https://evil.test/")],
                )
                    .into_response()
            }),
            Box::new(|| "not json".into_response()),
            Box::new(|| Json(json!({ "forceAcceptPrivacyPolicy": true })).into_response()),
            Box::new(|| Json(json!({ "jwt": 42 })).into_response()),
            Box::new(move || Json(json!({ "jwt": expired.clone() })).into_response()),
            Box::new(|| "x".repeat(MAX_RESPONSE_BYTES + 1).into_response()),
        ];
        for (i, reply) in cases.into_iter().enumerate() {
            let (adapter, _) = fake_portal(reply).await;
            assert_eq!(
                login(&adapter).await,
                Err(UpstreamError::Unavailable),
                "case {i}"
            );
        }
    }

    #[tokio::test]
    async fn unreachable_upstream_is_unavailable() {
        let adapter =
            OutlandsLogin::new(Url::parse("http://127.0.0.1:1/api/user/login").unwrap()).unwrap();
        assert_eq!(login(&adapter).await, Err(UpstreamError::Unavailable));
    }
}
