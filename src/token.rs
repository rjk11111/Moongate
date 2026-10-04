//! The token endpoint (`POST /token`): authorization_code grant only.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::Serialize;
use serde_json::json;
use sqlx::types::Uuid;

use crate::client::{Client, ClientId, ClientType};
use crate::identity::SubjectId;
use crate::{AppState, audit, crypto};

pub const ID_TOKEN_LIFETIME_SECS: i64 = 5 * 60;
pub const ACCESS_TOKEN_LIFETIME_SECS: i64 = 5 * 60;

#[derive(Debug, PartialEq, Eq)]
enum TokenError {
    InvalidRequest(&'static str),
    InvalidClient,
    InvalidGrant,
    UnsupportedGrantType,
    ServerError,
}

impl IntoResponse for TokenError {
    fn into_response(self) -> Response {
        let (status, error, description) = match self {
            Self::InvalidRequest(description) => {
                (StatusCode::BAD_REQUEST, "invalid_request", description)
            }
            Self::InvalidClient => (
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "client authentication failed",
            ),
            // One description for every grant failure: never say which check failed.
            Self::InvalidGrant => (
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "authorization code is invalid, expired, or already used",
            ),
            Self::UnsupportedGrantType => (
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "only authorization_code is supported",
            ),
            Self::ServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "temporarily unavailable",
            ),
        };
        let mut response = (
            status,
            Json(json!({ "error": error, "error_description": description })),
        )
            .into_response();
        let headers = response.headers_mut();
        no_store(headers);
        if status == StatusCode::UNAUTHORIZED {
            headers.insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"moongate\""),
            );
        }
        response
    }
}

/// subject_id, scopes, nonce, code_challenge, auth_time
type ConsumedCode = (Uuid, Vec<String>, Option<String>, Option<String>, i64);

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    id_token: String,
    scope: String,
}

#[derive(Serialize)]
struct IdTokenClaims<'a> {
    iss: &'a str,
    sub: String,
    aud: &'a str,
    exp: i64,
    iat: i64,
    auth_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
}

pub async fn token(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    match exchange(&state, &headers, &body).await {
        Ok(response) => {
            let mut response = Json(response).into_response();
            no_store(response.headers_mut());
            response
        }
        Err(error) => error.into_response(),
    }
}

async fn exchange(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<TokenResponse, TokenError> {
    let params: Vec<(String, String)> = url::form_urlencoded::parse(body).into_owned().collect();
    let mut names: Vec<&str> = params.iter().map(|(n, _)| n.as_str()).collect();
    names.sort_unstable();
    if names.windows(2).any(|w| w[0] == w[1]) {
        return Err(TokenError::InvalidRequest("duplicate parameter"));
    }
    let get = |name: &str| {
        params
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };

    let client = authenticate_client(state, headers, get("client_id")).await?;

    match get("grant_type") {
        Some("authorization_code") => {}
        Some(_) => return Err(TokenError::UnsupportedGrantType),
        None => return Err(TokenError::InvalidRequest("grant_type is required")),
    }
    let code = get("code").ok_or(TokenError::InvalidRequest("code is required"))?;
    let redirect_uri =
        get("redirect_uri").ok_or(TokenError::InvalidRequest("redirect_uri is required"))?;
    let verifier = get("code_verifier");
    if verifier.is_some_and(|v| !is_code_verifier(v)) {
        return Err(TokenError::InvalidRequest("malformed code_verifier"));
    }

    // Atomic single-use consumption. Client and redirect URI binding are part of the
    // match, so a code presented by another client or with another redirect URI is
    // not consumed and stays usable by its rightful client.
    let row: Option<ConsumedCode> = sqlx::query_as(
        "UPDATE authorization_codes c SET consumed_at = now() \
         FROM subjects s \
         WHERE c.code_hash = $1 AND c.consumed_at IS NULL AND c.expires_at > now() \
           AND c.client_id = $2 AND c.redirect_uri = $3 \
           AND s.id = c.subject_id AND s.disabled_at IS NULL \
         RETURNING c.subject_id, c.scopes, c.nonce, c.code_challenge, \
                   extract(epoch FROM c.auth_time)::bigint",
    )
    .bind(crypto::sha256_hex(code))
    .bind(client.id.as_str())
    .bind(redirect_uri)
    .fetch_optional(&state.pool)
    .await
    .map_err(|error| {
        tracing::warn!(%error, "authorization code consumption failed");
        TokenError::ServerError
    })?;

    let Some((subject, scopes, nonce, challenge, auth_time)) = row else {
        report_possible_replay(state, code, &client).await;
        return Err(TokenError::InvalidGrant);
    };

    // PKCE. A verifier without a stored challenge is also refused (downgrade guard).
    let pkce_ok = match (&challenge, verifier) {
        (Some(challenge), Some(verifier)) => {
            let computed = URL_SAFE_NO_PAD.encode(aws_lc_rs::digest::digest(
                &aws_lc_rs::digest::SHA256,
                verifier.as_bytes(),
            ));
            aws_lc_rs::constant_time::verify_slices_are_equal(
                computed.as_bytes(),
                challenge.as_bytes(),
            )
            .is_ok()
        }
        (None, None) => true,
        _ => false,
    };
    if !pkce_ok {
        audit::record(
            &state.pool,
            audit::Event::new(audit::Kind::TokenDenied)
                .client(client.id.as_str())
                .subject(SubjectId::from_uuid(subject))
                .detail("pkce"),
        )
        .await;
        return Err(TokenError::InvalidGrant);
    }

    let now = now();
    let claims = IdTokenClaims {
        iss: state.issuer.as_str(),
        sub: subject.to_string(),
        aud: client.id.as_str(),
        exp: now + ID_TOKEN_LIFETIME_SECS,
        iat: now,
        auth_time,
        nonce,
    };
    let id_token = state.signing_key.sign(&claims).map_err(|error| {
        tracing::warn!(%error, "id token signing failed");
        TokenError::ServerError
    })?;
    // ponytail: opaque and unstored, accepted nowhere; it exists because RFC 6749 §5.1
    // requires one. Store its hash when /userinfo is added.
    let access_token = crypto::random_token().map_err(|_| TokenError::ServerError)?;

    audit::record(
        &state.pool,
        audit::Event::new(audit::Kind::TokenIssued)
            .client(client.id.as_str())
            .subject(SubjectId::from_uuid(subject))
            .kid(state.signing_key.kid()),
    )
    .await;
    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_LIFETIME_SECS,
        id_token,
        scope: scopes.join(" "),
    })
}

/// Confidential clients authenticate with HTTP Basic (RFC 6749 §2.3.1). Public clients
/// send only `client_id` and are bound by PKCE instead.
async fn authenticate_client(
    state: &AppState,
    headers: &HeaderMap,
    body_client_id: Option<&str>,
) -> Result<Client, TokenError> {
    let basic = match headers.get(header::AUTHORIZATION) {
        Some(value) => Some(parse_basic(value).ok_or(TokenError::InvalidClient)?),
        None => None,
    };
    let client_id = match (&basic, body_client_id) {
        (Some((id, _)), Some(body_id)) if id != body_id => return Err(TokenError::InvalidClient),
        (Some((id, _)), _) => id.as_str(),
        (None, Some(body_id)) => body_id,
        (None, None) => return Err(TokenError::InvalidClient),
    };
    let client_id = ClientId::parse(client_id).ok_or(TokenError::InvalidClient)?;
    let client = Client::find_enabled(&state.pool, &client_id)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "client lookup failed");
            TokenError::ServerError
        })?
        .ok_or(TokenError::InvalidClient)?;

    let authenticated = match (client.client_type, &basic) {
        (ClientType::Confidential, Some((_, secret))) => client.verify_secret(secret),
        (ClientType::Public, None) => true,
        _ => false,
    };
    if !authenticated {
        audit::record(
            &state.pool,
            audit::Event::new(audit::Kind::TokenDenied)
                .client(client.id.as_str())
                .detail("client_auth"),
        )
        .await;
        return Err(TokenError::InvalidClient);
    }
    Ok(client)
}

/// `Basic base64(urlencode(id) ":" urlencode(secret))`.
fn parse_basic(value: &HeaderValue) -> Option<(String, String)> {
    let value = value.to_str().ok()?;
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = String::from_utf8(STANDARD.decode(encoded.trim()).ok()?).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    let unescape = |s: &str| {
        percent_encoding::percent_decode_str(&s.replace('+', " "))
            .decode_utf8()
            .ok()
            .map(|s| s.into_owned())
    };
    Some((unescape(id)?, unescape(secret)?))
}

/// RFC 7636 §4.1: 43–128 unreserved characters.
fn is_code_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// A code that exists but was already consumed is a replay: possibly a stolen code.
async fn report_possible_replay(state: &AppState, code: &str, client: &Client) {
    let consumed: Option<bool> = sqlx::query_scalar(
        "SELECT consumed_at IS NOT NULL FROM authorization_codes WHERE code_hash = $1",
    )
    .bind(crypto::sha256_hex(code))
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    if consumed == Some(true) {
        tracing::warn!("already-consumed authorization code presented");
        audit::record(
            &state.pool,
            audit::Event::new(audit::Kind::AuthorizationCodeReplay).client(client.id.as_str()),
        )
        .await;
    }
}

fn no_store(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};
    use serde_json::Value;
    use sqlx::PgPool;
    use tower::ServiceExt;

    use super::*;
    use crate::client::tests::{TEST_REDIRECT, register_test_client};
    use crate::identity::resolve_subject;
    use crate::tests::shared_test_key;
    use crate::upstream::{OutlandsId, UpstreamIdentity};

    /// A verifier and its S256 challenge, computed independently (Python hashlib).
    const VERIFIER: &str = "dBjftJeZ4CVP-mJ92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "ngF5GsXcbwljx6u133FFr3Xht9xooA_DuaX_3QwODtc";

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: Value,
    }

    impl Reply {
        fn error(&self) -> &str {
            self.body["error"].as_str().unwrap_or_default()
        }
    }

    async fn setup(pool: &PgPool) -> String {
        register_test_client(pool, "spa", ClientType::Public).await;
        register_test_client(pool, "rp", ClientType::Confidential)
            .await
            .unwrap()
            .expose()
            .to_owned()
    }

    async fn subject(pool: &PgPool) -> Uuid {
        let identity = UpstreamIdentity {
            outlands_id: OutlandsId::parse("10001").unwrap(),
            email: "player@moongate.localhost".into(),
            role: "player".into(),
        };
        resolve_subject(pool, &identity).await.unwrap().as_uuid()
    }

    async fn insert_code(pool: &PgPool, client: &str, challenge: Option<&str>) -> String {
        let code = crypto::random_token().unwrap();
        sqlx::query(
            "INSERT INTO authorization_codes \
                 (code_hash, client_id, subject_id, redirect_uri, scopes, nonce, code_challenge, \
                  auth_time, expires_at) \
             VALUES ($1, $2, $3, $4, '{openid}', 'n-0S6', $5, now(), now() + interval '60 seconds')",
        )
        .bind(crypto::sha256_hex(&code))
        .bind(client)
        .bind(subject(pool).await)
        .bind(TEST_REDIRECT)
        .bind(challenge)
        .execute(pool)
        .await
        .unwrap();
        code
    }

    fn basic(id: &str, secret: &str) -> String {
        format!("Basic {}", STANDARD.encode(format!("{id}:{secret}")))
    }

    async fn post(pool: &PgPool, form: &[(&str, &str)], authorization: Option<&str>) -> Reply {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        let mut request = Request::post("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(authorization) = authorization {
            request = request.header(header::AUTHORIZATION, authorization);
        }
        let response = crate::tests::test_app(pool.clone())
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        Reply {
            status,
            headers,
            body: serde_json::from_slice(&body).unwrap(),
        }
    }

    fn grant<'a>(code: &'a str, verifier: Option<&'a str>) -> Vec<(&'a str, &'a str)> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", TEST_REDIRECT),
        ];
        if let Some(verifier) = verifier {
            form.push(("code_verifier", verifier));
        }
        form
    }

    async fn confidential(
        pool: &PgPool,
        secret: &str,
        code: &str,
        verifier: Option<&str>,
    ) -> Reply {
        post(pool, &grant(code, verifier), Some(&basic("rp", secret))).await
    }

    async fn public(pool: &PgPool, code: &str, verifier: Option<&str>) -> Reply {
        let mut form = grant(code, verifier);
        form.push(("client_id", "spa"));
        post(pool, &form, None).await
    }

    fn validate_id_token(token: &str, audience: &str) -> Value {
        let key = DecodingKey::from_jwk(shared_test_key().public_jwk()).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[audience]);
        validation.set_issuer(&["https://moongate.test"]);
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);
        jsonwebtoken::decode::<Value>(token, &key, &validation)
            .unwrap()
            .claims
    }

    // --- Success ---

    #[sqlx::test]
    async fn confidential_client_receives_valid_id_token(pool: PgPool) {
        let secret = setup(&pool).await;
        let code = insert_code(&pool, "rp", Some(CHALLENGE)).await;
        let reply = confidential(&pool, &secret, &code, Some(VERIFIER)).await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(reply.body["token_type"], "Bearer");
        assert_eq!(reply.body["scope"], "openid");
        assert_eq!(reply.body["access_token"].as_str().unwrap().len(), 64);

        let id_token = reply.body["id_token"].as_str().unwrap();
        let header = jsonwebtoken::decode_header(id_token).unwrap();
        assert_eq!(header.kid.as_deref(), Some(shared_test_key().kid()));
        let claims = validate_id_token(id_token, "rp");
        assert_eq!(claims["sub"], subject(&pool).await.to_string());
        assert_eq!(claims["nonce"], "n-0S6");
        assert!(claims["auth_time"].as_i64().unwrap() > 0);
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            ID_TOKEN_LIFETIME_SECS
        );
        // Minimal disclosure: nothing beyond the protocol claims.
        let mut keys: Vec<&str> = claims
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["aud", "auth_time", "exp", "iat", "iss", "nonce", "sub"]
        );
    }

    #[sqlx::test]
    async fn confidential_client_without_pkce_succeeds(pool: PgPool) {
        let secret = setup(&pool).await;
        let code = insert_code(&pool, "rp", None).await;
        assert_eq!(
            confidential(&pool, &secret, &code, None).await.status,
            StatusCode::OK
        );
    }

    #[sqlx::test]
    async fn public_client_receives_id_token(pool: PgPool) {
        setup(&pool).await;
        let code = insert_code(&pool, "spa", Some(CHALLENGE)).await;
        let reply = public(&pool, &code, Some(VERIFIER)).await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        validate_id_token(reply.body["id_token"].as_str().unwrap(), "spa");
    }

    // --- Codes ---

    #[sqlx::test]
    async fn authorization_code_cannot_be_reused(pool: PgPool) {
        let secret = setup(&pool).await;
        let code = insert_code(&pool, "rp", Some(CHALLENGE)).await;
        assert_eq!(
            confidential(&pool, &secret, &code, Some(VERIFIER))
                .await
                .status,
            StatusCode::OK
        );
        let replay = confidential(&pool, &secret, &code, Some(VERIFIER)).await;
        assert_eq!(replay.status, StatusCode::BAD_REQUEST);
        assert_eq!(replay.error(), "invalid_grant");
    }

    #[sqlx::test]
    async fn token_outcomes_are_audited(pool: PgPool) {
        use crate::audit::tests::events;
        let secret = setup(&pool).await;

        let code = insert_code(&pool, "rp", Some(CHALLENGE)).await;
        confidential(&pool, &secret, &code, Some(VERIFIER)).await;
        confidential(&pool, &secret, &code, Some(VERIFIER)).await;
        let bad_pkce = insert_code(&pool, "spa", Some(CHALLENGE)).await;
        public(&pool, &bad_pkce, Some(&"x".repeat(43))).await;
        confidential(&pool, "wrong", &code, Some(VERIFIER)).await;

        let trail: Vec<(String, Option<String>, Option<String>)> = events(&pool)
            .await
            .into_iter()
            .filter(|row| row.0.starts_with("token") || row.0.starts_with("authorization"))
            .map(|row| (row.0, row.1, row.3))
            .collect();
        let expected = [
            ("token_issued", "rp", None),
            ("authorization_code_replay", "rp", None),
            ("token_denied", "spa", Some("pkce")),
            ("token_denied", "rp", Some("client_auth")),
        ];
        assert_eq!(
            trail,
            expected.map(|(k, c, d)| (k.to_owned(), Some(c.to_owned()), d.map(str::to_owned)))
        );
    }

    #[sqlx::test]
    async fn concurrent_redemption_succeeds_once(pool: PgPool) {
        let secret = setup(&pool).await;
        let code = insert_code(&pool, "rp", Some(CHALLENGE)).await;
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let (pool, secret, code) = (pool.clone(), secret.clone(), code.clone());
                tokio::spawn(async move {
                    confidential(&pool, &secret, &code, Some(VERIFIER))
                        .await
                        .status
                })
            })
            .collect();
        let mut successes = 0;
        for task in tasks {
            if task.await.unwrap() == StatusCode::OK {
                successes += 1;
            }
        }
        assert_eq!(successes, 1);
    }

    #[sqlx::test]
    async fn authorization_code_expires(pool: PgPool) {
        let secret = setup(&pool).await;
        let code = insert_code(&pool, "rp", Some(CHALLENGE)).await;
        sqlx::query(
            "UPDATE authorization_codes SET created_at = now() - interval '2 minutes', \
                                            expires_at = now() - interval '1 second'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let reply = confidential(&pool, &secret, &code, Some(VERIFIER)).await;
        assert_eq!(reply.error(), "invalid_grant");
    }

    #[sqlx::test]
    async fn unknown_code_is_invalid_grant(pool: PgPool) {
        let secret = setup(&pool).await;
        let code = crypto::random_token().unwrap();
        assert_eq!(
            confidential(&pool, &secret, &code, Some(VERIFIER))
                .await
                .error(),
            "invalid_grant"
        );
    }

    #[sqlx::test]
    async fn authorization_code_is_bound_to_client(pool: PgPool) {
        let secret = setup(&pool).await;
        let code = insert_code(&pool, "rp", Some(CHALLENGE)).await;
        assert_eq!(
            public(&pool, &code, Some(VERIFIER)).await.error(),
            "invalid_grant"
        );
        // The rightful client can still redeem it.
        assert_eq!(
            confidential(&pool, &secret, &code, Some(VERIFIER))
                .await
                .status,
            StatusCode::OK
        );
    }

    #[sqlx::test]
    async fn authorization_code_is_bound_to_redirect_uri(pool: PgPool) {
        let secret = setup(&pool).await;
        let code = insert_code(&pool, "rp", Some(CHALLENGE)).await;
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "https://rp.test/other"),
            ("code_verifier", VERIFIER),
        ];
        let reply = post(&pool, &form, Some(&basic("rp", &secret))).await;
        assert_eq!(reply.error(), "invalid_grant");
    }

    #[sqlx::test]
    async fn disabled_subject_cannot_redeem(pool: PgPool) {
        let secret = setup(&pool).await;
        let code = insert_code(&pool, "rp", Some(CHALLENGE)).await;
        sqlx::query("UPDATE subjects SET disabled_at = now()")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            confidential(&pool, &secret, &code, Some(VERIFIER))
                .await
                .error(),
            "invalid_grant"
        );
    }

    // --- PKCE ---

    #[sqlx::test]
    async fn pkce_rejects_wrong_verifier(pool: PgPool) {
        setup(&pool).await;
        let code = insert_code(&pool, "spa", Some(CHALLENGE)).await;
        let wrong = "dBjftJeZ4CVP-mJ92K27uhbUJU1p1r_wW1gFWFOEjXX";
        assert_eq!(
            public(&pool, &code, Some(wrong)).await.error(),
            "invalid_grant"
        );
    }

    #[sqlx::test]
    async fn pkce_rejects_missing_verifier(pool: PgPool) {
        setup(&pool).await;
        let code = insert_code(&pool, "spa", Some(CHALLENGE)).await;
        assert_eq!(public(&pool, &code, None).await.error(), "invalid_grant");
    }

    #[sqlx::test]
    async fn verifier_without_challenge_is_rejected(pool: PgPool) {
        let secret = setup(&pool).await;
        let code = insert_code(&pool, "rp", None).await;
        assert_eq!(
            confidential(&pool, &secret, &code, Some(VERIFIER))
                .await
                .error(),
            "invalid_grant"
        );
    }

    #[sqlx::test]
    async fn malformed_verifier_is_invalid_request(pool: PgPool) {
        setup(&pool).await;
        let code = insert_code(&pool, "spa", Some(CHALLENGE)).await;
        for bad in ["short", &"a".repeat(129), &format!("{}!", &VERIFIER[..43])] {
            assert_eq!(
                public(&pool, &code, Some(bad)).await.error(),
                "invalid_request"
            );
        }
    }

    // --- Client authentication ---

    #[sqlx::test]
    async fn wrong_client_secret_is_invalid_client(pool: PgPool) {
        setup(&pool).await;
        let code = insert_code(&pool, "rp", Some(CHALLENGE)).await;
        let reply = confidential(&pool, "wrong", &code, Some(VERIFIER)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.error(), "invalid_client");
        assert!(reply.headers.contains_key(header::WWW_AUTHENTICATE));
    }

    #[sqlx::test]
    async fn failed_client_auth_does_not_consume_code(pool: PgPool) {
        let secret = setup(&pool).await;
        let code = insert_code(&pool, "rp", Some(CHALLENGE)).await;
        confidential(&pool, "wrong", &code, Some(VERIFIER)).await;
        assert_eq!(
            confidential(&pool, &secret, &code, Some(VERIFIER))
                .await
                .status,
            StatusCode::OK
        );
    }

    #[sqlx::test]
    async fn confidential_client_must_authenticate(pool: PgPool) {
        setup(&pool).await;
        let code = insert_code(&pool, "rp", Some(CHALLENGE)).await;
        let mut form = grant(&code, Some(VERIFIER));
        form.push(("client_id", "rp"));
        assert_eq!(post(&pool, &form, None).await.error(), "invalid_client");
        assert_eq!(
            post(&pool, &grant(&code, Some(VERIFIER)), None)
                .await
                .error(),
            "invalid_client"
        );
    }

    #[sqlx::test]
    async fn public_client_cannot_use_basic_auth(pool: PgPool) {
        setup(&pool).await;
        let code = insert_code(&pool, "spa", Some(CHALLENGE)).await;
        let reply = post(
            &pool,
            &grant(&code, Some(VERIFIER)),
            Some(&basic("spa", "x")),
        )
        .await;
        assert_eq!(reply.error(), "invalid_client");
    }

    #[sqlx::test]
    async fn basic_and_body_client_id_must_agree(pool: PgPool) {
        let secret = setup(&pool).await;
        let code = insert_code(&pool, "rp", Some(CHALLENGE)).await;
        let mut form = grant(&code, Some(VERIFIER));
        form.push(("client_id", "spa"));
        let reply = post(&pool, &form, Some(&basic("rp", &secret))).await;
        assert_eq!(reply.error(), "invalid_client");
    }

    #[sqlx::test]
    async fn unknown_and_disabled_clients_are_invalid_client(pool: PgPool) {
        let secret = setup(&pool).await;
        let code = insert_code(&pool, "rp", Some(CHALLENGE)).await;
        let reply = post(
            &pool,
            &grant(&code, Some(VERIFIER)),
            Some(&basic("nobody", "x")),
        )
        .await;
        assert_eq!(reply.error(), "invalid_client");
        sqlx::query("UPDATE clients SET enabled = false WHERE client_id = 'rp'")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            confidential(&pool, &secret, &code, Some(VERIFIER))
                .await
                .error(),
            "invalid_client"
        );
    }

    // --- Request shape ---

    #[sqlx::test]
    async fn request_shape_errors(pool: PgPool) {
        let secret = setup(&pool).await;
        let code = insert_code(&pool, "rp", Some(CHALLENGE)).await;
        let auth = basic("rp", &secret);

        let mut form = grant(&code, Some(VERIFIER));
        form[0] = ("grant_type", "password");
        assert_eq!(
            post(&pool, &form, Some(&auth)).await.error(),
            "unsupported_grant_type"
        );

        let mut form = grant(&code, Some(VERIFIER));
        form.push(("code", "other"));
        assert_eq!(
            post(&pool, &form, Some(&auth)).await.error(),
            "invalid_request"
        );

        let form = [
            ("grant_type", "authorization_code"),
            ("redirect_uri", TEST_REDIRECT),
        ];
        assert_eq!(
            post(&pool, &form, Some(&auth)).await.error(),
            "invalid_request"
        );

        // None of the failures above consumed the code.
        assert_eq!(
            confidential(&pool, &secret, &code, Some(VERIFIER))
                .await
                .status,
            StatusCode::OK
        );
    }

    #[test]
    fn basic_credentials_are_form_decoded() {
        let header =
            HeaderValue::from_str(&format!("Basic {}", STANDARD.encode("my%20id:s%3Ac+r")))
                .unwrap();
        assert_eq!(parse_basic(&header), Some(("my id".into(), "s:c r".into())));
        let bearer = HeaderValue::from_static("Bearer abc");
        assert_eq!(parse_basic(&bearer), None);
        let garbage = HeaderValue::from_static("Basic !!!");
        assert_eq!(parse_basic(&garbage), None);
    }
}
