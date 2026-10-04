//! The authorization endpoint (`GET`/`POST /authorize`) and its login form (`POST /login`).
//!
//! Order matters: the client and the exact redirect URI are validated before anything
//! else. Until both are known good, every error is rendered locally and nothing is
//! ever redirected. After that, errors go back to the client per RFC 6749 §4.1.2.1.

use std::time::{SystemTime, UNIX_EPOCH};

use askama::Template;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use url::Url;

use crate::client::{Client, ClientId, ClientType};
use crate::identity::{SubjectId, resolve_subject};
use crate::upstream::{Password, UpstreamError};
use crate::{AppState, audit, crypto, ratelimit, session};

/// Authorization codes live this long; the RP exchanges them immediately.
pub const CODE_LIFETIME_SECS: i64 = 60;
const MAX_STATE_LEN: usize = 2048;
const MAX_NONCE_LEN: usize = 512;
const MAX_EMAIL_LEN: usize = 254;
const MAX_PASSWORD_LEN: usize = 1024;

/// Shown for any unusable client_id or redirect_uri. One message for every case, so
/// the page does not reveal which clients exist.
const BAD_CLIENT: &str = "This sign-in request is not valid for any registered application.";

/// A request that passed every check.
#[derive(Debug)]
struct AuthorizationRequest {
    client: Client,
    redirect_uri: String,
    scopes: Vec<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    prompt_none: bool,
    prompt_login: bool,
    max_age: Option<i64>,
}

impl AuthorizationRequest {
    /// The validated request, re-serialized for the login form. Only known fields are
    /// carried, so attacker-supplied extras can't collide with `email`/`password`/`csrf`.
    fn form_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("response_type", "code".to_owned()),
            ("client_id", self.client.id.as_str().to_owned()),
            ("redirect_uri", self.redirect_uri.clone()),
            ("scope", self.scopes.join(" ")),
        ];
        let optional = [
            ("state", &self.state),
            ("nonce", &self.nonce),
            ("code_challenge", &self.code_challenge),
        ];
        fields.extend(
            optional
                .into_iter()
                .filter_map(|(name, value)| value.clone().map(|v| (name, v))),
        );
        if self.code_challenge.is_some() {
            fields.push(("code_challenge_method", "S256".to_owned()));
        }
        fields
    }
}

#[derive(Debug)]
enum Rejection {
    /// Client or redirect URI unusable: render locally, never redirect.
    Local(&'static str),
    /// Safe to report to the client's registered redirect URI.
    Redirect {
        redirect_uri: String,
        state: Option<String>,
        error: &'static str,
        description: &'static str,
    },
    Unavailable,
}

pub(crate) type Params = Vec<(String, String)>;

pub(crate) fn parse_params(bytes: &[u8]) -> Params {
    url::form_urlencoded::parse(bytes).into_owned().collect()
}

/// `Ok(None)` if absent, `Err(())` if present more than once.
pub(crate) fn single<'a>(params: &'a Params, name: &str) -> Result<Option<&'a str>, ()> {
    let mut values = params
        .iter()
        .filter(|(n, _)| n == name)
        .map(|(_, v)| v.as_str());
    let first = values.next();
    match values.next() {
        Some(_) => Err(()),
        None => Ok(first),
    }
}

pub(crate) fn has_duplicates(params: &Params) -> bool {
    let mut names: Vec<&str> = params.iter().map(|(n, _)| n.as_str()).collect();
    names.sort_unstable();
    names.windows(2).any(|w| w[0] == w[1])
}

/// S256 output is 32 bytes, base64url without padding: exactly 43 characters.
fn is_s256_challenge(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

async fn validate(state: &AppState, params: &Params) -> Result<AuthorizationRequest, Rejection> {
    let client_id = match single(params, "client_id") {
        Ok(Some(value)) => ClientId::parse(value).ok_or(Rejection::Local(BAD_CLIENT))?,
        _ => return Err(Rejection::Local(BAD_CLIENT)),
    };
    let client = Client::find_enabled(&state.pool, &client_id)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "client lookup failed");
            Rejection::Unavailable
        })?
        .ok_or(Rejection::Local(BAD_CLIENT))?;
    let redirect_uri = match single(params, "redirect_uri") {
        Ok(Some(value)) if client.is_registered_redirect_uri(value) => value.to_owned(),
        _ => return Err(Rejection::Local(BAD_CLIENT)),
    };

    // From here on the redirect URI is trusted. Echo `state` only if it is well formed.
    let request_state = match single(params, "state") {
        Ok(value) => value
            .filter(|s| s.len() <= MAX_STATE_LEN)
            .map(str::to_owned),
        Err(()) => None,
    };
    let fail = |error, description| Rejection::Redirect {
        redirect_uri: redirect_uri.clone(),
        state: request_state.clone(),
        error,
        description,
    };

    if has_duplicates(params) {
        return Err(fail("invalid_request", "duplicate parameter"));
    }
    let get = |name| single(params, name).ok().flatten();
    if get("state").is_some_and(|s| s.len() > MAX_STATE_LEN) {
        return Err(fail("invalid_request", "state is too long"));
    }
    if get("request").is_some() {
        return Err(fail(
            "request_not_supported",
            "request objects are not supported",
        ));
    }
    if get("request_uri").is_some() {
        return Err(fail(
            "request_uri_not_supported",
            "request_uri is not supported",
        ));
    }
    if get("response_mode").is_some_and(|m| m != "query") {
        return Err(fail(
            "invalid_request",
            "only response_mode=query is supported",
        ));
    }
    match get("response_type") {
        Some("code") => {}
        Some(_) => return Err(fail("unsupported_response_type", "only code is supported")),
        None => return Err(fail("invalid_request", "response_type is required")),
    }

    let mut scopes: Vec<String> = get("scope")
        .unwrap_or_default()
        .split(' ')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    scopes.sort_unstable();
    scopes.dedup();
    if !scopes.iter().any(|s| s == "openid") {
        return Err(fail("invalid_scope", "the openid scope is required"));
    }
    if !scopes.iter().all(|s| client.allowed_scopes.contains(s)) {
        return Err(fail("invalid_scope", "a requested scope is not allowed"));
    }

    let code_challenge = match (get("code_challenge"), get("code_challenge_method")) {
        (None, None) if client.client_type == ClientType::Public => {
            return Err(fail("invalid_request", "PKCE is required for this client"));
        }
        (None, None) => None,
        (Some(challenge), Some("S256")) if is_s256_challenge(challenge) => {
            Some(challenge.to_owned())
        }
        (Some(_), Some("S256")) => return Err(fail("invalid_request", "malformed code_challenge")),
        (Some(_), _) => {
            return Err(fail(
                "invalid_request",
                "code_challenge_method must be S256",
            ));
        }
        (None, Some(_)) => return Err(fail("invalid_request", "code_challenge is required")),
    };

    let nonce = get("nonce").map(str::to_owned);
    if nonce.as_ref().is_some_and(|n| n.len() > MAX_NONCE_LEN) {
        return Err(fail("invalid_request", "nonce is too long"));
    }

    let prompts: Vec<&str> = get("prompt")
        .unwrap_or_default()
        .split(' ')
        .filter(|p| !p.is_empty())
        .collect();
    if !prompts
        .iter()
        .all(|p| matches!(*p, "none" | "login" | "consent" | "select_account"))
    {
        return Err(fail("invalid_request", "unsupported prompt value"));
    }
    let prompt_none = prompts.contains(&"none");
    if prompt_none && prompts.len() > 1 {
        return Err(fail("invalid_request", "prompt=none cannot be combined"));
    }

    let max_age = match get("max_age") {
        None => None,
        Some(value) => match value.parse::<i64>() {
            Ok(age) if age >= 0 && age.to_string() == value => Some(age),
            _ => {
                return Err(fail(
                    "invalid_request",
                    "max_age must be a non-negative integer",
                ));
            }
        },
    };

    Ok(AuthorizationRequest {
        prompt_login: prompts.contains(&"login"),
        client,
        redirect_uri,
        scopes,
        state: get("state").map(str::to_owned),
        nonce,
        code_challenge,
        prompt_none,
        max_age,
    })
}

pub async fn authorize_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    authorize(
        &state,
        &headers,
        parse_params(query.unwrap_or_default().as_bytes()),
    )
    .await
}

/// OIDC Core §3.1.2.1 requires POST support with form-encoded parameters.
pub async fn authorize_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    authorize(&state, &headers, parse_params(&body)).await
}

async fn authorize(state: &AppState, headers: &HeaderMap, params: Params) -> Response {
    let request = match validate(state, &params).await {
        Ok(request) => request,
        Err(rejection) => return reject(state, rejection),
    };

    let session = match state.session_cookie.read(headers) {
        Some(token) => match session::find_active(&state.pool, &token).await {
            Ok(session) => session,
            Err(error) => {
                tracing::warn!(%error, "session lookup failed");
                return reject(state, Rejection::Unavailable);
            }
        },
        None => None,
    };
    let fresh_enough = |authenticated_at: i64| {
        request
            .max_age
            .is_none_or(|max_age| now() - authenticated_at <= max_age)
    };
    let session = session.filter(|s| !request.prompt_login && fresh_enough(s.authenticated_at));

    match session {
        Some(session) => {
            issue_code(
                state,
                &request,
                session.subject,
                session.authenticated_at,
                None,
            )
            .await
        }
        None if request.prompt_none => reject(
            state,
            Rejection::Redirect {
                redirect_uri: request.redirect_uri,
                state: request.state,
                error: "login_required",
                description: "no active Moongate session",
            },
        ),
        None => login_page(state, headers, &request, None),
    }
}

/// Handles the login form. CSRF is checked first, then the whole authorization
/// request is validated again from scratch: hidden fields are attacker-editable.
pub async fn login(State(state): State<AppState>, parts: Parts, body: Bytes) -> Response {
    let headers = &parts.headers;
    let mut params = parse_params(&body);
    let mut take = |name: &str| {
        let value = single(&params, name).ok().flatten().map(str::to_owned);
        params.retain(|(n, _)| n != name);
        value
    };
    let (csrf, email, password) = (take("csrf"), take("email"), take("password"));

    let ip = ratelimit::client_ip(&parts, state.client_ip_header.as_ref());
    let csrf_ok = match (state.csrf_cookie.read(headers), &csrf) {
        (Some(cookie), Some(field)) => crypto::hash_matches(field, &crypto::sha256_hex(&cookie)),
        _ => false,
    };
    if !csrf_ok {
        audit::record(
            &state.pool,
            audit::Event::new(audit::Kind::AuthenticationFailed)
                .ip(ip)
                .detail("csrf"),
        )
        .await;
        return error_page(
            StatusCode::BAD_REQUEST,
            "Your sign-in form expired or was not submitted from Moongate.",
        );
    }

    let request = match validate(&state, &params).await {
        Ok(request) => request,
        Err(rejection) => return reject(&state, rejection),
    };
    let client_id = request.client.id.as_str().to_owned();

    let (Some(email), Some(password)) = (email, password) else {
        return login_page(&state, headers, &request, Some(SIGN_IN_FAILED));
    };
    if email.len() > MAX_EMAIL_LEN || password.len() > MAX_PASSWORD_LEN {
        return login_page(&state, headers, &request, Some(SIGN_IN_FAILED));
    }

    let buckets = ratelimit::Buckets::new(&email, ip);
    match ratelimit::attempt(&state.pool, &buckets).await {
        Ok(false) => {}
        Ok(true) => {
            audit::record(
                &state.pool,
                audit::Event::new(audit::Kind::AuthenticationRateLimited)
                    .client(&client_id)
                    .ip(ip),
            )
            .await;
            let mut page = login_page(&state, headers, &request, Some(RATE_LIMITED));
            *page.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            return page;
        }
        Err(error) => {
            tracing::warn!(%error, "rate limit check failed");
            return reject(&state, Rejection::Unavailable);
        }
    }

    let outcome = state
        .upstream
        .authenticate(&email, Password::new(password))
        .await;
    if !matches!(outcome, Err(UpstreamError::Rejected))
        && let Err(error) = ratelimit::release(&state.pool, &buckets).await
    {
        tracing::warn!(%error, "rate limit release failed");
    }
    let identity = match outcome {
        Ok(identity) => identity,
        Err(UpstreamError::Rejected) => {
            audit::record(
                &state.pool,
                audit::Event::new(audit::Kind::AuthenticationFailed)
                    .client(&client_id)
                    .ip(ip)
                    .detail("credentials_rejected"),
            )
            .await;
            return login_page(&state, headers, &request, Some(SIGN_IN_FAILED));
        }
        Err(UpstreamError::Unavailable) => {
            tracing::warn!("OutlandsID unavailable during sign-in");
            audit::record(
                &state.pool,
                audit::Event::new(audit::Kind::AuthenticationFailed)
                    .client(&client_id)
                    .ip(ip)
                    .detail("upstream_unavailable"),
            )
            .await;
            return login_page(
                &state,
                headers,
                &request,
                Some("OutlandsID is unavailable right now. Try again shortly."),
            );
        }
    };

    let subject = match resolve_subject(&state.pool, &identity).await {
        Ok(subject) => subject,
        Err(error) => {
            tracing::warn!(%error, "subject resolution failed");
            return reject(&state, Rejection::Unavailable);
        }
    };
    audit::record(
        &state.pool,
        audit::Event::new(audit::Kind::AuthenticationSucceeded)
            .client(&client_id)
            .subject(subject)
            .ip(ip),
    )
    .await;

    // Session rotation: whatever session the browser presented is ended, never upgraded.
    if let Some(old) = state.session_cookie.read(headers)
        && let Err(error) = session::revoke(&state.pool, &old).await
    {
        tracing::warn!(%error, "revoking previous session failed");
        return reject(&state, Rejection::Unavailable);
    }
    let (token, session) = match session::create(&state.pool, subject).await {
        Ok(created) => created,
        Err(error) => {
            tracing::warn!(?error, "session creation failed");
            return reject(&state, Rejection::Unavailable);
        }
    };
    let cookie = state.session_cookie.set_cookie(&token);
    issue_code(
        &state,
        &request,
        subject,
        session.authenticated_at,
        Some(cookie),
    )
    .await
}

const SIGN_IN_FAILED: &str = "Sign-in failed. Check your OutlandsID email and password.";
const RATE_LIMITED: &str = "Too many sign-in attempts. Wait a few minutes and try again.";

async fn issue_code(
    state: &AppState,
    request: &AuthorizationRequest,
    subject: SubjectId,
    auth_time: i64,
    session_cookie: Option<HeaderValue>,
) -> Response {
    let Ok(code) = crypto::random_token() else {
        return reject(state, Rejection::Unavailable);
    };
    let stored = sqlx::query(
        "INSERT INTO authorization_codes \
             (code_hash, client_id, subject_id, redirect_uri, scopes, nonce, code_challenge, \
              auth_time, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, to_timestamp($8), now() + make_interval(secs => $9))",
    )
    .bind(crypto::sha256_hex(&code))
    .bind(request.client.id.as_str())
    .bind(subject.as_uuid())
    .bind(&request.redirect_uri)
    .bind(&request.scopes)
    .bind(&request.nonce)
    .bind(&request.code_challenge)
    .bind(auth_time as f64)
    .bind(CODE_LIFETIME_SECS as f64)
    .execute(&state.pool)
    .await;
    if let Err(error) = stored {
        tracing::warn!(%error, "storing authorization code failed");
        return reject(state, Rejection::Unavailable);
    }
    audit::record(
        &state.pool,
        audit::Event::new(audit::Kind::AuthorizationGranted)
            .client(request.client.id.as_str())
            .subject(subject),
    )
    .await;

    let mut params = vec![("code", code.as_str())];
    if let Some(s) = &request.state {
        params.push(("state", s));
    }
    params.push(("iss", state.issuer.as_str()));
    let mut response = redirect(&request.redirect_uri, &params);
    if let Some(cookie) = session_cookie {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

fn reject(state: &AppState, rejection: Rejection) -> Response {
    match rejection {
        Rejection::Local(message) => {
            tracing::info!(
                event = "authorization_denied",
                reason = message,
                "rejected locally"
            );
            error_page(StatusCode::BAD_REQUEST, message)
        }
        Rejection::Unavailable => error_page(
            StatusCode::SERVICE_UNAVAILABLE,
            "Moongate is temporarily unavailable.",
        ),
        Rejection::Redirect {
            redirect_uri,
            state: request_state,
            error,
            description,
        } => {
            tracing::info!(
                event = "authorization_denied",
                error,
                description,
                "error sent to client"
            );
            let mut params = vec![("error", error), ("error_description", description)];
            if let Some(s) = &request_state {
                params.push(("state", s));
            }
            params.push(("iss", state.issuer.as_str()));
            redirect(&redirect_uri, &params)
        }
    }
}

/// `redirect_uri` is always an exact registered value, already validated as a URL.
pub(crate) fn redirect(redirect_uri: &str, params: &[(&str, &str)]) -> Response {
    let Ok(mut url) = Url::parse(redirect_uri) else {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, BAD_CLIENT);
    };
    url.query_pairs_mut().extend_pairs(params);
    let mut response = StatusCode::SEE_OTHER.into_response();
    let headers = response.headers_mut();
    if let Ok(location) = HeaderValue::from_str(url.as_str()) {
        headers.insert(header::LOCATION, location);
    }
    no_store(headers);
    response
}

pub(crate) fn no_store(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage<'a> {
    client_name: &'a str,
    action: String,
    csrf: &'a str,
    fields: Vec<(&'static str, String)>,
    error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage<'a> {
    message: &'a str,
}

fn login_page(
    state: &AppState,
    headers: &HeaderMap,
    request: &AuthorizationRequest,
    error: Option<&str>,
) -> Response {
    // Reuse the browser's CSRF cookie so several open login tabs keep working.
    let csrf = match state.csrf_cookie.read(headers) {
        Some(existing) => existing,
        None => match crypto::random_token() {
            Ok(token) => token,
            Err(_) => return reject(state, Rejection::Unavailable),
        },
    };
    let page = LoginPage {
        client_name: &request.client.display_name,
        action: state.issuer.endpoint("/login"),
        csrf: &csrf,
        fields: request.form_fields(),
        error,
    };
    let mut response = html(StatusCode::OK, page.render());
    response
        .headers_mut()
        .append(header::SET_COOKIE, state.csrf_cookie.set(&csrf));
    response
}

pub(crate) fn error_page(status: StatusCode, message: &str) -> Response {
    html(status, ErrorPage { message }.render())
}

pub(crate) fn html(status: StatusCode, rendered: askama::Result<String>) -> Response {
    let Ok(body) = rendered else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut response = (status, Html(body)).into_response();
    let headers = response.headers_mut();
    no_store(headers);
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
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
    use sqlx::PgPool;
    use tower::ServiceExt;

    use super::*;
    use crate::client::tests::{TEST_REDIRECT, register_test_client};

    /// A well-formed S256 challenge (43 base64url characters).
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    struct Reply {
        status: StatusCode,
        location: Option<Url>,
        cookies: Vec<String>,
        body: String,
    }

    impl Reply {
        fn param(&self, name: &str) -> Option<String> {
            self.location
                .as_ref()?
                .query_pairs()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.into_owned())
        }

        fn cookie(&self, name: &str) -> Option<String> {
            self.cookies.iter().find_map(|c| {
                c.split(';')
                    .next()?
                    .strip_prefix(&format!("{name}="))
                    .map(str::to_owned)
            })
        }

        fn is_login_page(&self) -> bool {
            self.status == StatusCode::OK && self.body.contains("Sign in with OutlandsID")
        }
    }

    async fn send(pool: &PgPool, request: Request<Body>) -> Reply {
        let response = crate::tests::test_app(pool.clone())
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        Reply {
            status,
            location: headers
                .get(header::LOCATION)
                .map(|l| Url::parse(l.to_str().unwrap()).unwrap()),
            cookies: headers
                .get_all(header::SET_COOKIE)
                .iter()
                .map(|c| c.to_str().unwrap().to_owned())
                .collect(),
            body: String::from_utf8(body.to_vec()).unwrap(),
        }
    }

    fn encode(pairs: &[(&str, &str)]) -> String {
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish()
    }

    fn base(client: &str) -> Vec<(&str, &str)> {
        vec![
            ("response_type", "code"),
            ("client_id", client),
            ("redirect_uri", TEST_REDIRECT),
            ("scope", "openid"),
            ("state", "st&te=1"),
            ("nonce", "n-0S6"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ]
    }

    fn with(
        mut pairs: Vec<(&'static str, &'static str)>,
        name: &'static str,
        value: &'static str,
    ) -> Vec<(&'static str, &'static str)> {
        pairs.retain(|(n, _)| *n != name);
        pairs.push((name, value));
        pairs
    }

    fn without(
        mut pairs: Vec<(&'static str, &'static str)>,
        name: &str,
    ) -> Vec<(&'static str, &'static str)> {
        pairs.retain(|(n, _)| *n != name);
        pairs
    }

    async fn authorize(pool: &PgPool, pairs: &[(&str, &str)], cookie: Option<&str>) -> Reply {
        let mut request = Request::get(format!("/authorize?{}", encode(pairs)));
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        send(pool, request.body(Body::empty()).unwrap()).await
    }

    async fn login(pool: &PgPool, form: &[(&str, &str)], cookie: Option<&str>) -> Reply {
        let mut request = Request::post("/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        send(pool, request.body(Body::from(encode(form))).unwrap()).await
    }

    /// GET /authorize, then submit the login form the way a browser would.
    async fn sign_in(pool: &PgPool, pairs: &[(&str, &str)], extra_cookie: &str) -> Reply {
        let page = authorize(pool, pairs, None).await;
        assert!(page.is_login_page());
        let csrf = page.cookie("__Host-moongate_csrf").unwrap();
        let mut form = pairs.to_vec();
        form.extend([
            ("csrf", csrf.as_str()),
            ("email", "player@moongate.localhost"),
            ("password", "player"),
        ]);
        let cookie = format!("__Host-moongate_csrf={csrf}; {extra_cookie}");
        login(pool, &form, Some(&cookie)).await
    }

    async fn setup(pool: &PgPool) {
        register_test_client(pool, "rp", ClientType::Confidential).await;
        register_test_client(pool, "spa", ClientType::Public).await;
    }

    async fn code_count(pool: &PgPool) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM authorization_codes")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    fn assert_local_error(reply: &Reply) {
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert!(reply.location.is_none(), "redirected: {:?}", reply.location);
    }

    fn assert_redirect_error(reply: &Reply, error: &str) {
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        let location = reply.location.as_ref().unwrap();
        assert!(location.as_str().starts_with(TEST_REDIRECT));
        assert_eq!(reply.param("error").as_deref(), Some(error));
        assert_eq!(reply.param("iss").as_deref(), Some("https://moongate.test"));
        assert!(reply.param("code").is_none());
    }

    // --- Client and redirect URI: never redirect ---

    #[sqlx::test]
    async fn unknown_client_is_rejected_locally(pool: PgPool) {
        setup(&pool).await;
        assert_local_error(&authorize(&pool, &base("nobody"), None).await);
        assert_local_error(&authorize(&pool, &base("Not Valid!"), None).await);
        assert_local_error(&authorize(&pool, &without(base("rp"), "client_id"), None).await);
    }

    #[sqlx::test]
    async fn disabled_client_is_rejected_locally(pool: PgPool) {
        setup(&pool).await;
        sqlx::query("UPDATE clients SET enabled = false WHERE client_id = 'rp'")
            .execute(&pool)
            .await
            .unwrap();
        assert_local_error(&authorize(&pool, &base("rp"), None).await);
    }

    #[sqlx::test]
    async fn unregistered_redirect_uri_is_rejected_locally(pool: PgPool) {
        setup(&pool).await;
        for bad in [
            "https://evil.test/callback",
            "https://rp.test/callback/",
            "https://rp.test/callback?next=https://evil.test",
            "https://rp.test/callback.evil.test",
        ] {
            let reply = authorize(&pool, &with(base("rp"), "redirect_uri", bad), None).await;
            assert_local_error(&reply);
            assert!(!reply.body.contains("evil.test"), "echoed attacker URI");
        }
        assert_local_error(&authorize(&pool, &without(base("rp"), "redirect_uri"), None).await);
    }

    #[sqlx::test]
    async fn duplicated_client_or_redirect_is_rejected_locally(pool: PgPool) {
        setup(&pool).await;
        let mut dup_client = base("rp");
        dup_client.push(("client_id", "spa"));
        assert_local_error(&authorize(&pool, &dup_client, None).await);
        let mut dup_redirect = base("rp");
        dup_redirect.push(("redirect_uri", "https://evil.test/cb"));
        assert_local_error(&authorize(&pool, &dup_redirect, None).await);
    }

    // --- Errors reported to the client ---

    #[sqlx::test]
    async fn duplicated_parameter_is_invalid_request(pool: PgPool) {
        setup(&pool).await;
        let mut pairs = base("rp");
        pairs.push(("scope", "openid"));
        assert_redirect_error(&authorize(&pool, &pairs, None).await, "invalid_request");
    }

    #[sqlx::test]
    async fn error_redirect_preserves_state(pool: PgPool) {
        setup(&pool).await;
        let reply = authorize(&pool, &with(base("rp"), "response_type", "token"), None).await;
        assert_redirect_error(&reply, "unsupported_response_type");
        assert_eq!(reply.param("state").as_deref(), Some("st&te=1"));
    }

    #[sqlx::test]
    async fn response_type_is_required_and_code_only(pool: PgPool) {
        setup(&pool).await;
        let missing = authorize(&pool, &without(base("rp"), "response_type"), None).await;
        assert_redirect_error(&missing, "invalid_request");
        for bad in ["token", "id_token", "code id_token", "code token"] {
            let reply = authorize(&pool, &with(base("rp"), "response_type", bad), None).await;
            assert_redirect_error(&reply, "unsupported_response_type");
        }
    }

    #[sqlx::test]
    async fn openid_scope_is_required(pool: PgPool) {
        setup(&pool).await;
        let reply = authorize(&pool, &with(base("rp"), "scope", "profile"), None).await;
        assert_redirect_error(&reply, "invalid_scope");
        let reply = authorize(&pool, &without(base("rp"), "scope"), None).await;
        assert_redirect_error(&reply, "invalid_scope");
    }

    #[sqlx::test]
    async fn unallowed_scope_is_rejected(pool: PgPool) {
        setup(&pool).await;
        let reply = authorize(&pool, &with(base("rp"), "scope", "openid email"), None).await;
        assert_redirect_error(&reply, "invalid_scope");
    }

    #[sqlx::test]
    async fn public_client_requires_pkce(pool: PgPool) {
        setup(&pool).await;
        let pairs = without(
            without(base("spa"), "code_challenge"),
            "code_challenge_method",
        );
        assert_redirect_error(&authorize(&pool, &pairs, None).await, "invalid_request");
    }

    #[sqlx::test]
    async fn confidential_client_may_omit_pkce(pool: PgPool) {
        setup(&pool).await;
        let pairs = without(
            without(base("rp"), "code_challenge"),
            "code_challenge_method",
        );
        assert!(authorize(&pool, &pairs, None).await.is_login_page());
    }

    #[sqlx::test]
    async fn pkce_rejects_plain_and_missing_method(pool: PgPool) {
        setup(&pool).await;
        let plain = with(base("spa"), "code_challenge_method", "plain");
        assert_redirect_error(&authorize(&pool, &plain, None).await, "invalid_request");
        let missing = without(base("spa"), "code_challenge_method");
        assert_redirect_error(&authorize(&pool, &missing, None).await, "invalid_request");
        let method_only = without(base("spa"), "code_challenge");
        assert_redirect_error(
            &authorize(&pool, &method_only, None).await,
            "invalid_request",
        );
    }

    #[sqlx::test]
    async fn pkce_rejects_malformed_challenge(pool: PgPool) {
        setup(&pool).await;
        for bad in [
            "short",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c=",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cMM",
        ] {
            let reply = authorize(&pool, &with(base("spa"), "code_challenge", bad), None).await;
            assert_redirect_error(&reply, "invalid_request");
        }
    }

    #[sqlx::test]
    async fn request_objects_and_other_response_modes_are_rejected(pool: PgPool) {
        setup(&pool).await;
        let reply = authorize(&pool, &with(base("rp"), "request", "eyJ..."), None).await;
        assert_redirect_error(&reply, "request_not_supported");
        let reply = authorize(
            &pool,
            &with(base("rp"), "request_uri", "https://x.test/r"),
            None,
        )
        .await;
        assert_redirect_error(&reply, "request_uri_not_supported");
        let reply = authorize(&pool, &with(base("rp"), "response_mode", "fragment"), None).await;
        assert_redirect_error(&reply, "invalid_request");
    }

    #[sqlx::test]
    async fn prompt_none_without_session_is_login_required(pool: PgPool) {
        setup(&pool).await;
        let reply = authorize(&pool, &with(base("rp"), "prompt", "none"), None).await;
        assert_redirect_error(&reply, "login_required");
        let reply = authorize(&pool, &with(base("rp"), "prompt", "none login"), None).await;
        assert_redirect_error(&reply, "invalid_request");
    }

    #[sqlx::test]
    async fn unknown_parameters_are_ignored(pool: PgPool) {
        setup(&pool).await;
        let reply = authorize(&pool, &with(base("rp"), "ui_locales", "en"), None).await;
        assert!(reply.is_login_page());
    }

    // --- Login page and form ---

    #[sqlx::test]
    async fn login_page_is_protected_and_escapes_client_name(pool: PgPool) {
        setup(&pool).await;
        sqlx::query(
            "UPDATE clients SET display_name = '<script>alert(1)</script>' WHERE client_id = 'rp'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let reply = authorize(&pool, &base("rp"), None).await;
        assert!(reply.is_login_page());
        assert!(!reply.body.contains("<script>alert"));
        assert!(reply.body.contains("&#60;script&#62;") || reply.body.contains("&lt;script&gt;"));
        let csrf = reply.cookie("__Host-moongate_csrf").unwrap();
        assert!(reply.body.contains(&csrf), "form must carry the CSRF token");
        assert!(reply.cookie("__Host-moongate_session").is_none());
        assert_eq!(code_count(&pool).await, 0);
    }

    #[sqlx::test]
    async fn login_without_csrf_cookie_is_rejected(pool: PgPool) {
        setup(&pool).await;
        let mut form = base("rp");
        form.extend([
            ("csrf", "ab"),
            ("email", "player@moongate.localhost"),
            ("password", "player"),
        ]);
        let reply = login(&pool, &form, None).await;
        assert_local_error(&reply);
        assert!(reply.cookie("__Host-moongate_session").is_none());
    }

    #[sqlx::test]
    async fn login_with_mismatched_csrf_is_rejected(pool: PgPool) {
        setup(&pool).await;
        let (cookie_token, form_token) = ("ab".repeat(32), "cd".repeat(32));
        let mut form = base("rp");
        form.extend([
            ("csrf", form_token.as_str()),
            ("email", "player@moongate.localhost"),
            ("password", "player"),
        ]);
        let cookie = format!("__Host-moongate_csrf={cookie_token}");
        let reply = login(&pool, &form, Some(&cookie)).await;
        assert_local_error(&reply);
        assert_eq!(code_count(&pool).await, 0);
    }

    #[sqlx::test]
    async fn wrong_password_shows_generic_error_and_issues_nothing(pool: PgPool) {
        setup(&pool).await;
        let page = authorize(&pool, &base("rp"), None).await;
        let csrf = page.cookie("__Host-moongate_csrf").unwrap();
        let mut form = base("rp");
        form.extend([
            ("csrf", csrf.as_str()),
            ("email", "player@moongate.localhost"),
            ("password", "nope"),
        ]);
        let reply = login(&pool, &form, Some(&format!("__Host-moongate_csrf={csrf}"))).await;
        assert!(reply.is_login_page());
        assert!(reply.body.contains(SIGN_IN_FAILED));
        assert!(reply.location.is_none());
        assert!(reply.cookie("__Host-moongate_session").is_none());
        assert_eq!(code_count(&pool).await, 0);
    }

    async fn attempt_password(pool: &PgPool, password: &str) -> Reply {
        let page = authorize(pool, &base("rp"), None).await;
        let csrf = page.cookie("__Host-moongate_csrf").unwrap();
        let mut form = base("rp");
        form.extend([
            ("csrf", csrf.as_str()),
            ("email", "player@moongate.localhost"),
            ("password", password),
        ]);
        login(pool, &form, Some(&format!("__Host-moongate_csrf={csrf}"))).await
    }

    #[sqlx::test]
    async fn repeated_wrong_passwords_lock_the_account_temporarily(pool: PgPool) {
        setup(&pool).await;
        for _ in 0..crate::ratelimit::MAX_ATTEMPTS_PER_EMAIL {
            assert!(
                attempt_password(&pool, "wrong")
                    .await
                    .body
                    .contains(SIGN_IN_FAILED)
            );
        }
        // Even the right password is refused now, without reaching upstream.
        let reply = attempt_password(&pool, "player").await;
        assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(reply.body.contains(RATE_LIMITED));
        assert!(reply.location.is_none());
        assert!(reply.cookie("__Host-moongate_session").is_none());
        assert_eq!(code_count(&pool).await, 0);
    }

    #[sqlx::test]
    async fn sign_in_flows_are_audited(pool: PgPool) {
        use crate::audit::tests::{events, kinds};
        setup(&pool).await;
        let before = events(&pool).await.len();

        attempt_password(&pool, "wrong").await;
        let failed = events(&pool).await.pop().unwrap();
        assert_eq!(failed.0, "authentication_failed");
        assert_eq!(failed.1.as_deref(), Some("rp"));
        assert_eq!(failed.3.as_deref(), Some("credentials_rejected"));
        assert!(!failed.4, "a failed attempt names no subject");

        sign_in(&pool, &base("rp"), "").await;
        let trail: Vec<String> = kinds(&pool).await.split_off(before + 1);
        assert_eq!(
            trail,
            [
                "subject_created",
                "authentication_succeeded",
                "session_created",
                "authorization_granted"
            ]
        );
    }

    #[sqlx::test]
    async fn successful_logins_are_not_rate_limited(pool: PgPool) {
        setup(&pool).await;
        for _ in 0..(crate::ratelimit::MAX_ATTEMPTS_PER_EMAIL * 2) {
            assert_eq!(
                attempt_password(&pool, "player").await.status,
                StatusCode::SEE_OTHER
            );
        }
    }

    #[sqlx::test]
    async fn login_revalidates_tampered_redirect_uri(pool: PgPool) {
        setup(&pool).await;
        let page = authorize(&pool, &base("rp"), None).await;
        let csrf = page.cookie("__Host-moongate_csrf").unwrap();
        let mut form = with(base("rp"), "redirect_uri", "https://evil.test/cb");
        form.extend([
            ("csrf", csrf.as_str()),
            ("email", "player@moongate.localhost"),
            ("password", "player"),
        ]);
        let reply = login(&pool, &form, Some(&format!("__Host-moongate_csrf={csrf}"))).await;
        assert_local_error(&reply);
        assert_eq!(code_count(&pool).await, 0);
    }

    #[sqlx::test]
    async fn successful_login_issues_bound_code_and_session(pool: PgPool) {
        setup(&pool).await;
        let reply = sign_in(&pool, &base("rp"), "").await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        assert!(
            reply
                .location
                .as_ref()
                .unwrap()
                .as_str()
                .starts_with(TEST_REDIRECT)
        );
        assert_eq!(reply.param("state").as_deref(), Some("st&te=1"));
        assert_eq!(reply.param("iss").as_deref(), Some("https://moongate.test"));
        assert!(reply.cookie("__Host-moongate_session").is_some());

        let code = reply.param("code").unwrap();
        assert_eq!(code.len(), 64);
        let row: (
            String,
            String,
            Vec<String>,
            Option<String>,
            Option<String>,
            f64,
        ) = sqlx::query_as(
            "SELECT client_id, redirect_uri, scopes, nonce, code_challenge, \
                    extract(epoch FROM expires_at - created_at)::float8 \
             FROM authorization_codes WHERE code_hash = $1",
        )
        .bind(crypto::sha256_hex(&code))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, "rp");
        assert_eq!(row.1, TEST_REDIRECT);
        assert_eq!(row.2, vec!["openid".to_owned()]);
        assert_eq!(row.3.as_deref(), Some("n-0S6"));
        assert_eq!(row.4.as_deref(), Some(CHALLENGE));
        assert_eq!(row.5, CODE_LIFETIME_SECS as f64);
    }

    #[sqlx::test]
    async fn login_rotates_presented_session(pool: PgPool) {
        setup(&pool).await;
        let first = sign_in(&pool, &base("rp"), "").await;
        let old = first.cookie("__Host-moongate_session").unwrap();
        let second = sign_in(
            &pool,
            &base("rp"),
            &format!("__Host-moongate_session={old}"),
        )
        .await;
        let new = second.cookie("__Host-moongate_session").unwrap();
        assert_ne!(old, new);
        assert!(session::find_active(&pool, &old).await.unwrap().is_none());
        assert!(session::find_active(&pool, &new).await.unwrap().is_some());
    }

    // --- SSO ---

    async fn session_cookie(pool: &PgPool) -> String {
        let reply = sign_in(pool, &base("rp"), "").await;
        format!(
            "__Host-moongate_session={}",
            reply.cookie("__Host-moongate_session").unwrap()
        )
    }

    #[sqlx::test]
    async fn existing_session_issues_code_without_login(pool: PgPool) {
        setup(&pool).await;
        let cookie = session_cookie(&pool).await;
        let reply = authorize(&pool, &base("spa"), Some(&cookie)).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        assert!(reply.param("code").is_some());
        assert!(
            reply.cookie("__Host-moongate_session").is_none(),
            "SSO must not reissue the session"
        );
    }

    #[sqlx::test]
    async fn prompt_none_with_session_issues_code(pool: PgPool) {
        setup(&pool).await;
        let cookie = session_cookie(&pool).await;
        let reply = authorize(&pool, &with(base("rp"), "prompt", "none"), Some(&cookie)).await;
        assert!(reply.param("code").is_some());
    }

    #[sqlx::test]
    async fn revoked_session_cannot_authorize(pool: PgPool) {
        setup(&pool).await;
        let cookie = session_cookie(&pool).await;
        let token = cookie.split_once('=').unwrap().1;
        session::revoke(&pool, token).await.unwrap();
        assert!(
            authorize(&pool, &base("rp"), Some(&cookie))
                .await
                .is_login_page()
        );
    }

    #[sqlx::test]
    async fn prompt_login_forces_reauthentication(pool: PgPool) {
        setup(&pool).await;
        let cookie = session_cookie(&pool).await;
        let reply = authorize(&pool, &with(base("rp"), "prompt", "login"), Some(&cookie)).await;
        assert!(reply.is_login_page());
    }

    #[sqlx::test]
    async fn max_age_exceeded_forces_reauthentication(pool: PgPool) {
        setup(&pool).await;
        let cookie = session_cookie(&pool).await;
        sqlx::query("UPDATE sessions SET authenticated_at = now() - interval '1 hour'")
            .execute(&pool)
            .await
            .unwrap();
        let reply = authorize(&pool, &with(base("rp"), "max_age", "60"), Some(&cookie)).await;
        assert!(reply.is_login_page());
        let reply = authorize(&pool, &with(base("rp"), "max_age", "7200"), Some(&cookie)).await;
        assert!(reply.param("code").is_some());
        let reply = authorize(&pool, &with(base("rp"), "max_age", "-1"), Some(&cookie)).await;
        assert_redirect_error(&reply, "invalid_request");
    }

    #[sqlx::test]
    async fn authorize_accepts_post(pool: PgPool) {
        setup(&pool).await;
        let request = Request::post("/authorize")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(encode(&base("rp"))))
            .unwrap();
        assert!(send(&pool, request).await.is_login_page());
    }
}
