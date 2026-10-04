//! RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0): `GET`/`POST /logout`.
//!
//! This ends only the Moongate SSO session. Relying parties end their own sessions, and
//! there is no upstream OutlandsID session to end (the compatibility adapter keeps none).
//!
//! Logout is silent only when the request carries an ID token that Moongate signed for
//! the browser's current subject. Anything else needs a CSRF-protected confirmation, so a
//! third-party page cannot log people out with a hidden link.

use askama::Template;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use jsonwebtoken::{DecodingKey, Validation};
use serde_json::Value;

use crate::authorize::{Params, error_page, has_duplicates, html, parse_params, redirect, single};
use crate::client::{Client, ClientId};
use crate::{AppState, crypto, session, signing};

const BAD_REQUEST: &str = "This sign-out request is not valid.";

#[derive(Template)]
#[template(path = "logout_confirm.html")]
struct ConfirmPage<'a> {
    action: String,
    csrf: &'a str,
    fields: Vec<(&'static str, String)>,
}

#[derive(Template)]
#[template(path = "signed_out.html")]
struct SignedOutPage;

/// Who a valid `id_token_hint` names.
struct Hint {
    subject: String,
    audience: String,
}

/// A logout request whose client and post-logout URI (if any) passed validation.
struct LogoutRequest {
    hint: Option<Hint>,
    client: Option<Client>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
}

pub async fn logout_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    logout(
        &state,
        &headers,
        parse_params(query.unwrap_or_default().as_bytes()),
    )
    .await
}

pub async fn logout_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    logout(&state, &headers, parse_params(&body)).await
}

async fn logout(state: &AppState, headers: &HeaderMap, mut params: Params) -> Response {
    // Our own confirmation form adds these two; strip them before validating the rest.
    let mut take = |name: &str| {
        let value = single(&params, name).ok().flatten().map(str::to_owned);
        params.retain(|(n, _)| n != name);
        value
    };
    let (csrf, confirm) = (take("csrf"), take("confirm"));

    let request = match validate(state, &params).await {
        Ok(request) => request,
        Err(message) => return error_page(StatusCode::BAD_REQUEST, message),
    };

    let token = state.session_cookie.read(headers);
    let session = match &token {
        Some(token) => match session::find_active(&state.pool, token).await {
            Ok(session) => session,
            Err(error) => {
                tracing::warn!(%error, "session lookup failed");
                return error_page(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Moongate is temporarily unavailable.",
                );
            }
        },
        None => None,
    };

    let confirmed =
        confirm.as_deref() == Some("yes") && csrf_matches(state, headers, csrf.as_deref());
    if confirm.is_some() && !confirmed {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Your sign-out form expired or was not submitted from Moongate.",
        );
    }

    let hint_matches_session = match (&request.hint, &session) {
        (Some(hint), Some(session)) => hint.subject == session.subject.as_uuid().to_string(),
        (Some(_), None) => true,
        (None, _) => false,
    };
    if session.is_some() && !hint_matches_session && !confirmed {
        return confirm_page(state, headers, &request);
    }

    if let Some(token) = &token
        && let Err(error) = session::revoke(&state.pool, token).await
    {
        tracing::warn!(%error, "session revocation failed");
        return error_page(
            StatusCode::SERVICE_UNAVAILABLE,
            "Moongate is temporarily unavailable.",
        );
    }

    let mut response = match &request.post_logout_redirect_uri {
        Some(uri) => {
            let params: Vec<(&str, &str)> = request
                .state
                .as_deref()
                .map(|s| ("state", s))
                .into_iter()
                .collect();
            redirect(uri, &params)
        }
        None => html(StatusCode::OK, SignedOutPage.render()),
    };
    let headers = response.headers_mut();
    headers.append(header::SET_COOKIE, state.session_cookie.clear_cookie());
    response
}

async fn validate(state: &AppState, params: &Params) -> Result<LogoutRequest, &'static str> {
    if has_duplicates(params) {
        return Err(BAD_REQUEST);
    }
    let get = |name| single(params, name).ok().flatten();

    let hint = match get("id_token_hint") {
        Some(token) => Some(verify_hint(state, token).await.ok_or(BAD_REQUEST)?),
        None => None,
    };

    let client_id = match (get("client_id"), &hint) {
        (Some(id), Some(hint)) if id != hint.audience => return Err(BAD_REQUEST),
        (Some(id), _) => Some(id),
        (None, Some(hint)) => Some(hint.audience.as_str()),
        (None, None) => None,
    };
    let client = match client_id {
        Some(id) => {
            let id = ClientId::parse(id).ok_or(BAD_REQUEST)?;
            Some(
                Client::find_enabled(&state.pool, &id)
                    .await
                    .map_err(|_| BAD_REQUEST)?
                    .ok_or(BAD_REQUEST)?,
            )
        }
        None => None,
    };

    // A post-logout URI is only ever used if it is exactly registered for a known client.
    let post_logout_redirect_uri = match get("post_logout_redirect_uri") {
        Some(uri) => match &client {
            Some(client) if client.is_registered_post_logout_uri(uri) => Some(uri.to_owned()),
            _ => return Err(BAD_REQUEST),
        },
        None => None,
    };

    Ok(LogoutRequest {
        hint,
        client,
        post_logout_redirect_uri,
        state: get("state").filter(|s| s.len() <= 2048).map(str::to_owned),
    })
}

/// An ID token Moongate issued: signature from a published key, our issuer. Expiry is
/// deliberately not checked; the spec allows expired hints.
async fn verify_hint(state: &AppState, token: &str) -> Option<Hint> {
    let kid = jsonwebtoken::decode_header(token).ok()?.kid?;
    let jwks = signing::published_jwks(&state.pool).await.ok()?;
    let key = DecodingKey::from_jwk(jwks.find(&kid)?).ok()?;
    let mut validation = Validation::new(signing::ALGORITHM);
    validation.set_issuer(&[state.issuer.as_str()]);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.set_required_spec_claims(&["iss", "sub", "aud"]);
    let claims = jsonwebtoken::decode::<Value>(token, &key, &validation)
        .ok()?
        .claims;
    Some(Hint {
        subject: claims.get("sub")?.as_str()?.to_owned(),
        audience: claims.get("aud")?.as_str()?.to_owned(),
    })
}

fn csrf_matches(state: &AppState, headers: &HeaderMap, field: Option<&str>) -> bool {
    match (state.csrf_cookie.read(headers), field) {
        (Some(cookie), Some(field)) => crypto::hash_matches(field, &crypto::sha256_hex(&cookie)),
        _ => false,
    }
}

fn confirm_page(state: &AppState, headers: &HeaderMap, request: &LogoutRequest) -> Response {
    let csrf = match state.csrf_cookie.read(headers) {
        Some(existing) => existing,
        None => match crypto::random_token() {
            Ok(token) => token,
            Err(_) => {
                return error_page(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Moongate is temporarily unavailable.",
                );
            }
        },
    };
    // Only validated values are carried; they are re-validated on submit anyway.
    let mut fields = Vec::new();
    if let Some(client) = &request.client {
        fields.push(("client_id", client.id.as_str().to_owned()));
    }
    if let Some(uri) = &request.post_logout_redirect_uri {
        fields.push(("post_logout_redirect_uri", uri.clone()));
    }
    if let Some(s) = &request.state {
        fields.push(("state", s.clone()));
    }
    let page = ConfirmPage {
        action: state.issuer.endpoint("/logout"),
        csrf: &csrf,
        fields,
    };
    let mut response = html(StatusCode::OK, page.render());
    response
        .headers_mut()
        .append(header::SET_COOKIE, state.csrf_cookie.set(&csrf));
    response
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use serde_json::json;
    use sqlx::PgPool;
    use tower::ServiceExt;
    use url::Url;

    use super::*;
    use crate::client::ClientType;
    use crate::client::tests::{TEST_POST_LOGOUT, TEST_REDIRECT, register_test_client};
    use crate::identity::{SubjectId, resolve_subject};
    use crate::tests::shared_test_key;
    use crate::upstream::{OutlandsId, UpstreamIdentity};

    struct Reply {
        status: StatusCode,
        location: Option<Url>,
        cookies: Vec<String>,
        body: String,
    }

    impl Reply {
        fn cleared_session(&self) -> bool {
            self.cookies
                .iter()
                .any(|c| c.starts_with("__Host-moongate_session=;") && c.contains("Max-Age=0"))
        }
        fn csrf(&self) -> Option<String> {
            self.cookies.iter().find_map(|c| {
                c.split(';')
                    .next()?
                    .strip_prefix("__Host-moongate_csrf=")
                    .map(str::to_owned)
            })
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

    async fn get(pool: &PgPool, pairs: &[(&str, &str)], cookie: Option<&str>) -> Reply {
        let mut request = Request::get(format!("/logout?{}", encode(pairs)));
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        send(pool, request.body(Body::empty()).unwrap()).await
    }

    async fn post(pool: &PgPool, pairs: &[(&str, &str)], cookie: &str) -> Reply {
        let request = Request::post("/logout")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, cookie)
            .body(Body::from(encode(pairs)))
            .unwrap();
        send(pool, request).await
    }

    struct Fixture {
        subject: SubjectId,
        token: String,
        cookie: String,
    }

    async fn setup(pool: &PgPool, outlands_id: &str) -> Fixture {
        shared_test_key().activate(pool).await.unwrap();
        if Client::find_enabled(pool, &ClientId::parse("rp").unwrap())
            .await
            .unwrap()
            .is_none()
        {
            register_test_client(pool, "rp", ClientType::Confidential).await;
            register_test_client(pool, "spa", ClientType::Public).await;
        }
        user_with_session(pool, outlands_id).await
    }

    async fn user_with_session(pool: &PgPool, outlands_id: &str) -> Fixture {
        let identity = UpstreamIdentity {
            outlands_id: OutlandsId::parse(outlands_id).unwrap(),
            email: "player@moongate.localhost".into(),
            role: "player".into(),
        };
        let subject = resolve_subject(pool, &identity).await.unwrap();
        let (token, _) = session::create(pool, subject).await.unwrap();
        // SessionToken never reveals its value; read it back from the cookie it produces.
        let set_cookie =
            crate::session::CookiePolicy::session(&crate::tests::test_issuer()).set_cookie(&token);
        let cookie = set_cookie
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let token = cookie.split_once('=').unwrap().1.to_owned();
        Fixture {
            subject,
            token,
            cookie,
        }
    }

    fn id_token(subject: &str, audience: &str, issuer: &str, exp_offset: i64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        shared_test_key()
            .sign(&json!({ "iss": issuer, "sub": subject, "aud": audience, "iat": now, "exp": now + exp_offset }))
            .unwrap()
    }

    fn hint_for(f: &Fixture) -> String {
        id_token(
            &f.subject.as_uuid().to_string(),
            "rp",
            "https://moongate.test",
            300,
        )
    }

    async fn active(pool: &PgPool, f: &Fixture) -> bool {
        session::find_active(pool, &f.token)
            .await
            .unwrap()
            .is_some()
    }

    #[sqlx::test]
    async fn valid_hint_logs_out_silently_and_redirects(pool: PgPool) {
        let f = setup(&pool, "10001").await;
        let hint = hint_for(&f);
        let reply = get(
            &pool,
            &[
                ("id_token_hint", &hint),
                ("post_logout_redirect_uri", TEST_POST_LOGOUT),
                ("state", "s1"),
            ],
            Some(&f.cookie),
        )
        .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        let location = reply.location.as_ref().unwrap();
        assert!(location.as_str().starts_with(TEST_POST_LOGOUT));
        assert_eq!(
            location
                .query_pairs()
                .find(|(k, _)| k == "state")
                .unwrap()
                .1,
            "s1"
        );
        assert!(reply.cleared_session());
        assert!(!active(&pool, &f).await);
    }

    #[sqlx::test]
    async fn expired_hint_is_still_accepted(pool: PgPool) {
        let f = setup(&pool, "10001").await;
        let hint = id_token(
            &f.subject.as_uuid().to_string(),
            "rp",
            "https://moongate.test",
            -3600,
        );
        let reply = get(&pool, &[("id_token_hint", &hint)], Some(&f.cookie)).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert!(reply.body.contains("left Moongate"));
        assert!(!active(&pool, &f).await);
    }

    #[sqlx::test]
    async fn forged_or_foreign_hints_are_rejected(pool: PgPool) {
        let f = setup(&pool, "10001").await;
        let subject = f.subject.as_uuid().to_string();
        let unpublished = crate::signing::tests::test_key()
            .sign(&json!({ "iss": "https://moongate.test", "sub": subject, "aud": "rp" }))
            .unwrap();
        for hint in [
            unpublished,
            id_token(&subject, "rp", "https://evil.test", 300),
            id_token(&subject, "nobody", "https://moongate.test", 300),
            "garbage".to_owned(),
        ] {
            let reply = get(&pool, &[("id_token_hint", &hint)], Some(&f.cookie)).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST);
            assert!(reply.location.is_none());
            assert!(active(&pool, &f).await, "session must survive a bad hint");
        }
    }

    #[sqlx::test]
    async fn unregistered_post_logout_uri_is_never_used(pool: PgPool) {
        let f = setup(&pool, "10001").await;
        let hint = hint_for(&f);
        for uri in [
            "https://evil.test/",
            TEST_REDIRECT,
            "https://rp.test/logged-out/",
        ] {
            let reply = get(
                &pool,
                &[("id_token_hint", &hint), ("post_logout_redirect_uri", uri)],
                Some(&f.cookie),
            )
            .await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{uri}");
            assert!(reply.location.is_none());
            assert!(active(&pool, &f).await);
        }
        // A post-logout URI needs a client to check it against.
        let reply = get(
            &pool,
            &[("post_logout_redirect_uri", TEST_POST_LOGOUT)],
            Some(&f.cookie),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    }

    #[sqlx::test]
    async fn client_id_must_match_hint_audience(pool: PgPool) {
        let f = setup(&pool, "10001").await;
        let hint = hint_for(&f);
        let reply = get(
            &pool,
            &[("id_token_hint", &hint), ("client_id", "spa")],
            Some(&f.cookie),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert!(active(&pool, &f).await);
    }

    #[sqlx::test]
    async fn logout_without_hint_requires_confirmation(pool: PgPool) {
        let f = setup(&pool, "10001").await;
        let pairs = [
            ("client_id", "rp"),
            ("post_logout_redirect_uri", TEST_POST_LOGOUT),
        ];
        let page = get(&pool, &pairs, Some(&f.cookie)).await;
        assert_eq!(page.status, StatusCode::OK);
        assert!(page.body.contains("Sign out of Moongate"));
        assert!(active(&pool, &f).await, "nothing happens until confirmed");

        let csrf = page.csrf().unwrap();
        let mut form = pairs.to_vec();
        form.extend([("csrf", csrf.as_str()), ("confirm", "yes")]);
        let cookie = format!("{}; __Host-moongate_csrf={csrf}", f.cookie);
        let reply = post(&pool, &form, &cookie).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        assert!(
            reply
                .location
                .unwrap()
                .as_str()
                .starts_with(TEST_POST_LOGOUT)
        );
        assert!(!active(&pool, &f).await);
    }

    #[sqlx::test]
    async fn confirmation_requires_csrf(pool: PgPool) {
        let f = setup(&pool, "10001").await;
        let other = "ab".repeat(32);
        let form = [("csrf", "cd".repeat(32)), ("confirm", "yes".to_owned())];
        let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let reply = post(
            &pool,
            &form,
            &format!("{}; __Host-moongate_csrf={other}", f.cookie),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        let reply = post(&pool, &[("confirm", "yes")], &f.cookie).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert!(active(&pool, &f).await);
    }

    #[sqlx::test]
    async fn hint_for_another_subject_requires_confirmation(pool: PgPool) {
        let f = setup(&pool, "10001").await;
        let attacker = setup(&pool, "40000").await;
        let reply = get(
            &pool,
            &[("id_token_hint", &hint_for(&attacker))],
            Some(&f.cookie),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        assert!(reply.body.contains("Sign out of Moongate"));
        assert!(active(&pool, &f).await);
    }

    #[sqlx::test]
    async fn logout_without_session_just_completes(pool: PgPool) {
        let f = setup(&pool, "10001").await;
        let reply = get(&pool, &[], None).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert!(reply.body.contains("left Moongate"));
        assert!(
            active(&pool, &f).await,
            "another browser's session is untouched"
        );
    }

    #[sqlx::test]
    async fn logout_ends_only_this_session(pool: PgPool) {
        let f = setup(&pool, "10001").await;
        let (other, _) = session::create(&pool, f.subject).await.unwrap();
        let other =
            crate::session::CookiePolicy::session(&crate::tests::test_issuer()).set_cookie(&other);
        let other = other
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1
            .to_owned();
        get(&pool, &[("id_token_hint", &hint_for(&f))], Some(&f.cookie)).await;
        assert!(!active(&pool, &f).await);
        assert!(session::find_active(&pool, &other).await.unwrap().is_some());
    }
}
