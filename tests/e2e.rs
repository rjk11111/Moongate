//! Milestone 1: an independent OIDC client library (`openidconnect`) completes
//! Authorization Code + PKCE against a real Moongate server over HTTP, using the
//! mock OutlandsID, and validates the ID token against the published JWKS.

use std::sync::Arc;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use moongate::client::{self, ClientId, ClientType, NewClient, RedirectUri};
use moongate::signing::SigningKey;
use moongate::upstream::Upstream;
use moongate::{AppState, Issuer, app};
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId as OidcClientId, ClientSecret, CsrfToken,
    IssuerUrl, Nonce, PkceCodeChallenge, RedirectUrl, TokenResponse,
};
use reqwest::header;
use sqlx::PgPool;
use url::Url;

const REDIRECT: &str = "http://127.0.0.1:9/callback";

struct Server {
    issuer: String,
    http: reqwest::Client,
}

async fn start(pool: PgPool) -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());

    let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
    let der = AsDer::as_der(&pair).unwrap();
    let pem = pem::encode(&pem::Pem::new("PRIVATE KEY", der.as_ref()));
    let key = SigningKey::from_pem(pem.as_bytes()).unwrap();
    key.activate(&pool).await.unwrap();

    let state = AppState::new(
        pool,
        Issuer::parse(&issuer).unwrap(),
        Upstream::Mock,
        Arc::new(key),
    );
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    Server { issuer, http }
}

async fn register(pool: &PgPool, id: &str, client_type: ClientType) -> Option<String> {
    let new = NewClient {
        id: ClientId::parse(id).unwrap(),
        display_name: format!("E2E {id}"),
        client_type,
        redirect_uris: vec![RedirectUri::parse(REDIRECT).unwrap()],
        post_logout_redirect_uris: vec![],
    };
    client::register(pool, &new)
        .await
        .unwrap()
        .map(|secret| secret.expose().to_owned())
}

fn cookie(response: &reqwest::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|c| {
            c.to_str()
                .ok()?
                .split(';')
                .next()?
                .strip_prefix(&format!("{name}="))
                .map(str::to_owned)
        })
}

fn location(response: &reqwest::Response) -> Url {
    assert_eq!(response.status(), reqwest::StatusCode::SEE_OTHER);
    Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap()
}

fn param(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.into_owned())
}

/// What a browser does: load the login page, then submit it. The form re-posts the
/// authorization parameters plus the CSRF token that the page set as a cookie.
async fn browser_login(server: &Server, auth_url: &Url) -> (Url, String) {
    let page = server.http.get(auth_url.as_str()).send().await.unwrap();
    assert_eq!(page.status(), reqwest::StatusCode::OK);
    let csrf = cookie(&page, "moongate_csrf").unwrap();
    assert!(
        page.text()
            .await
            .unwrap()
            .contains("Sign in with OutlandsID")
    );

    let mut form: Vec<(String, String)> = auth_url.query_pairs().into_owned().collect();
    form.extend([
        ("csrf".into(), csrf.clone()),
        ("email".into(), "player@moongate.localhost".into()),
        ("password".into(), "player".into()),
    ]);
    let response = server
        .http
        .post(format!("{}/login", server.issuer))
        .header(header::COOKIE, format!("moongate_csrf={csrf}"))
        .form(&form)
        .send()
        .await
        .unwrap();
    let session = cookie(&response, "moongate_session").unwrap();
    (location(&response), session)
}

#[sqlx::test]
async fn relying_party_completes_code_flow_with_pkce_and_sso(pool: PgPool) {
    let secret = register(&pool, "e2e-rp", ClientType::Confidential)
        .await
        .unwrap();
    register(&pool, "e2e-spa", ClientType::Public).await;
    let server = start(pool).await;

    // Discovery and JWKS, fetched and validated by the library.
    let metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new(server.issuer.clone()).unwrap(),
        &server.http,
    )
    .await
    .unwrap();
    let redirect = RedirectUrl::new(REDIRECT.into()).unwrap();

    // Confidential client: full login.
    let rp = CoreClient::from_provider_metadata(
        metadata.clone(),
        OidcClientId::new("e2e-rp".into()),
        Some(ClientSecret::new(secret)),
    )
    .set_redirect_uri(redirect.clone());
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, state, nonce) = rp
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(challenge)
        .url();

    let (callback, session) = browser_login(&server, &auth_url).await;
    assert!(callback.as_str().starts_with(REDIRECT));
    assert_eq!(
        param(&callback, "state").as_deref(),
        Some(state.secret().as_str())
    );
    assert_eq!(
        param(&callback, "iss").as_deref(),
        Some(server.issuer.as_str())
    );
    let code = param(&callback, "code").unwrap();

    let tokens = rp
        .exchange_code(AuthorizationCode::new(code.clone()))
        .unwrap()
        .set_pkce_verifier(verifier)
        .request_async(&server.http)
        .await
        .unwrap();
    let id_token = tokens.id_token().unwrap();
    let claims = id_token.claims(&rp.id_token_verifier(), &nonce).unwrap();
    let subject = claims.subject().as_str().to_owned();
    assert!(uuid_like(&subject), "sub must be an opaque UUID: {subject}");
    assert!(claims.auth_time().is_some());

    // The same token fails validation with a different nonce (replayed into another flow).
    assert!(
        id_token
            .claims(&rp.id_token_verifier(), &Nonce::new("other".into()))
            .is_err()
    );

    // The code is single use, also through the library.
    let (_, unused_verifier) = PkceCodeChallenge::new_random_sha256();
    let replay = rp
        .exchange_code(AuthorizationCode::new(code))
        .unwrap()
        .set_pkce_verifier(unused_verifier)
        .request_async(&server.http)
        .await;
    assert!(replay.is_err());

    // Public client: SSO via the existing Moongate session, no second login.
    let spa =
        CoreClient::from_provider_metadata(metadata, OidcClientId::new("e2e-spa".into()), None)
            .set_redirect_uri(redirect);
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, state, nonce) = spa
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(challenge)
        .url();
    let response = server
        .http
        .get(auth_url.as_str())
        .header(header::COOKIE, format!("moongate_session={session}"))
        .send()
        .await
        .unwrap();
    let callback = location(&response);
    assert_eq!(
        param(&callback, "state").as_deref(),
        Some(state.secret().as_str())
    );
    let tokens = spa
        .exchange_code(AuthorizationCode::new(param(&callback, "code").unwrap()))
        .unwrap()
        .set_pkce_verifier(verifier)
        .request_async(&server.http)
        .await
        .unwrap();
    let claims = tokens
        .id_token()
        .unwrap()
        .claims(&spa.id_token_verifier(), &nonce)
        .unwrap();
    // Same person, same subject, different audience.
    assert_eq!(claims.subject().as_str(), subject);
    assert_eq!(claims.audiences()[0].as_str(), "e2e-spa");
}

fn uuid_like(value: &str) -> bool {
    value.len() == 36 && value.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}
