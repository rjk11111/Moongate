//! OIDC discovery (also served as RFC 8414 metadata) and JWKS.

use axum::Json;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::{AppState, Issuer, signing};

/// Advertises only what Moongate supports: code flow, PKCE S256, RS256.
/// `/authorize` and `/token` are listed because discovery requires them; they land next.
pub fn discovery_document(issuer: &Issuer) -> Value {
    json!({
        "issuer": issuer.as_str(),
        "authorization_endpoint": issuer.endpoint("/authorize"),
        "token_endpoint": issuer.endpoint("/token"),
        "jwks_uri": issuer.endpoint("/jwks.json"),
        "end_session_endpoint": issuer.endpoint("/logout"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": true,
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
        "claims_supported": ["iss", "sub", "aud", "exp", "iat", "auth_time", "nonce"],
    })
}

pub async fn discovery(State(state): State<AppState>) -> Json<Value> {
    Json(state.discovery.as_ref().clone())
}

pub async fn jwks(State(state): State<AppState>) -> Response {
    match signing::published_jwks(&state.pool).await {
        Ok(set) => ([(header::CACHE_CONTROL, "public, max-age=300")], Json(set)).into_response(),
        Err(error) => {
            tracing::warn!(%error, "jwks lookup failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use sqlx::PgPool;
    use tower::ServiceExt;

    use super::*;
    use crate::signing::tests::test_key;

    async fn get(pool: PgPool, uri: &str) -> (StatusCode, Option<String>, Value) {
        let response = crate::tests::test_app(pool)
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let cache = response
            .headers()
            .get(header::CACHE_CONTROL)
            .map(|v| v.to_str().unwrap().to_owned());
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (
            status,
            cache,
            serde_json::from_slice(&body).unwrap_or(Value::Null),
        )
    }

    #[sqlx::test]
    async fn discovery_is_served_at_both_well_known_paths(pool: PgPool) {
        let (status, _, oidc) = get(pool.clone(), "/.well-known/openid-configuration").await;
        assert_eq!(status, StatusCode::OK);
        let (_, _, oauth) = get(pool, "/.well-known/oauth-authorization-server").await;
        assert_eq!(oidc, oauth);
    }

    #[sqlx::test]
    async fn discovery_matches_issuer_and_supported_features(pool: PgPool) {
        let (_, _, doc) = get(pool, "/.well-known/openid-configuration").await;
        assert_eq!(doc["issuer"], "https://moongate.test");
        assert_eq!(
            doc["authorization_endpoint"],
            "https://moongate.test/authorize"
        );
        assert_eq!(doc["token_endpoint"], "https://moongate.test/token");
        assert_eq!(doc["jwks_uri"], "https://moongate.test/jwks.json");
        assert_eq!(doc["end_session_endpoint"], "https://moongate.test/logout");
        assert_eq!(doc["response_types_supported"], json!(["code"]));
        assert_eq!(doc["code_challenge_methods_supported"], json!(["S256"]));
        assert_eq!(
            doc["id_token_signing_alg_values_supported"],
            json!(["RS256"])
        );
    }

    #[sqlx::test]
    async fn jwks_endpoint_publishes_active_key(pool: PgPool) {
        let key = test_key();
        key.activate(&pool).await.unwrap();
        let (status, cache, body) = get(pool, "/jwks.json").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(cache.as_deref(), Some("public, max-age=300"));
        let keys = body["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kid"], key.kid());
        assert!(keys[0].get("d").is_none());
    }
}
