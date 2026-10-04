# Moongate

**Single sign-on for the Ultima Online Outlands web ecosystem, built on OpenID Connect.**

Moongate lets one OutlandsID sign in to Outlands Portal, Forums (XenForo), Wiki
(MediaWiki), and future services. It's a small, standards-based OpenID Connect provider written
in Rust. Each application keeps its own users, permissions, content, and sessions. Moongate only
answers one question for them: *who is this player, according to OutlandsID?*

> **Status: proof of concept.** Moongate was built outside the Outlands team as a working
> proposal. It has never been deployed against production Outlands services. Read
> [Limitations](#limitations) before considering it for production.

```
           OutlandsID (login.uooutlands.com)      who is this player?
                        |
                     Moongate                     how can a service trust that?
                   /    |    \
             Portal   Forums   Wiki               what may this player do here?
```

Read more:

- [`docs/architecture.md`](docs/architecture.md): trust model, observed OutlandsID behaviour, data
  model, integration plan, rollout phases, and **recommendations to the Outlands team**
- [`docs/adr/0001-outlandsid-compatibility-adapter.md`](docs/adr/0001-outlandsid-compatibility-adapter.md):
  how Moongate authenticates against today's OutlandsID and why that's acceptable for now

## What works

| Area | Behaviour |
|---|---|
| Protocol | OpenID Connect Authorization Code flow with PKCE (`S256` only). No implicit flow, password grant, or custom grants. |
| Endpoints | Discovery, JWKS, `/authorize` (GET and POST), `/token`, `/logout` (RP-initiated), health checks. |
| Identity | Every player gets an opaque, immutable UUID `sub`. Never an email or the raw OutlandsID. The same player gets the same `sub` at every application. |
| ID tokens | RS256, 5-minute lifetime. Claims: `iss sub aud exp iat auth_time nonce` and nothing else. |
| SSO | Server-side Moongate session (12 h) in a `__Host-` cookie. Signing in at one application signs you in at the next. `prompt=none\|login` and `max_age` are supported. |
| Clients | Registered with exact redirect URIs (no prefix or wildcard matching). Confidential clients use `client_secret_basic`; public clients use PKCE. |
| OutlandsID | A mock with fixed users for development, and a compatibility adapter that signs in through Portal's existing login API ([ADR 0001](docs/adr/0001-outlandsid-compatibility-adapter.md)). |
| Hardening | Sign-in rate limiting (per email and per IP), login and logout CSRF protection, signing-key rotation with automatic retirement, cleanup of expired state, and an audit trail in the database. |

An end-to-end test (`tests/e2e.rs`) runs the [`openidconnect`](https://crates.io/crates/openidconnect)
crate, an independent OIDC client library, against a live Moongate server. It covers discovery,
login, code exchange, ID token validation, and SSO for a second application.

## Quick start (local, mock OutlandsID)

Requirements: Rust stable (pinned by `rust-toolchain.toml`), PostgreSQL 14 or later (developed
on 17), `openssl`, and Docker or Podman for the database.

```sh
# 1. Database
podman run -d --name moongate-postgres -p 127.0.0.1:5434:5432 \
  -e POSTGRES_USER=moongate -e POSTGRES_PASSWORD=moongate-dev -e POSTGRES_DB=moongate \
  docker.io/library/postgres:17-alpine

# 2. Configuration and a development signing key
cp .env.example .env
mkdir -p secrets
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out secrets/signing-key.pem

# 3. Load the configuration into your shell (Moongate reads only environment variables)
set -a; . ./.env; set +a

# 4. Register a test application, then start Moongate (migrations run automatically)
cargo run -- register-client --id demo-rp --name "Demo RP" --type confidential \
  --redirect-uri http://rp.localhost:9000/callback \
  --post-logout-redirect-uri http://rp.localhost:9000/
cargo run
```

`register-client` prints the client secret **once**; store it. Moongate is now at
`http://moongate.localhost:8090`. Point any OIDC client library at
`http://moongate.localhost:8090/.well-known/openid-configuration` and sign in with a mock user:

| Email | Password | Role |
|---|---|---|
| `player@moongate.localhost` | `player` | `player` |
| `staff@moongate.localhost` | `staff` | `staff` |

`*.localhost` names resolve to your own machine in modern browsers. The mock is refused at
startup unless `MOONGATE_BASE_URL` is a localhost address, so it can't be switched on by
accident in a real deployment.

## Configuration

All configuration comes from environment variables. Invalid values stop startup; there are no
insecure fallbacks.

| Variable | Required | Meaning |
|---|---|---|
| `DATABASE_URL` | yes | PostgreSQL connection string. |
| `MOONGATE_BIND` | yes | Listen address, e.g. `127.0.0.1:8090`. |
| `MOONGATE_BASE_URL` | yes | Public base URL and OIDC issuer. Must be https (http only for localhost), canonical, with no trailing `/`. |
| `MOONGATE_SIGNING_KEY_FILE` | yes | RSA private key (PEM, at least 2048 bits). Never commit it. |
| `MOONGATE_UPSTREAM` | yes | `mock` (localhost only) or `outlands`. |
| `OUTLANDS_LOGIN_URL` | with `outlands` | Portal login API, e.g. `https://portal.uooutlands.com/api/user/login`. https only. |
| `MOONGATE_CLIENT_IP_HEADER` | no | Header carrying the real client IP behind a proxy (e.g. `CF-Connecting-IP`). Set it **only** if every request passes through a proxy that overwrites that header; otherwise clients can spoof it. If unset, the TCP peer address is used. |
| `RUST_LOG` | no | Log filter, default `info`. Logs never contain passwords, tokens, codes, session IDs, or secrets. |

**Key rotation:** replace the key file and restart. The new key signs from then on. The old key
stays in JWKS for an hour so tokens it signed still validate, then it's retired automatically.

## Integrating an application

1. Register it with `moongate register-client`. Pass `--redirect-uri` once for each exact callback
   URL, and optionally `--post-logout-redirect-uri`.
2. Configure the application's OIDC client with the discovery URL, the client ID, and the secret.
   Request `scope=openid`, and use PKCE.
3. Key the application's users by the ID token's `sub` together with `iss`. Don't key them by email.

Existing XenForo and MediaWiki accounts should be linked inside each application by proving
ownership (signing in locally, then connecting Moongate), never by matching email addresses.
[`docs/architecture.md`](docs/architecture.md) describes the intended XenForo and MediaWiki
integrations and the staged Portal migration.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features     # needs DATABASE_URL; each test gets its own throwaway database
```

Tests never contact real Outlands services; OutlandsID is replaced by a mock or a fake Portal.
Database schema changes are migrations in `migrations/`.

Code map:

| Path | Purpose |
|---|---|
| `src/authorize.rs` | `/authorize`, login form, SSO, authorization codes |
| `src/token.rs` | `/token`: client authentication, code redemption, PKCE, ID tokens |
| `src/logout.rs` | `/logout` |
| `src/oidc.rs` | Discovery and JWKS |
| `src/signing.rs` | Signing keys and rotation |
| `src/session.rs` | Moongate sessions and cookies |
| `src/client.rs` | Client registry |
| `src/identity.rs` | OutlandsID to Moongate subject mapping |
| `src/upstream.rs`, `src/upstream/outlands.rs` | OutlandsID boundary: mock and Portal adapter |
| `src/ratelimit.rs` | Sign-in rate limiting |
| `src/audit.rs` | Audit trail |
| `src/maintenance.rs` | Periodic cleanup and key retirement |

## Limitations

These are deliberate scope cuts or open questions, not oversights:

- **Moongate handles OutlandsID passwords.** Outlands has no redirect-based login that Moongate
  can use, so the adapter posts credentials to Portal's login API and trusts the returned token
  because of the TLS connection, not its signature (it's HS256). See
  [ADR 0001](docs/adr/0001-outlandsid-compatibility-adapter.md) and the recommendations in
  [`docs/architecture.md`](docs/architecture.md); a redirect-based OutlandsID login would remove
  this entirely.
- **Untested against production.** The Portal adapter is tested only against a fake. What happens
  when an account must first accept Portal's privacy policy (`forceAcceptPrivacyPolicy`) is
  unknown; Moongate currently reports "OutlandsID is unavailable" in that case.
- **Not implemented:** `/userinfo`, refresh tokens, a consent screen (all clients are assumed to
  be first-party Outlands services), an admin UI (clients are managed by CLI), account-linking
  tooling, and the XenForo and MediaWiki adapters. The token response includes the access token
  that OAuth requires, but nothing accepts it yet.
- **Operations:** there's no audit-log retention policy, and audit writes are best effort. Rate
  limiting uses fixed windows. TLS uses ring while JWT signing uses aws-lc, so there are two
  crypto libraries.
