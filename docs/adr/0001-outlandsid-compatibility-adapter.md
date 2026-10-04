# ADR 0001: OutlandsID compatibility adapter trusts the upstream JWT via TLS

- Status: accepted
- Date: 2026-10-04

## Context

Moongate must federate a real OutlandsID. We can't see what the Outlands team runs internally,
and the only login interface we can observe is Portal's:

```
POST https://portal.uooutlands.com/api/user/login
Content-Type: application/json
{"email": "...", "password": "..."}
```

On success, the response includes a `jwt`. The JWT header is `{"alg":"HS256","typ":"JWT"}` with
no `kid`, so it's signed with a symmetric secret that only Outlands holds. Its observed claims
are `outlandsid` (a numeric string), `emailaddress`, `role`, `purpose` (`Portal`), `exp`,
`iss` = `aud` = `https://login.uooutlands.com`, and `jti`. There is no `iat` or `nbf`.

Failed logins observed on 2026-10-04 return ASP.NET Core `application/problem+json` bodies:
- `401` (`title: "Unauthorized"`) for a well-formed email with the wrong password
- `400` (`title: "Bad Request"`) for malformed input, such as an email without `@`

Moongate's rules say a JWT is never trusted without signature verification, but nobody except
Outlands can verify an HS256 token.

## Decision

1. Moongate shows its own "Sign in with OutlandsID" form and posts the credentials to the
   configured Portal login URL (`OUTLANDS_LOGIN_URL`, https only, from config, never from request
   input). The password is held only for that request and is never stored or logged.
2. The JWT is trusted **because of the channel, not its signature**. Moongate made the TLS
   connection itself, validated the certificate against the web PKI, did not follow redirects,
   and read the token from that response. This is the same reasoning as OIDC Core §3.1.3.7,
   which lets a client skip signature checks for ID tokens received directly from the token
   endpoint over TLS.
3. An Outlands JWT from **any other source** (browser, relying party, form field, header) is
   never accepted. The adapter exposes no way to submit one.
4. The claims are still checked, to catch upstream changes rather than forgeries:
   - header `alg` is exactly `HS256`
   - `iss` and `aud` are `https://login.uooutlands.com`
   - `exp` is in the future
   - `purpose` is `Portal`
   - `outlandsid` is a canonical positive integer
   - email and role are present
5. Only the `jwt` field of the response body is used. Identity values come from its claims, and
   other response fields are ignored.
6. Status mapping: `200` → validate the token; `401` (observed for wrong credentials), `400`
   (observed for malformed input), and `403` → credentials rejected;
   anything else, a redirect, a timeout, an oversized body, or a token that fails the checks →
   upstream unavailable. Users see a single generic message for rejected credentials.
7. The raw token is dropped as soon as the `UpstreamIdentity` has been extracted.

## Alternatives considered

- **Verify the HS256 signature.** Impossible without Outlands' secret, and holding that secret
  would let Moongate forge OutlandsID tokens.
- **Accept Portal JWTs presented by the browser** (the user logs into Portal and hands the token
  to Moongate). Rejected: Moongate could not verify the token, so anyone with a stolen or forged
  token string could become that user.
- **Confirm the token by calling an authenticated Portal API with it.** This proves Outlands
  accepts the token, but adds a second dependency and still relies on TLS. It may be worth
  adding as a cross-check if Portal exposes a stable "who am I" endpoint.
- **Wait for a redirect-based Outlands login.** That is preferred, and it's recommended to the
  Outlands team in `docs/architecture.md`, but it isn't available and is outside our control.

## Security implications

- Moongate handles OutlandsID passwords in memory. Rate limiting on `/login` becomes mandatory
  before production, because Moongate is now a password oracle against Portal.
- Compromise of Moongate's outbound TLS (a mis-issued certificate, or a compromised resolver
  combined with one) lets an attacker impersonate any OutlandsID. The web PKI is the trust anchor.
- Outlands may see all logins coming from Moongate's IP and rate-limit or block it. That is an
  operational risk, not a security one.
- `purpose = Portal` means Moongate holds a Portal-scoped token for a moment. It is never stored,
  forwarded, or used to call Portal APIs.

## Consequences

- Milestone 2 can ship without Outlands' cooperation.
- Replacing this adapter with a redirect-based flow later only touches `upstream::Upstream`.
- Revisit this decision if Outlands publishes asymmetric keys (then verify signatures) or offers
  a redirect flow (then drop password handling entirely).
