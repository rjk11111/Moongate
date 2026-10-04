-- Public half of every signing key Moongate has used. Private keys never live here.
-- `kid` is the RFC 7638 JWK thumbprint, so a kid always identifies exactly one key.
-- Lifecycle: active -> retiring (still published in JWKS) -> retired (no longer published).
CREATE TABLE signing_keys (
    kid          text        PRIMARY KEY,
    algorithm    text        NOT NULL CHECK (algorithm = 'RS256'),
    public_jwk   jsonb       NOT NULL,
    status       text        NOT NULL CHECK (status IN ('active', 'retiring', 'retired')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz NOT NULL DEFAULT now(),
    retired_at   timestamptz
);

-- At most one key signs new tokens.
CREATE UNIQUE INDEX signing_keys_single_active ON signing_keys ((true)) WHERE status = 'active';
