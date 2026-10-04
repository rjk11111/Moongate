-- Authorization codes. Only the SHA-256 of the code is stored. A code is bound
-- to its client, exact redirect URI, and (when present) PKCE S256 challenge, and
-- is consumed atomically by setting consumed_at (see /token).
CREATE TABLE authorization_codes (
    code_hash      text        PRIMARY KEY,
    client_id      text        NOT NULL REFERENCES clients (client_id) ON DELETE CASCADE,
    subject_id     uuid        NOT NULL REFERENCES subjects (id),
    redirect_uri   text        NOT NULL,
    scopes         text[]      NOT NULL CHECK ('openid' = ANY (scopes)),
    nonce          text,
    -- S256 only; the method is implied.
    code_challenge text        CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    auth_time      timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    consumed_at    timestamptz,
    CHECK (expires_at > created_at)
);
