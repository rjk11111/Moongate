-- Moongate SSO sessions. The browser holds an opaque 256-bit token; only its
-- SHA-256 is stored, so a database read does not yield usable session cookies.
CREATE TABLE sessions (
    token_hash       text        PRIMARY KEY,
    subject_id       uuid        NOT NULL REFERENCES subjects (id),
    authenticated_at timestamptz NOT NULL DEFAULT now(),
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_seen_at     timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    revoked_at       timestamptz,
    CHECK (expires_at > created_at)
);

CREATE INDEX sessions_subject_id ON sessions (subject_id);
