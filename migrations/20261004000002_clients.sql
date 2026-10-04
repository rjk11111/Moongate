-- Registered OIDC relying parties.
-- Confidential clients authenticate with a secret (client_secret_basic); only its
-- SHA-256 is stored. Public clients have no secret and must use PKCE.
CREATE TABLE clients (
    client_id      text        PRIMARY KEY CHECK (client_id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    display_name   text        NOT NULL CHECK (length(display_name) BETWEEN 1 AND 100),
    client_type    text        NOT NULL CHECK (client_type IN ('confidential', 'public')),
    secret_hash    text,
    allowed_scopes text[]      NOT NULL DEFAULT '{openid}' CHECK ('openid' = ANY (allowed_scopes)),
    enabled        boolean     NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CHECK ((client_type = 'confidential') = (secret_hash IS NOT NULL))
);

-- Exact registered redirect URIs. Matching is byte-for-byte string equality.
CREATE TABLE client_redirect_uris (
    client_id    text NOT NULL REFERENCES clients (client_id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    PRIMARY KEY (client_id, redirect_uri)
);
