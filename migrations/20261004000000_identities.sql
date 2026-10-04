-- A Moongate identity. `id` is the opaque OIDC `sub`.
CREATE TABLE subjects (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at  timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz
);

-- Binds a subject to its upstream identity (today only OutlandsID).
CREATE TABLE upstream_identities (
    subject_id            uuid        NOT NULL REFERENCES subjects (id),
    provider              text        NOT NULL CHECK (provider IN ('outlands')),
    provider_subject      text        NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    last_authenticated_at timestamptz,
    -- One upstream identity can never be bound to two subjects.
    PRIMARY KEY (provider, provider_subject),
    -- One subject can never hold two identities from the same provider.
    UNIQUE (subject_id, provider)
);
