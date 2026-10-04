-- Security audit trail. Deliberately narrow columns: there is no free-form
-- metadata field, so requests, credentials, and tokens cannot accumulate here.
-- detail is a short code from a fixed set chosen in the application.
CREATE TABLE audit_events (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    event_type  text        NOT NULL CHECK (event_type ~ '^[a-z_]{1,64}$'),
    subject_id  uuid        REFERENCES subjects (id),
    -- No foreign key: history outlives deleted clients.
    client_id   text,
    source_ip   text,
    kid         text,
    detail      text        CHECK (detail ~ '^[a-z_]{1,64}$')
);

CREATE INDEX audit_events_occurred_at ON audit_events (occurred_at);
CREATE INDEX audit_events_subject_id ON audit_events (subject_id) WHERE subject_id IS NOT NULL;
