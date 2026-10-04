-- Fixed-window sign-in attempt counters, shared by all Moongate instances.
-- bucket is 'email:<sha256 of normalized email>' or 'ip:<address or /64 prefix>';
-- plaintext emails are never stored.
CREATE TABLE login_attempts (
    bucket       text        NOT NULL,
    window_start timestamptz NOT NULL,
    attempts     integer     NOT NULL CHECK (attempts >= 0),
    PRIMARY KEY (bucket, window_start)
);

CREATE INDEX login_attempts_window_start ON login_attempts (window_start);
