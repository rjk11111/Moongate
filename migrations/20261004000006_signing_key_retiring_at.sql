-- When a key stopped signing. It stays published in JWKS until the validation
-- window after this has passed, then maintenance marks it retired.
ALTER TABLE signing_keys ADD COLUMN retiring_at timestamptz;
UPDATE signing_keys SET retiring_at = now() WHERE status = 'retiring';
ALTER TABLE signing_keys
    ADD CONSTRAINT signing_keys_retiring_has_time CHECK (status <> 'retiring' OR retiring_at IS NOT NULL);
