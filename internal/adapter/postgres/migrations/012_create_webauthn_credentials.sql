CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id               TEXT PRIMARY KEY,
    subject          TEXT NOT NULL,
    tenant_id        TEXT NOT NULL,
    credential_id    BYTEA NOT NULL UNIQUE,
    public_key       BYTEA NOT NULL,
    aaguid           BYTEA,
    sign_count       INTEGER NOT NULL DEFAULT 0,
    attestation_type TEXT NOT NULL DEFAULT 'none',
    display_name     TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_webauthn_subject ON webauthn_credentials(tenant_id, subject);
