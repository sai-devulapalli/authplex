-- 008_create_mfa.sql
-- MFA enrollments and challenges.

CREATE TABLE IF NOT EXISTS totp_enrollments (
    id          TEXT PRIMARY KEY,
    subject     TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    secret      BYTEA NOT NULL,
    confirmed   BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(tenant_id, subject)
);

CREATE TABLE IF NOT EXISTS mfa_challenges (
    id                      TEXT PRIMARY KEY,
    subject                 TEXT NOT NULL,
    tenant_id               TEXT NOT NULL,
    methods                 TEXT[] NOT NULL DEFAULT '{}',
    expires_at              TIMESTAMPTZ NOT NULL,
    verified                BOOLEAN NOT NULL DEFAULT false,
    original_client_id      TEXT,
    original_redirect_uri   TEXT,
    original_scope          TEXT,
    original_state          TEXT,
    code_challenge          TEXT,
    code_challenge_method   TEXT,
    nonce                   TEXT
);

CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires ON mfa_challenges(expires_at);
