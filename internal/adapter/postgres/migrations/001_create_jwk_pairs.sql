-- 001_create_jwk_pairs.sql
-- Creates the JWK key pairs table for storing tenant signing keys.

CREATE TABLE IF NOT EXISTS jwk_pairs (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    key_type    TEXT NOT NULL,
    algorithm   TEXT NOT NULL,
    key_use     TEXT NOT NULL DEFAULT 'sig',
    private_key BYTEA NOT NULL,
    public_key  BYTEA NOT NULL,
    active      BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_jwk_pairs_tenant_active ON jwk_pairs(tenant_id, active);
