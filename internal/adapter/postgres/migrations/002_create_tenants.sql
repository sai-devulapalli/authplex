-- 002_create_tenants.sql
-- Creates the tenants table for multi-tenancy support.

CREATE TABLE IF NOT EXISTS tenants (
    id              TEXT PRIMARY KEY,
    domain          TEXT NOT NULL UNIQUE,
    issuer          TEXT NOT NULL UNIQUE,
    algorithm       TEXT NOT NULL,
    active_key_id   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tenants_domain ON tenants(domain) WHERE deleted_at IS NULL;
