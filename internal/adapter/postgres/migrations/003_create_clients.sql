-- 003_create_clients.sql
-- OAuth 2.0 client registry.

CREATE TABLE IF NOT EXISTS clients (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    client_name         TEXT NOT NULL,
    client_type         TEXT NOT NULL CHECK (client_type IN ('public', 'confidential')),
    secret_hash         BYTEA,
    redirect_uris       TEXT[] NOT NULL DEFAULT '{}',
    allowed_scopes      TEXT[] NOT NULL DEFAULT '{}',
    allowed_grant_types TEXT[] NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_clients_tenant ON clients(tenant_id) WHERE deleted_at IS NULL;
