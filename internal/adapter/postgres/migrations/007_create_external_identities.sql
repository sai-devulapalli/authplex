-- 007_create_external_identities.sql
-- Links external provider identities to internal subjects.

CREATE TABLE IF NOT EXISTS external_identities (
    id                TEXT PRIMARY KEY,
    provider_id       TEXT NOT NULL,
    external_subject  TEXT NOT NULL,
    internal_subject  TEXT NOT NULL,
    tenant_id         TEXT NOT NULL,
    email             TEXT,
    name              TEXT,
    profile_data      JSONB NOT NULL DEFAULT '{}',
    linked_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(provider_id, external_subject)
);

CREATE INDEX IF NOT EXISTS idx_external_identities_internal ON external_identities(tenant_id, internal_subject);
