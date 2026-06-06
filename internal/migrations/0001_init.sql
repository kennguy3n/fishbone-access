-- 0001_init: core ShieldNet Access schema.
--
-- Ten core tables for tenancy, connectors, the access-request lifecycle, and
-- the tamper-evident audit log. Every tenant-scoped table carries a
-- workspace_id (FK to workspaces) that maps 1:1 to an iam-core tenant_id.
-- This DDL mirrors the GORM models in internal/models.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS workspaces (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name               TEXT NOT NULL,
    iam_core_tenant_id TEXT NOT NULL UNIQUE,
    plan               TEXT NOT NULL DEFAULT 'base',
    data_residency     TEXT,
    default_locale     TEXT NOT NULL DEFAULT 'en',
    sso_connection_id  TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at         TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS teams (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    name         TEXT NOT NULL,
    description  TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_teams_workspace ON teams(workspace_id);

CREATE TABLE IF NOT EXISTS team_members (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id     UUID NOT NULL REFERENCES workspaces(id),
    team_id          UUID NOT NULL REFERENCES teams(id),
    iam_core_user_id TEXT NOT NULL,
    role             TEXT NOT NULL DEFAULT 'member',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_team_members_workspace ON team_members(workspace_id);
CREATE INDEX IF NOT EXISTS idx_team_members_team ON team_members(team_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(iam_core_user_id);

CREATE TABLE IF NOT EXISTS access_connectors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id),
    provider        TEXT NOT NULL,
    display_name    TEXT,
    status          TEXT NOT NULL DEFAULT 'pending',
    config          JSONB,
    secret_envelope TEXT,
    last_synced_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_access_connectors_workspace ON access_connectors(workspace_id);

CREATE TABLE IF NOT EXISTS access_jobs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    connector_id UUID REFERENCES access_connectors(id),
    type         TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'queued',
    attempts     INT NOT NULL DEFAULT 0,
    payload      JSONB,
    last_error   TEXT,
    run_after    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_access_jobs_workspace ON access_jobs(workspace_id);
CREATE INDEX IF NOT EXISTS idx_access_jobs_status_runafter ON access_jobs(status, run_after);

CREATE TABLE IF NOT EXISTS access_requests (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id  UUID NOT NULL REFERENCES workspaces(id),
    requester_id  TEXT NOT NULL,
    resource_ref  TEXT NOT NULL,
    role          TEXT,
    justification TEXT,
    state         TEXT NOT NULL DEFAULT 'requested',
    risk_level    TEXT,
    expires_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_access_requests_workspace ON access_requests(workspace_id);
CREATE INDEX IF NOT EXISTS idx_access_requests_requester ON access_requests(requester_id);

CREATE TABLE IF NOT EXISTS access_grants (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id     UUID NOT NULL REFERENCES workspaces(id),
    request_id       UUID REFERENCES access_requests(id),
    connector_id     UUID NOT NULL REFERENCES access_connectors(id),
    iam_core_user_id TEXT NOT NULL,
    resource_ref     TEXT NOT NULL,
    role             TEXT,
    state            TEXT NOT NULL DEFAULT 'active',
    granted_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_access_grants_workspace ON access_grants(workspace_id);
CREATE INDEX IF NOT EXISTS idx_access_grants_user ON access_grants(iam_core_user_id);

CREATE TABLE IF NOT EXISTS access_reviews (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    name         TEXT NOT NULL,
    state        TEXT NOT NULL DEFAULT 'draft',
    started_at   TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_access_reviews_workspace ON access_reviews(workspace_id);

CREATE TABLE IF NOT EXISTS policies (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    name         TEXT NOT NULL,
    state        TEXT NOT NULL DEFAULT 'draft',
    version      INT NOT NULL DEFAULT 1,
    definition   JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_policies_workspace ON policies(workspace_id);

CREATE TABLE IF NOT EXISTS audit_events (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    actor        TEXT,
    action       TEXT NOT NULL,
    target_ref   TEXT,
    metadata     JSONB,
    prev_hash    TEXT,
    chain_hash   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_audit_events_workspace ON audit_events(workspace_id);
