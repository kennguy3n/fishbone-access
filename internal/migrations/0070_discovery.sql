-- 0070_discovery: account/asset auto-discovery + auto-onboarding (Feature E).
--
-- Discovery finds hosts/databases and DB-internal accounts that are NOT yet
-- onboarded, classifies them (managed/unmanaged/orphan), and — opt-in, default
-- OFF — auto-creates managed PAM targets for matching assets. This is the
-- surface that lets a non-expert SME admin go from "signed up" to "protected"
-- without a network engineer, so it must be cheap across the 5,000-tenant fleet
-- (most dormant): every table is workspace-scoped, every sweep is set-based and
-- hibernation-gated, and the indexes below serve the inventory/facet reads and
-- the idempotent upsert keys directly.
--
-- These four tables mirror the GORM models in internal/models/discovery.go,
-- which are the source of truth for the SQLite test path (AutoMigrate). Each
-- carries a workspace_id and therefore JOINS the 0024 tenant-isolation RLS
-- regime — the RLS block at the foot of this file adds the same tenant_isolation
-- policy + FORCE ROW LEVEL SECURITY every other workspace-scoped table uses.

-- discovered_assets: one host/database a sweep found that is a candidate to
-- onboard. Upserted idempotently on (workspace_id, source, external_id) so
-- re-running a sweep updates last_seen_at/metadata in place, never duplicating.
CREATE TABLE IF NOT EXISTS discovered_assets (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id  UUID NOT NULL REFERENCES workspaces(id),
    source        TEXT NOT NULL,
    external_id   TEXT NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    protocol      TEXT NOT NULL DEFAULT '',
    address       TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'unmanaged',
    agent_id      UUID REFERENCES target_agents(id),
    connector_id  UUID REFERENCES access_connectors(id),
    target_id     UUID REFERENCES pam_targets(id),
    metadata      JSONB,
    policy_matched BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at    TIMESTAMPTZ
);

-- Idempotent upsert key: a re-scan resolves the same row by source identity.
-- PARTIAL on deleted_at IS NULL matches the soft-delete convention every other
-- unique index in this schema follows, so a soft-deleted row never blocks a
-- fresh insert for the same identity. The reconciler's ON CONFLICT names the
-- same predicate so Postgres infers this index as the upsert arbiter.
CREATE UNIQUE INDEX IF NOT EXISTS uq_discovered_assets_identity
    ON discovered_assets (workspace_id, source, external_id)
    WHERE deleted_at IS NULL;

-- Default inventory listing is a tenant's assets by status, freshest first;
-- this composite serves the faceted status filter + last_seen ordering.
CREATE INDEX IF NOT EXISTS idx_discovered_assets_ws_status
    ON discovered_assets (workspace_id, status, last_seen_at DESC);

-- discovered_accounts: one DB-internal role/user enumerated on an
-- already-registered PAM database target. Complements the connector-level
-- orphan reconciler (SaaS identities) by covering accounts INSIDE the database.
CREATE TABLE IF NOT EXISTS discovered_accounts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id  UUID NOT NULL REFERENCES workspaces(id),
    target_id     UUID NOT NULL REFERENCES pam_targets(id),
    username      TEXT NOT NULL,
    source        TEXT NOT NULL DEFAULT 'db_accounts',
    status        TEXT NOT NULL DEFAULT 'unmanaged',
    can_login     BOOLEAN NOT NULL DEFAULT FALSE,
    superuser     BOOLEAN NOT NULL DEFAULT FALSE,
    attributes    JSONB,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at    TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_discovered_accounts_identity
    ON discovered_accounts (workspace_id, target_id, username)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_discovered_accounts_ws_status
    ON discovered_accounts (workspace_id, status, last_seen_at DESC);

-- discovery_scans: durable record of each sweep run (source, trigger, outcome
-- counts, error). Powers the "recent scans" timeline; aggregate counts only,
-- never per-tenant Prometheus labels.
CREATE TABLE IF NOT EXISTS discovery_scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id),
    source          TEXT NOT NULL DEFAULT '',
    trigger         TEXT NOT NULL DEFAULT 'manual',
    status          TEXT NOT NULL DEFAULT 'running',
    actor           TEXT NOT NULL DEFAULT '',
    assets_found    INTEGER NOT NULL DEFAULT 0 CHECK (assets_found >= 0),
    assets_new      INTEGER NOT NULL DEFAULT 0 CHECK (assets_new >= 0),
    accounts_found  INTEGER NOT NULL DEFAULT 0 CHECK (accounts_found >= 0),
    onboarded_count INTEGER NOT NULL DEFAULT 0 CHECK (onboarded_count >= 0),
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    error           TEXT NOT NULL DEFAULT '',
    params          JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_discovery_scans_ws_started
    ON discovery_scans (workspace_id, started_at DESC);

-- auto_onboarding_policies: per-workspace, opt-in (default OFF) policy that
-- turns matching unmanaged assets into managed PAM targets on each sweep. The
-- onboarding credential is AES-256-GCM sealed (envelope/key_version), never
-- stored in plaintext; the safety boundary is enforced in the service layer
-- (require_lease, RBAC, audit). Exactly one row per workspace.
CREATE TABLE IF NOT EXISTS auto_onboarding_policies (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id        UUID NOT NULL REFERENCES workspaces(id),
    enabled             BOOLEAN NOT NULL DEFAULT FALSE,
    create_targets      BOOLEAN NOT NULL DEFAULT FALSE,
    require_lease       BOOLEAN NOT NULL DEFAULT TRUE,
    rules               JSONB,
    default_agent_id    UUID REFERENCES target_agents(id),
    credential_username TEXT NOT NULL DEFAULT '',
    credential_envelope TEXT NOT NULL DEFAULT '',
    credential_key_ver  INTEGER NOT NULL DEFAULT 0,
    updated_by          TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_auto_onboarding_policy_ws
    ON auto_onboarding_policies (workspace_id)
    WHERE deleted_at IS NULL;

-- Row-Level Security: all four tables carry a workspace_id, so they join the
-- 0024 tenant-isolation regime. On the authenticated request path RequireTenant
-- pins app.workspace_id and the policy restricts a tenant to its OWN rows — a
-- privacy backstop behind the explicit `WHERE workspace_id = ?`. The discovery
-- sweep + reconciler run UNSCOPED (no GUC) in the workflow engine, so the policy
-- is permissive for them and one set-based sweep may upsert rows for every
-- workspace. app_current_workspace_id() is defined in 0024.
ALTER TABLE discovered_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovered_assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON discovered_assets;
CREATE POLICY tenant_isolation ON discovered_assets
    USING (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id())
    WITH CHECK (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id());

ALTER TABLE discovered_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovered_accounts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON discovered_accounts;
CREATE POLICY tenant_isolation ON discovered_accounts
    USING (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id())
    WITH CHECK (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id());

ALTER TABLE discovery_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_scans FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON discovery_scans;
CREATE POLICY tenant_isolation ON discovery_scans
    USING (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id())
    WITH CHECK (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id());

ALTER TABLE auto_onboarding_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE auto_onboarding_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON auto_onboarding_policies;
CREATE POLICY tenant_isolation ON auto_onboarding_policies
    USING (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id())
    WITH CHECK (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id());
