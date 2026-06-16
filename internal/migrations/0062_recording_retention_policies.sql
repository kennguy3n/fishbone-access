-- 0062_recording_retention_policies: per-workspace recording retention override.
--
-- Cost-aware tiering for the 5,000-SME fleet: replay blobs are the heaviest
-- artifact the platform stores, and most tenants are dormant trials that must
-- cost ~nothing. The retention prune sweep (cmd/access-workflow-engine) ages a
-- recording's heavy blob out of object storage once it is older than the
-- workspace's retention window, while PRESERVING the light forensic row
-- (session_recordings) and the audit-chain event — so the evidence that a
-- session happened (and its integrity digest) survives, only the replayable
-- bytes are tiered.
--
-- This table holds the per-workspace OVERRIDE. When a workspace has no row, the
-- sweep falls back to the plan/global default from config
-- (ACCESS_RECORDING_RETENTION_DAYS), so the common case needs no row at all
-- (NoOps: sensible default, zero configuration). retention_days = 0 means
-- "retain indefinitely" (never prune) — an explicit opt-out for a workspace
-- with a long compliance hold.
--
-- It mirrors the GORM model models.RecordingRetentionPolicy (the SQLite test
-- source of truth). The workspace_id is the primary key: exactly one policy per
-- tenant.

CREATE TABLE IF NOT EXISTS recording_retention_policies (
    workspace_id   UUID PRIMARY KEY REFERENCES workspaces(id),
    retention_days INTEGER NOT NULL DEFAULT 0 CHECK (retention_days >= 0),
    updated_by     TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Row-Level Security: the read/write of a tenant's own retention policy happens
-- on the authenticated request path (RequireTenant pins app.workspace_id), so
-- the policy restricts a tenant to its OWN row. The prune sweep reads policies
-- UNSCOPED (no GUC) in the workflow engine, where the policy is permissive so a
-- single sweep can read every workspace's retention setting.
-- app_current_workspace_id() is defined in 0024.
ALTER TABLE recording_retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE recording_retention_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON recording_retention_policies;
CREATE POLICY tenant_isolation ON recording_retention_policies
    USING (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id())
    WITH CHECK (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id());
