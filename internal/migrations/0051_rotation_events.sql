-- Credential rotation history.
--
-- One row per rotation attempt (manual "rotate now", scheduled interval sweep,
-- or rotate-on-checkin), recording the trigger, outcome and — on failure — the
-- error, so the console can render a per-target rotation timeline and surface
-- the health of the last attempt. This is the queryable projection; the
-- authoritative tamper-evident record is still the per-workspace audit hash
-- chain (audit_events), which every successful rotation also appends to
-- atomically via the vault's RotateSecret transaction.
CREATE TABLE IF NOT EXISTS pam_rotation_events (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    target_id    UUID NOT NULL REFERENCES pam_targets(id),
    policy_id    UUID REFERENCES pam_rotation_policies(id),
    -- 'manual' | 'scheduled' | 'checkin'
    trigger      TEXT NOT NULL,
    -- 'success' | 'failed'
    status       TEXT NOT NULL,
    protocol     TEXT,
    actor        TEXT,
    -- The lease whose checkin triggered the rotation (checkin trigger only).
    lease_id     UUID REFERENCES pam_leases(id),
    key_version  INTEGER NOT NULL DEFAULT 0,
    detail       TEXT,
    error        TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pam_rotation_events_workspace ON pam_rotation_events(workspace_id);
-- The per-target history view reads newest-first; a composite index serves it
-- without a sort.
CREATE INDEX IF NOT EXISTS idx_pam_rotation_events_target ON pam_rotation_events(target_id, created_at DESC);

ALTER TABLE pam_rotation_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_rotation_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON pam_rotation_events;
CREATE POLICY tenant_isolation ON pam_rotation_events
    USING (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id())
    WITH CHECK (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id());
