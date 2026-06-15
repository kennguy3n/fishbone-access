-- Credential rotation policies.
--
-- A rotation policy is the per-workspace, per-target configuration that drives
-- automatic credential rotation for a privileged target. It is the control
-- plane for three independent behaviours that can be combined on one target:
--
--   * interval rotation   — rotate the sealed credential every N seconds. The
--                           scheduler in cmd/access-workflow-engine sweeps for
--                           due policies using next_rotation_at, so selecting
--                           the work is O(due rows) not O(targets) at 5k tenants.
--   * rotate-on-checkin    — rotate the moment a JIT lease against the target
--                           ends (expired or revoked), so a credential that was
--                           exposed to a live session never outlives it.
--   * dynamic credentials  — for database targets, mint a short-lived per-lease
--                           DB role instead of handing out the long-lived stored
--                           password, and drop it at checkin/expiry.
--
-- One policy row per target (uniqueness enforced below). The row also carries
-- the last-rotation outcome (last_status / last_error) so the console can show
-- an operator the health of automatic rotation without scanning the event log.
CREATE TABLE IF NOT EXISTS pam_rotation_policies (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id        UUID NOT NULL REFERENCES workspaces(id),
    target_id           UUID NOT NULL REFERENCES pam_targets(id),
    -- 'disabled' | 'interval'. rotate_on_checkin and dynamic_enabled are
    -- orthogonal booleans so a target can, e.g., rotate every 30 days AND on
    -- every checkin. mode governs only the time-interval sweep.
    mode                TEXT NOT NULL DEFAULT 'disabled',
    interval_seconds    BIGINT NOT NULL DEFAULT 0,
    rotate_on_checkin   BOOLEAN NOT NULL DEFAULT false,
    dynamic_enabled     BOOLEAN NOT NULL DEFAULT false,
    dynamic_ttl_seconds BIGINT NOT NULL DEFAULT 0,
    -- Master kill-switch for the policy independent of mode; an operator can
    -- pause all automatic rotation for a target without losing its schedule.
    enabled             BOOLEAN NOT NULL DEFAULT true,
    last_rotation_at    TIMESTAMPTZ,
    -- Pre-computed next-due instant for interval rotation. The scheduler scans a
    -- partial index on this column; NULL means "never due" (disabled/non-interval).
    next_rotation_at    TIMESTAMPTZ,
    last_status         TEXT,
    last_error          TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pam_rotation_policies_workspace ON pam_rotation_policies(workspace_id);
CREATE INDEX IF NOT EXISTS idx_pam_rotation_policies_deleted_at ON pam_rotation_policies(deleted_at);
-- Exactly one live policy per target.
CREATE UNIQUE INDEX IF NOT EXISTS uq_pam_rotation_policies_target ON pam_rotation_policies(workspace_id, target_id)
    WHERE deleted_at IS NULL;
-- The interval sweep selects only policies that are due. A partial index on the
-- enabled interval set keeps that selection cheap as the table grows across
-- 5000 tenants (most of which never enable rotation at all).
CREATE INDEX IF NOT EXISTS idx_pam_rotation_policies_due ON pam_rotation_policies(next_rotation_at)
    WHERE enabled = true AND mode = 'interval' AND next_rotation_at IS NOT NULL AND deleted_at IS NULL;

-- Tenant isolation backstop (mirrors internal/migrations/0024_row_level_security.sql):
-- the policy is permissive when the app.workspace_id GUC is unset so trusted
-- cross-tenant workers (the scheduler) and the migration runner keep working,
-- and restricts to the matching workspace on every authenticated request path.
ALTER TABLE pam_rotation_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_rotation_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON pam_rotation_policies;
CREATE POLICY tenant_isolation ON pam_rotation_policies
    USING (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id())
    WITH CHECK (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id());
