-- Dynamic (ephemeral) database credentials.
--
-- Instead of handing a long-lived stored password to a database session, a
-- target with dynamic credentials enabled mints a short-lived DB role per JIT
-- lease (scoped to that lease) and drops it at checkin/expiry — the database
-- analogue of the SSH CA's ephemeral per-session certificate
-- (internal/gateway/ssh_ca.go). This table tracks the lifecycle of each minted
-- role so the reaper can drop it on the upstream when the bound lease ends or
-- the credential's own TTL lapses. The role's PASSWORD is returned to the
-- caller once at mint time and never persisted (same posture as connect tokens).
CREATE TABLE IF NOT EXISTS pam_dynamic_credentials (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    target_id    UUID NOT NULL REFERENCES pam_targets(id),
    -- The lease that owns this credential; when it stops being live the reaper
    -- drops the role. Nullable for a future non-lease mint path.
    lease_id     UUID REFERENCES pam_leases(id),
    protocol     TEXT NOT NULL,
    -- The ephemeral role/user name created on the upstream database.
    db_username  TEXT NOT NULL,
    -- 'active' | 'revoked' | 'expired' | 'failed'. A row leaves 'active' only
    -- once the role has actually been dropped upstream (or the drop is no longer
    -- possible), so the reaper's active-set scan is authoritative.
    state        TEXT NOT NULL DEFAULT 'active',
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    last_error   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pam_dynamic_credentials_workspace ON pam_dynamic_credentials(workspace_id);
CREATE INDEX IF NOT EXISTS idx_pam_dynamic_credentials_lease ON pam_dynamic_credentials(lease_id);
CREATE INDEX IF NOT EXISTS idx_pam_dynamic_credentials_deleted_at ON pam_dynamic_credentials(deleted_at);
-- The reaper scans the live set for credentials whose lease ended or TTL
-- lapsed; a partial index on the active set keeps that sweep cheap at scale.
CREATE INDEX IF NOT EXISTS idx_pam_dynamic_credentials_active ON pam_dynamic_credentials(expires_at)
    WHERE state = 'active' AND deleted_at IS NULL;

ALTER TABLE pam_dynamic_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_dynamic_credentials FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON pam_dynamic_credentials;
CREATE POLICY tenant_isolation ON pam_dynamic_credentials
    USING (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id())
    WITH CHECK (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id());
