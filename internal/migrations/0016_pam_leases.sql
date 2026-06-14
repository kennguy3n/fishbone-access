-- JIT lease state machine + live session control.
--
-- pam_leases is the just-in-time access grant: an operator requests a lease
-- against a pam_targets row, an approver grants a time-boxed window, and the
-- connect-token broker turns the lease "active" the moment a session is opened
-- against it. The state (requested → approved → active → expired → revoked) is
-- DERIVED from the (granted_at, activated_at, expires_at, revoked_at) tuple in
-- the service layer rather than stored, mirroring the lifecycle access_grants
-- convention, so the row's timestamps are the single source of truth and the
-- database can never disagree with the machine state.
--
-- Every lease transition (request, approve, revoke, expire, activate) appends
-- to the shared audit_events hash chain (internal/services/lifecycle/audit.go)
-- for tamper evidence; this table holds the queryable projection.
CREATE TABLE IF NOT EXISTS pam_leases (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id          UUID NOT NULL REFERENCES workspaces(id),
    target_id             UUID NOT NULL REFERENCES pam_targets(id),
    subject               TEXT NOT NULL,
    requested_by          TEXT NOT NULL,
    reason                TEXT,
    request_id            UUID REFERENCES access_requests(id),
    approved_by           TEXT,
    requested_ttl_seconds INTEGER NOT NULL DEFAULT 0,
    risk_level            TEXT,
    risk_factors          JSONB,
    risk_reason           TEXT,
    risk_degraded         BOOLEAN NOT NULL DEFAULT false,
    granted_at            TIMESTAMPTZ,
    activated_at          TIMESTAMPTZ,
    expires_at            TIMESTAMPTZ,
    expired_at            TIMESTAMPTZ,
    revoked_at            TIMESTAMPTZ,
    revoke_reason         TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at            TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pam_leases_workspace ON pam_leases(workspace_id);
CREATE INDEX IF NOT EXISTS idx_pam_leases_target ON pam_leases(target_id);
CREATE INDEX IF NOT EXISTS idx_pam_leases_subject ON pam_leases(subject);
CREATE INDEX IF NOT EXISTS idx_pam_leases_request ON pam_leases(request_id);
CREATE INDEX IF NOT EXISTS idx_pam_leases_deleted_at ON pam_leases(deleted_at);
-- The expiry sweep scans for live leases whose TTL has lapsed; a partial index
-- on the granted-but-not-revoked set keeps that sweep cheap as the table grows
-- across 5000 tenants.
CREATE INDEX IF NOT EXISTS idx_pam_leases_expiry_sweep ON pam_leases(expires_at)
    WHERE granted_at IS NOT NULL AND revoked_at IS NULL AND expired_at IS NULL AND deleted_at IS NULL;

-- Bind the one-shot connect token and the proxied session to the lease that
-- authorized them so the broker can re-validate liveness at mint/redeem and the
-- expiry/revoke sweep can find sessions to tear down. Nullable to preserve the
-- legacy direct-mint path (a token gated solely by the target's MFA flag).
ALTER TABLE pam_connect_tokens ADD COLUMN IF NOT EXISTS lease_id UUID REFERENCES pam_leases(id);
CREATE INDEX IF NOT EXISTS idx_pam_connect_tokens_lease ON pam_connect_tokens(lease_id);

ALTER TABLE pam_sessions ADD COLUMN IF NOT EXISTS lease_id UUID REFERENCES pam_leases(id);
CREATE INDEX IF NOT EXISTS idx_pam_sessions_lease ON pam_sessions(lease_id);

-- Live session control: the operator-driven soft-pause flag and its audit
-- stamps. The gateway reconciler loop reconciles this durable intent against
-- the in-process pause gate that holds the operator→upstream byte path.
ALTER TABLE pam_sessions ADD COLUMN IF NOT EXISTS paused BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE pam_sessions ADD COLUMN IF NOT EXISTS paused_by TEXT;
ALTER TABLE pam_sessions ADD COLUMN IF NOT EXISTS paused_at TIMESTAMPTZ;
-- The reconciler polls for sessions it hosts that are still active; a partial
-- index on the active set keeps that poll cheap.
CREATE INDEX IF NOT EXISTS idx_pam_sessions_active ON pam_sessions(workspace_id, state)
    WHERE state = 'active' AND deleted_at IS NULL;
