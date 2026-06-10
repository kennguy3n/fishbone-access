-- WS2: sponsor-approved extensions of a contractor grant's time box.
--
-- A contractor engagement is prolonged ONLY through an explicit, sponsor-
-- approved, audited extension — never by silently editing expires_at. Each
-- extension is its own immutable row (previous → new expiry, approver, reason)
-- so the complete time-box history of an external engagement is reconstructable:
-- an auditor sees exactly when, by whom, and why access was prolonged, not just
-- the latest expiry. The contractor_grants.expires_at column is advanced in the
-- same transaction that inserts the extension. Tenant-scoped by workspace_id.
CREATE TABLE IF NOT EXISTS contractor_grant_extensions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id        UUID NOT NULL REFERENCES workspaces(id),
    contractor_grant_id UUID NOT NULL REFERENCES contractor_grants(id),
    previous_expires_at TIMESTAMPTZ NOT NULL,
    new_expires_at      TIMESTAMPTZ NOT NULL,
    approved_by         TEXT NOT NULL,
    reason              TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_contractor_grant_extensions_workspace ON contractor_grant_extensions(workspace_id);
CREATE INDEX IF NOT EXISTS idx_contractor_grant_extensions_grant ON contractor_grant_extensions(contractor_grant_id);
