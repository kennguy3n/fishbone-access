-- Time-boxed, sponsor-approved contractor / external access grants.
--
-- Every contractor grant carries a MANDATORY expires_at (NOT NULL) and a named
-- internal sponsor, so external access is time-boxed and owned by construction.
-- The lifecycle is request → sponsor approval → provisioned active grant →
-- automatic expiry, where expiry runs the existing JML leaver kill switch to
-- deprovision the contractor everywhere (grant revoke, team removal, identity
-- disable, connector session/SCIM sweep). grant_id links the materialized
-- access_grants row created at approval so expiry/revocation tears down the real
-- entitlement. Tenant-scoped by workspace_id.
CREATE TABLE IF NOT EXISTS contractor_grants (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id       UUID NOT NULL REFERENCES workspaces(id),
    contractor_user_id TEXT NOT NULL,
    display_name       TEXT,
    connector_id       UUID NOT NULL REFERENCES access_connectors(id),
    resource_ref       TEXT NOT NULL,
    role               TEXT,
    sponsor_id         TEXT NOT NULL,
    requested_by       TEXT,
    justification      TEXT,
    -- pending_approval → active → expired | revoked ; or pending_approval → rejected.
    state              TEXT NOT NULL DEFAULT 'pending_approval',
    expires_at         TIMESTAMPTZ NOT NULL,
    approved_by        TEXT,
    approved_at        TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ,
    grant_id           UUID REFERENCES access_grants(id),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at         TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_contractor_grants_workspace ON contractor_grants(workspace_id);
CREATE INDEX IF NOT EXISTS idx_contractor_grants_user ON contractor_grants(workspace_id, contractor_user_id);
CREATE INDEX IF NOT EXISTS idx_contractor_grants_sponsor ON contractor_grants(workspace_id, sponsor_id);
-- The expiry sweep scans active grants past their expires_at; index that path.
CREATE INDEX IF NOT EXISTS idx_contractor_grants_expiry ON contractor_grants(state, expires_at) WHERE deleted_at IS NULL;
