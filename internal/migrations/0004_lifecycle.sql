-- Session 1C: access-request lifecycle + policy engine schema.
--
-- Extends the 0001 core schema with the request state-history audit trail,
-- the columns the provisioning + JML services need on access_requests and
-- access_grants, the policy draft/simulate/promote columns, the access-review
-- per-grant decision table, and the orphan-account reconciliation table.
--
-- Every tenant-scoped table carries workspace_id so the RequireTenant
-- middleware + service layer can scope every query by workspace.

-- access_requests: provisioning target, owning connector, AI risk factors.
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS target_user_id TEXT;
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS connector_id UUID REFERENCES access_connectors(id);
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS risk_factors JSONB;
CREATE INDEX IF NOT EXISTS idx_access_requests_target_user ON access_requests(target_user_id);
CREATE INDEX IF NOT EXISTS idx_access_requests_connector ON access_requests(connector_id);

-- access_grants: revocation timestamp (rows are preserved for audit).
ALTER TABLE access_grants ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

-- audit_events: strictly-increasing per-workspace sequence used to find the
-- hash-chain head. The 0001 head lookup ordered by (created_at, id), but
-- several audit rows are appended inside one transaction and need not have
-- monotonically increasing created_at (TransitionInTx and its caller can pass
-- different timestamps, and tests use a fixed clock), so created_at ordering
-- could pick the wrong head and fork the chain. chain_seq is assigned as
-- prev_head.chain_seq + 1 under the per-workspace advisory lock, so it always
-- reflects true append order regardless of wall-clock values.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS chain_seq BIGINT NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_audit_events_chain_seq ON audit_events(workspace_id, chain_seq DESC);

-- policies: cached simulation impact + promotion timestamp.
ALTER TABLE policies ADD COLUMN IF NOT EXISTS draft_impact JSONB;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS promoted_at TIMESTAMPTZ;

-- access_reviews: campaigns start active (the 1C review lifecycle is
-- active → completed; there is no draft campaign state), so align the column
-- default with the only initial state the service produces. The 0001 default
-- of 'draft' was never exercised because StartCampaign always sets state
-- explicitly.
ALTER TABLE access_reviews ALTER COLUMN state SET DEFAULT 'active';

-- access_request_state_history: one immutable row per FSM transition.
CREATE TABLE IF NOT EXISTS access_request_state_history (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    request_id   UUID NOT NULL REFERENCES access_requests(id),
    from_state   TEXT NOT NULL DEFAULT '',
    to_state     TEXT NOT NULL,
    actor        TEXT,
    reason       TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_arsh_workspace ON access_request_state_history(workspace_id);
CREATE INDEX IF NOT EXISTS idx_arsh_request ON access_request_state_history(request_id);

-- access_review_items: per-grant certification decisions within a campaign.
CREATE TABLE IF NOT EXISTS access_review_items (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    review_id    UUID NOT NULL REFERENCES access_reviews(id),
    grant_id     UUID NOT NULL REFERENCES access_grants(id),
    decision     TEXT NOT NULL DEFAULT 'pending',
    decided_by   TEXT,
    decided_at   TIMESTAMPTZ,
    reason       TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_review_items_workspace ON access_review_items(workspace_id);
CREATE INDEX IF NOT EXISTS idx_review_items_review ON access_review_items(review_id);
CREATE INDEX IF NOT EXISTS idx_review_items_grant ON access_review_items(grant_id);

-- access_orphan_accounts: upstream accounts with no matching live grant.
CREATE TABLE IF NOT EXISTS access_orphan_accounts (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id     UUID NOT NULL REFERENCES workspaces(id),
    connector_id     UUID NOT NULL REFERENCES access_connectors(id),
    external_user_id TEXT NOT NULL,
    display_name     TEXT,
    disposition      TEXT NOT NULL DEFAULT 'pending',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_orphan_accounts_workspace ON access_orphan_accounts(workspace_id);
CREATE INDEX IF NOT EXISTS idx_orphan_accounts_connector ON access_orphan_accounts(connector_id);
