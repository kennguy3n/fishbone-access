-- WS6: certification campaigns + compliance evidence.
--
-- The compliance EVIDENCE stream is deliberately NOT a new table: it is a
-- typed projection over the existing per-workspace audit hash chain
-- (audit_events), so control evidence is captured as a side effect of normal
-- operation and inherits the chain's tamper-evidence (prev_hash → chain_hash)
-- rather than duplicating a parallel, separately-forgeable log.
--
-- Certification campaigns are the "full" expansion of the 1C access-review
-- primitive: a scoped (resource / role / connector), reviewer-assigned,
-- due-dated review whose per-grant decisions are STAGED and only applied
-- (revoked) at close — so the destructive teardown is preview-able first, the
-- same test-before-effect guardrail the policy promote path enforces. Every
-- lifecycle transition and decision appends to the workspace audit chain, so a
-- campaign produces compliance evidence automatically.
--
-- Every tenant-scoped table carries workspace_id so the RequireTenant
-- middleware + service layer can scope every query by workspace.

-- certification_campaigns: one scoped certification campaign.
--   state: running → closed (closed applies the staged revocations).
--   scope_*: optional filters narrowing which live grants are enumerated.
--   reviewers: JSON array of iam-core user ids assigned to the worklist.
--   framework: optional compliance framework tag (e.g. SOC2 / ISO27001 / PCI-DSS).
--   due_at: SLA deadline; a running campaign past due is "overdue".
CREATE TABLE IF NOT EXISTS certification_campaigns (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id       UUID NOT NULL REFERENCES workspaces(id),
    name               TEXT NOT NULL,
    state              TEXT NOT NULL DEFAULT 'running',
    framework          TEXT,
    scope_resource     TEXT,
    scope_role         TEXT,
    scope_connector_id UUID REFERENCES access_connectors(id),
    reviewers          JSONB,
    due_at             TIMESTAMPTZ,
    started_at         TIMESTAMPTZ,
    closed_at          TIMESTAMPTZ,
    overdue_at         TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at         TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_cert_campaigns_workspace ON certification_campaigns(workspace_id);
CREATE INDEX IF NOT EXISTS idx_cert_campaigns_state ON certification_campaigns(workspace_id, state);

-- certification_items: one per-grant certification decision within a campaign.
--   decision: pending → certify | revoke | escalate (terminal once certify/revoke).
--   revoked_at: stamped when the staged revoke is actually applied at close,
--   so re-closing is idempotent and the teardown is auditable.
CREATE TABLE IF NOT EXISTS certification_items (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    campaign_id  UUID NOT NULL REFERENCES certification_campaigns(id),
    grant_id     UUID NOT NULL REFERENCES access_grants(id),
    reviewer     TEXT,
    decision     TEXT NOT NULL DEFAULT 'pending',
    decided_by   TEXT,
    decided_at   TIMESTAMPTZ,
    reason       TEXT,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_cert_items_workspace ON certification_items(workspace_id);
CREATE INDEX IF NOT EXISTS idx_cert_items_campaign ON certification_items(campaign_id);
CREATE INDEX IF NOT EXISTS idx_cert_items_grant ON certification_items(grant_id);
-- A grant appears at most once per campaign (idempotent enumeration / re-runs).
CREATE UNIQUE INDEX IF NOT EXISTS uq_cert_items_campaign_grant
    ON certification_items(campaign_id, grant_id) WHERE deleted_at IS NULL;
