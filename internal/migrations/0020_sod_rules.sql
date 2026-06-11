-- WS2: Separation-of-Duties (SoD) toxic-combination rules.
--
-- An SoD rule names two entitlement SELECTORS (A and B). Each selector matches
-- a held entitlement — an (resource_ref, role) pair from a subject's live
-- access_grants — by resource and role, where '*' is a wildcard. A subject
-- violates the rule when their effective entitlements contain two DISTINCT
-- entitlements, one matching selector A and one matching selector B (the classic
-- "create-vendor" + "approve-payment" fraud pair). This is governance over
-- cross-entitlement accumulation, distinct from the pairwise grant-vs-deny
-- policy_conflict path which only catches two policies disagreeing about the
-- same (subject, resource) pair.
--
-- The simulate/promote what-if evaluates a candidate policy against these rules
-- so a catastrophic SoD change is surfaced (and high/critical violations block)
-- BEFORE it is applied; the scheduled detector evaluates live grants against
-- them to emit dispositioned-anomaly evidence. Tenant-scoped by workspace_id.
CREATE TABLE IF NOT EXISTS sod_rules (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    name         TEXT NOT NULL,
    description  TEXT,
    -- low | medium | high | critical. high/critical block a promotion as a
    -- "catastrophic change" unless force-overridden with an audited reason.
    severity     TEXT NOT NULL DEFAULT 'high',
    -- Only enabled rules are evaluated; retiring a rule keeps its history.
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    -- Selector A / B: '*' (or empty) is a wildcard matching any resource/role.
    resource_a   TEXT NOT NULL DEFAULT '*',
    role_a       TEXT NOT NULL DEFAULT '*',
    resource_b   TEXT NOT NULL DEFAULT '*',
    role_b       TEXT NOT NULL DEFAULT '*',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_sod_rules_workspace ON sod_rules(workspace_id);
-- The evaluator loads only enabled rules for a workspace on the hot simulate
-- path, so index that predicate.
CREATE INDEX IF NOT EXISTS idx_sod_rules_enabled ON sod_rules(workspace_id, enabled) WHERE deleted_at IS NULL;
