-- AI risk review baked into the elevation request flow.
--
-- Adds the append-only AI risk-verdict trail and the advisory anomaly-flag
-- table that back the lifecycle RiskReviewService. Both are workspace-scoped so
-- the RequireTenant middleware + service layer scope every query by workspace,
-- and both are immutable audit rows (never UPDATEd) so a request's full
-- risk-assessment history — the exact signals fed to the model and the model's
-- rationale — is reconstructable.

-- access_risk_verdicts: one immutable row per AI review of a request. The
-- latest row drives workflow routing; older rows are retained for audit. inputs
-- captures the exact signals sent to the model; factors/rationale capture its
-- output; degraded=true marks a fail-open fallback verdict (AI unreachable).
CREATE TABLE IF NOT EXISTS access_risk_verdicts (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id   UUID NOT NULL REFERENCES workspaces(id),
    request_id     UUID NOT NULL REFERENCES access_requests(id),
    score          TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    factors        JSONB,
    rationale      TEXT,
    inputs         JSONB,
    source         TEXT NOT NULL DEFAULT 'ai_agent',
    degraded       BOOLEAN NOT NULL DEFAULT false,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_risk_verdicts_workspace ON access_risk_verdicts(workspace_id);
CREATE INDEX IF NOT EXISTS idx_risk_verdicts_request ON access_risk_verdicts(request_id, created_at DESC);

-- access_request_anomaly_flags: advisory anomaly observations surfaced by the
-- anomaly-detection skill against an approved elevation. Workspace-scoped and
-- optionally grant-linked so the flag surfaces both on the request and inside
-- access reviews. Advisory only — a flag never changes FSM state.
CREATE TABLE IF NOT EXISTS access_request_anomaly_flags (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    request_id   UUID NOT NULL REFERENCES access_requests(id),
    grant_id     UUID REFERENCES access_grants(id),
    kind         TEXT NOT NULL,
    severity     TEXT,
    reason       TEXT,
    confidence   DOUBLE PRECISION,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_anomaly_flags_workspace ON access_request_anomaly_flags(workspace_id);
CREATE INDEX IF NOT EXISTS idx_anomaly_flags_request ON access_request_anomaly_flags(request_id);
CREATE INDEX IF NOT EXISTS idx_anomaly_flags_grant ON access_request_anomaly_flags(grant_id);
