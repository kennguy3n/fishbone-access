-- WS2: detected, dispositioned access anomalies.
--
-- The scheduled anomaly detector evaluates a workspace's LIVE access_grants
-- against the SoD rules and records each toxic-combination it finds here, then
-- appends the detection + auto-disposition to the per-workspace audit hash chain
-- (audit_events) under the actions the compliance framework already maps to the
-- SOC2 CC7.3 evidence kinds (orphan.detected → orphan_detected,
-- orphan.disposition.* → orphan_disposition). So CC7.3 stops showing 0 records
-- as a side effect of normal operation — this table is the detector's OWN state
-- (worklist + idempotency), NOT a parallel, separately-forgeable evidence log.
--
-- fingerprint dedupes a standing violation across sweeps: the same (kind,
-- subject, rule, entitlement pair) is detected once and not re-emitted every
-- interval. Tenant-scoped by workspace_id.
CREATE TABLE IF NOT EXISTS access_anomalies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id),
    kind            TEXT NOT NULL,
    subject         TEXT NOT NULL,
    rule_id         UUID REFERENCES sod_rules(id),
    severity        TEXT NOT NULL DEFAULT 'high',
    detail          JSONB,
    -- flagged (auto-triaged at detection) → acknowledged | resolved (operator).
    disposition     TEXT NOT NULL DEFAULT 'flagged',
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    fingerprint     TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_access_anomalies_workspace ON access_anomalies(workspace_id);
CREATE INDEX IF NOT EXISTS idx_access_anomalies_subject ON access_anomalies(workspace_id, subject);
-- A standing violation is recorded once per workspace: the detector upserts on
-- this fingerprint so re-running the sweep does not duplicate evidence.
CREATE UNIQUE INDEX IF NOT EXISTS uq_access_anomalies_fingerprint
    ON access_anomalies(workspace_id, fingerprint) WHERE deleted_at IS NULL;
