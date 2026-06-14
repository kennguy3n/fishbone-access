-- 0025_tenant_usage: per-tenant usage-metering rollup (P1 billing foundation).
--
-- Accumulates per-tenant usage counts (API calls today) so cost-to-serve is
-- attributable per tenant across a 5,000-SME fleet, and can later be billed or
-- capped. It is the "who is using what" half of the cost story; the per-tenant
-- rate limiter (0-config, in-memory) is the "cap the abuser" half.
--
-- Cardinality is the operative constraint at this tenant count. The Prometheus
-- instruments (migration-independent, see internal/pkg/observability) are
-- deliberately NEVER labelled by tenant id, because 5,000 tenants x routes would
-- explode the time-series count. Per-tenant attribution therefore lives HERE, in
-- Postgres, where a row per (workspace, period, metric) is cheap; only AGGREGATE
-- (non-tenant) counters reach /metrics. The control plane reads a tenant's own
-- rollup back through an authenticated endpoint, never by scraping per tenant.
--
-- One row per (workspace_id, period, metric). The period is a billing month
-- ("YYYY-MM" UTC), so a new month starts a fresh row rather than mutating the
-- previous month's total. Writes use an ADDITIVE upsert (count = count + delta)
-- from each ztna-api replica's in-memory flush, so N replicas SUM into one row
-- rather than overwriting one another (the deliberate per-replica posture,
-- mirroring the rate limiter). This mirrors the GORM model usage.TenantUsage,
-- which is the source of truth for the SQLite test path.

CREATE TABLE IF NOT EXISTS tenant_usage (
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    period       TEXT NOT NULL,
    metric       TEXT NOT NULL,
    count        BIGINT NOT NULL DEFAULT 0 CHECK (count >= 0),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, period, metric)
);

-- Fleet/operator reporting reads by (period, metric) across tenants
-- ("total API calls billed this month", "top consumers"); the composite primary
-- key already serves the per-tenant read (workspace_id, period prefix), so this
-- secondary index covers only the cross-tenant rollup scan.
CREATE INDEX IF NOT EXISTS idx_tenant_usage_period_metric
    ON tenant_usage (period, metric);

-- Row-Level Security: tenant_usage carries a workspace_id, so it joins the
-- 0024 tenant-isolation regime. RLS DOES apply because the table is READ on the
-- authenticated request path (the read endpoint), where RequireTenant pins the
-- app.workspace_id GUC and the policy then restricts a tenant to its OWN rows —
-- a privacy backstop behind the explicit `WHERE workspace_id = ?`. The WRITE
-- path is the flush worker, which runs UNSCOPED (no GUC), so the policy is
-- permissive for it and one batch may UPSERT rows for every active workspace.
-- The app_current_workspace_id() helper is defined in 0024.
ALTER TABLE tenant_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_usage FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_usage;
CREATE POLICY tenant_isolation ON tenant_usage
    USING (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id())
    WITH CHECK (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id());
