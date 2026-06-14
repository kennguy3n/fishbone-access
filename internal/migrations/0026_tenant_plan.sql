-- 0026_tenant_plan: per-tenant billing plan assignment (P2 billing economics).
--
-- Turns the per-tenant usage rollup (0025_tenant_usage) into an economics layer:
-- a tenant's PLAN names which quota ladder and pricing apply, and quota
-- enforcement caps consumption before a runaway tenant burns shared resources
-- (and the bill). This is the "what may a tenant consume, and what does it owe"
-- half of the cost story; 0025 is the "who is using what" half.
--
-- The plan identity is deliberately the SAME tier ladder as the tenancy
-- resource budgets (0019_tenant_resource_budgets: trial/base/pro/enterprise),
-- reusing the tenancy.Tier* constants rather than inventing a parallel billing
-- taxonomy. The two tables stay SEPARATE because they answer different
-- questions and change on different cadences: tenant_resource_budgets bounds
-- INTERNAL background-work concurrency for the fair scheduler, while tenant_plan
-- bounds EXTERNAL request consumption and carries the billing quota overrides.
-- Folding billing columns into the scheduler-budget row would couple two
-- unrelated concerns behind one CHECK/RLS surface; layering beside it keeps each
-- table cohesive while the shared tier string ties them to one ladder.
--
-- Like the budget table, absence of a row means the tenant takes its plan's
-- built-in quota ladder (see internal/services/billing: planDefaults), so this
-- table need only hold explicit assignments/overrides rather than a row per
-- tenant — keeping it near-empty for the dormant-trial majority. A zero
-- override column means "inherit the plan default" at resolve time, so an
-- operator can pin one tenant's API ceiling without restating the whole plan.
--
-- The included/hard-cap quotas are stored as BIGINT counts (no float drift);
-- pricing lives in code (minor units, also integer) and is derived, not stored,
-- so a statement re-generated for a closed period is byte-identical. This
-- mirrors the GORM model billing.TenantPlan, the source of truth for the SQLite
-- test path.

CREATE TABLE IF NOT EXISTS tenant_plan (
    workspace_id          UUID PRIMARY KEY REFERENCES workspaces(id),
    plan                  TEXT NOT NULL DEFAULT 'trial'
                               CHECK (plan IN ('trial', 'base', 'pro', 'enterprise')),
    -- Per-workspace overrides for the api_requests metric (0 = inherit the
    -- plan default). Named columns mirror tenant_resource_budgets rather than a
    -- generic key/value blob: only api_requests is metered today, so an
    -- explicit, CHECK-constrained column is clearer and indexable. Additional
    -- metered metrics get their own columns in a later migration.
    api_requests_included BIGINT NOT NULL DEFAULT 0 CHECK (api_requests_included >= 0),
    api_requests_hard_cap BIGINT NOT NULL DEFAULT 0 CHECK (api_requests_hard_cap >= 0),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Surface explicit plan assignments by tier for operator review / fleet
-- reporting ("how many tenants are on pro?"). Cheap: the table holds only
-- explicit rows, not a row per tenant.
CREATE INDEX IF NOT EXISTS idx_tenant_plan_plan
    ON tenant_plan (plan);

-- Row-Level Security: tenant_plan carries a workspace_id, so it joins the 0024
-- tenant-isolation regime. RLS applies because the table is READ on the
-- authenticated request path (the billing read endpoints AND the quota
-- enforcement middleware), where RequireTenant pins the app.workspace_id GUC and
-- the policy then restricts a tenant to its OWN plan — a privacy backstop behind
-- the explicit `WHERE workspace_id = ?`. The admin set-plan write also runs on
-- that authenticated, GUC-pinned path, so the WITH CHECK clause stops a tenant
-- writing a row for another workspace. A background/unscoped context (empty GUC)
-- is permissive, so a future fleet-wide billing worker keeps working. The
-- app_current_workspace_id() helper is defined in 0024.
ALTER TABLE tenant_plan ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_plan FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_plan;
CREATE POLICY tenant_isolation ON tenant_plan
    USING (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id())
    WITH CHECK (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id());
