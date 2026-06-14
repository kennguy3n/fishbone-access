-- 0019_tenant_resource_budgets: tiered per-tenant resource budgets.
--
-- Bounds how much concurrent periodic work any one tenant may run so the
-- dormant-trial majority — and any single noisy tenant — cannot consume the
-- share of active, paying tenants. One row per workspace; absence of a row
-- means the tenant takes its tier defaults (see internal/services/tenancy:
-- tierDefaults), so this table need only hold explicit overrides rather than a
-- row per tenant — keeping it near-empty for the dormant majority.
--
-- A zero cap column means "inherit the tier default" at resolve time, so an
-- operator can pin one knob for one tenant without restating the whole budget.
-- The fair scheduler (tenancy.FairScheduler) enforces max_concurrent_syncs as a
-- per-tenant ceiling under a process-global ceiling; max_periodic_jobs_per_hour
-- and fair_share_weight tune scheduling frequency and fair-share bias.
--
-- This mirrors the GORM model tenancy.TenantResourceBudget.

CREATE TABLE IF NOT EXISTS tenant_resource_budgets (
    workspace_id               UUID PRIMARY KEY REFERENCES workspaces(id),
    tier                       TEXT NOT NULL DEFAULT 'trial'
                                    CHECK (tier IN ('trial', 'base', 'pro', 'enterprise')),
    max_concurrent_syncs       INTEGER NOT NULL DEFAULT 0
                                    CHECK (max_concurrent_syncs >= 0),
    max_periodic_jobs_per_hour INTEGER NOT NULL DEFAULT 0
                                    CHECK (max_periodic_jobs_per_hour >= 0),
    fair_share_weight          INTEGER NOT NULL DEFAULT 0
                                    CHECK (fair_share_weight >= 0),
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Surface explicit budgets by tier for operator review / fleet reporting
-- ("how many tenants are pinned to enterprise?"). Cheap: the table holds only
-- overrides, not a row per tenant.
CREATE INDEX IF NOT EXISTS idx_tenant_resource_budgets_tier
    ON tenant_resource_budgets (tier);
