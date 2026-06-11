-- 0018_tenant_activity: per-tenant activity + dormancy model (WS1 scale/NoOps).
--
-- Tracks the last real interaction per workspace and the derived dormancy
-- state, so the control plane can hibernate the large dormant-trial fraction of
-- a 5,000-SME fleet: periodic workers consult the state (via
-- internal/services/tenancy) and skip dormant tenants, which wake LAZILY on
-- their next activity. One row per workspace (workspace_id is the primary key,
-- 1:1 with an iam-core tenant_id); the row is created lazily on first activity
-- or seeded by the reconcile sweep from the workspace's creation time, so a
-- trial that was never touched is still classified correctly.
--
-- This mirrors the GORM model tenancy.TenantActivity. The state column is the
-- authoritative signal the hibernation gate reads; it is persisted (not derived
-- on read) so the gate is a single indexed primary-key lookup.

CREATE TABLE IF NOT EXISTS tenant_activity (
    workspace_id       UUID PRIMARY KEY REFERENCES workspaces(id),
    last_activity_at   TIMESTAMPTZ NOT NULL,
    last_activity_kind TEXT NOT NULL DEFAULT 'unknown',
    state              TEXT NOT NULL DEFAULT 'active'
                            CHECK (state IN ('active', 'dormant')),
    state_changed_at   TIMESTAMPTZ NOT NULL,
    hibernated_at      TIMESTAMPTZ,
    woken_at           TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The reconcile sweep classifies on (state, last_activity_at): it scans active
-- rows whose last activity predates the idle cutoff (→ hibernate) and dormant
-- rows that have caught up (→ wake). A composite index on (state,
-- last_activity_at) serves both range scans without touching dormant rows when
-- sweeping active ones, keeping the sweep cost proportional to what changes.
CREATE INDEX IF NOT EXISTS idx_tenant_activity_state_last
    ON tenant_activity (state, last_activity_at);
