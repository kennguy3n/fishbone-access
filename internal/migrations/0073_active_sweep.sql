-- 0073_active_sweep: scheduled ACTIVE network discovery sweep, per workspace.
--
-- 0070 added auto_onboarding_policies, which the workflow engine's scheduled
-- sweep uses to inventory CONNECTORS and onboard matching assets. This adds an
-- independent, opt-in ACTIVE sweep: on each scheduled-sweep tick the engine
-- expands a bounded host/cidr list and probes well-known privileged-service
-- ports THROUGH a named agent (the same AgentSweep an operator can trigger
-- manually), so previously-undiscovered hosts surface automatically. It is
-- gated by its OWN flag (active_sweep_enabled), separate from `enabled`, so a
-- workspace can run active discovery without auto-onboarding, or vice versa.
--
--   * active_sweep_enabled  BOOLEAN NOT NULL DEFAULT FALSE — safe-by-default
--     OFF. NOT NULL with a DEFAULT is lock-safe (no table rewrite, no scan).
--   * active_sweep_agent_id UUID REFERENCES agents(id) — the agent the sweep
--     dials through (a sweep only ever probes through an agent, never direct).
--     Mirrors default_agent_id from 0070: nullable FK, validated NOT VALID-free
--     since the column starts empty. A nullable ADD COLUMN with an FK takes only
--     a brief SHARE ROW EXCLUSIVE lock and rewrites nothing.
--   * active_sweep_targets  JSONB — the bounded {hosts,cidrs,ports} target set;
--     the service caps host*port fan-out by Config.MaxProbeTargets at save time.
--
-- No RLS policy block required: auto_onboarding_policies already carries
-- tenant_isolation + FORCE ROW LEVEL SECURITY from 0070, and this only adds
-- columns to that existing table.
ALTER TABLE auto_onboarding_policies
    ADD COLUMN IF NOT EXISTS active_sweep_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS active_sweep_agent_id UUID REFERENCES agents(id),
    ADD COLUMN IF NOT EXISTS active_sweep_targets JSONB;
