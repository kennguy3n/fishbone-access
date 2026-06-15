-- Outbound connector agents + brokered dial.
--
-- An outbound-only agent runs on one host inside an SME's private network. It
-- dials OUT to the control-plane relay over mTLS and brokers privileged
-- sessions (SSH/DB/...) to private targets, so the customer never opens an
-- inbound firewall port. These tables back the agent registry (agents), the
-- one-shot enrollment-token broker (agent_enrollment_tokens), and the
-- reachable-target bindings the relay routes by (agent_reachable_targets).
--
-- Every table carries workspace_id so RequireTenant + the service layer scope
-- each query by workspace, exactly like the rest of the schema, and each is
-- added to the Row-Level Security policy set below (the same tenant_isolation
-- policy + FORCE RLS as 0024) so a forgotten WHERE clause can never broker one
-- tenant's tunnel to another's network. Enroll/revoke/broker-open actions land
-- in the shared audit_events hash chain (internal/services/lifecycle/audit.go).

-- agents: the durable registration + health record for one outbound connector.
-- Identity is the issued client certificate: cert_fingerprint is the SHA-256 of
-- its DER, which the relay matches against the presented peer certificate to
-- bind a live tunnel to this row. status is the control-plane view of health
-- (enrolled → online/offline, or revoked); the live tunnel itself lives only in
-- the relay process. A workspace cannot have two live agents with the same name
-- (the partial unique index ignores soft-deleted rows).
CREATE TABLE IF NOT EXISTS agents (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id     UUID NOT NULL REFERENCES workspaces(id),
    name             TEXT NOT NULL,
    cert_fingerprint TEXT NOT NULL,
    cert_serial      TEXT NOT NULL,
    cert_not_after   TIMESTAMPTZ NOT NULL,
    status           TEXT NOT NULL DEFAULT 'enrolled',
    last_seen_at     TIMESTAMPTZ,
    agent_version    TEXT,
    platform         TEXT,
    revoked_at       TIMESTAMPTZ,
    revoked_by       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_agents_workspace ON agents(workspace_id);
CREATE INDEX IF NOT EXISTS idx_agents_deleted_at ON agents(deleted_at);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agents_fingerprint ON agents(cert_fingerprint);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agents_name ON agents(workspace_id, name) WHERE deleted_at IS NULL;

-- agent_enrollment_tokens: one-shot, short-lived secrets an operator mints to
-- enroll exactly one agent. Only token_hash (SHA-256 of the raw token) is
-- stored, so a database read cannot recover a usable token. Redemption
-- atomically flips state pending → consumed and binds agent_id under the unique
-- token_hash so a token enrolls at most one agent.
CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    token_hash   TEXT NOT NULL,
    name         TEXT NOT NULL,
    state        TEXT NOT NULL DEFAULT 'pending',
    expires_at   TIMESTAMPTZ NOT NULL,
    consumed_at  TIMESTAMPTZ,
    agent_id     UUID REFERENCES agents(id),
    created_by   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_enroll_tokens_hash ON agent_enrollment_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_agent_enroll_tokens_workspace ON agent_enrollment_tokens(workspace_id);
CREATE INDEX IF NOT EXISTS idx_agent_enroll_tokens_agent ON agent_enrollment_tokens(agent_id);

-- agent_reachable_targets: the network destinations an agent advertises it can
-- reach. The relay unions operator-created bindings (target_id set, what the UI
-- shows) with the agent's self-reported CIDRs (target_id null) to pick an agent
-- for a DialThroughAgent and to fail closed when no online agent covers an
-- address. A binding is unique per (workspace, agent, pattern) for live rows.
CREATE TABLE IF NOT EXISTS agent_reachable_targets (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    agent_id     UUID NOT NULL REFERENCES agents(id),
    pattern      TEXT NOT NULL,
    kind         TEXT NOT NULL,
    target_id    UUID REFERENCES pam_targets(id),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_agent_reach_workspace ON agent_reachable_targets(workspace_id);
CREATE INDEX IF NOT EXISTS idx_agent_reach_agent ON agent_reachable_targets(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_reach_target ON agent_reachable_targets(target_id);
CREATE INDEX IF NOT EXISTS idx_agent_reach_deleted_at ON agent_reachable_targets(deleted_at);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_reach ON agent_reachable_targets(workspace_id, agent_id, pattern) WHERE deleted_at IS NULL;

-- pam_targets gains an optional "reach via agent" pointer. Nullable ADD COLUMN
-- so it is lock-safe (no table rewrite) and the legacy direct-dial path is
-- unchanged for every existing row (NULL = dial directly).
ALTER TABLE pam_targets ADD COLUMN IF NOT EXISTS via_agent_id UUID REFERENCES agents(id);
CREATE INDEX IF NOT EXISTS idx_pam_targets_via_agent ON pam_targets(via_agent_id);

-- Row-Level Security: enroll the three new tenant-scoped tables into the same
-- tenant_isolation policy + FORCE RLS the rest of the schema uses (see 0024).
-- app_current_workspace_id() already exists from 0024.
DO $$
DECLARE
    t text;
    tables text[] := ARRAY[
        'agents',
        'agent_enrollment_tokens',
        'agent_reachable_targets'
    ];
BEGIN
    FOREACH t IN ARRAY tables LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I '
            'USING (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id()) '
            'WITH CHECK (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id())',
            t);
    END LOOP;
END $$;
