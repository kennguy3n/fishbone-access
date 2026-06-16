-- 0080_agent_session_directory: cross-replica ownership of agent tunnels (HA).
--
-- The pam-gateway binary runs as multiple horizontally-scaled replicas behind a
-- load balancer, but an outbound connector agent's mTLS tunnel terminates on
-- exactly ONE replica (its yamux session lives only in that replica's memory).
-- A privileged session-open that needs DialThroughAgent may land on a DIFFERENT
-- replica, which has no local tunnel for that agent and — before this feature —
-- failed closed even though the agent was online elsewhere. This table is the
-- durable, authoritative record of which replica owns each agent's live tunnel
-- so the broker can FORWARD a dial to that replica instead of failing closed.
--
-- Ownership model (single-writer per (workspace_id, agent_id)):
--   * the owning replica claims the row when an agent registers, bumping epoch;
--   * it refreshes last_seen_at on heartbeat (COALESCED — never per-dial, so 5k
--     dormant tenants add no write traffic);
--   * it clears the row on disconnect;
--   * a reconnect (possibly to another replica) takes over by bumping epoch, and
--     every refresh/release is conditioned on the claimant still holding that
--     exact epoch (compare-and-set) so a stale owner whose tunnel already died
--     cannot clobber or delete a newer owner's claim.
--
-- The row is HARD-deleted on disconnect (no soft-delete column): a
-- fast-reconnecting agent must not accumulate tombstones, and the (workspace,
-- agent) pair — not a surrogate id — is the identity. It mirrors the GORM model
-- models.AgentSessionDirectoryEntry, the source of truth for the SQLite test
-- path (AutoMigrate).
--
-- Cost discipline (5,000-SME fleet): at most one row per ONLINE agent; empty and
-- dormant workspaces store nothing. owner_forward_addr is an INTERNAL address
-- (replica-to-replica mTLS), never exposed to tenants.

CREATE TABLE IF NOT EXISTS agent_session_directory (
    workspace_id       UUID        NOT NULL REFERENCES workspaces(id),
    agent_id           UUID        NOT NULL REFERENCES agents(id),
    owner_node_id      TEXT        NOT NULL,
    owner_forward_addr TEXT        NOT NULL,
    epoch              BIGINT      NOT NULL DEFAULT 1 CHECK (epoch > 0),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, agent_id)
);

-- The fleet-wide reconnect path looks an agent's owner up by (workspace, agent),
-- which the primary key already serves. This partial index accelerates the
-- staleness sweep / global online-count read that scans recent owners.
CREATE INDEX IF NOT EXISTS idx_agent_session_dir_last_seen ON agent_session_directory(last_seen_at);

-- Row-Level Security: enroll the new tenant-scoped table into the same
-- tenant_isolation policy + FORCE RLS the rest of the schema uses (see 0024).
-- app_current_workspace_id() already exists from 0024. This is the database-tier
-- backstop that makes a cross-tenant forwarded dial non-exploitable even if an
-- application-level workspace filter were ever forgotten.
DO $$
DECLARE
    t text;
    tables text[] := ARRAY[
        'agent_session_directory'
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
