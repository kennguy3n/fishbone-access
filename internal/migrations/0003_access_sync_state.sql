-- 0003_access_sync_state
--
-- Per-connector incremental-sync checkpoints. Delta-capable providers (e.g.
-- Microsoft Entra / Graph, Okta) return an opaque delta link or cursor at the
-- end of each sync; persisting it lets the next run fetch only what changed
-- instead of re-enumerating every identity. Scoped by workspace for tenant
-- isolation, with one row per (workspace, connector, sync_type).

CREATE TABLE IF NOT EXISTS access_sync_state (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id   UUID NOT NULL REFERENCES workspaces(id),
    connector_id   UUID NOT NULL REFERENCES access_connectors(id),
    sync_type      TEXT NOT NULL DEFAULT 'identities',
    delta_link     TEXT,
    last_synced_at TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_access_sync_state_workspace ON access_sync_state(workspace_id);

-- One checkpoint per (workspace, connector, sync_type). Partial unique index
-- (deleted_at IS NULL) so a soft-deleted checkpoint doesn't block re-creating
-- one for the same connector, matching the GORM soft-delete convention.
CREATE UNIQUE INDEX IF NOT EXISTS uq_access_sync_state
    ON access_sync_state(workspace_id, connector_id, sync_type)
    WHERE deleted_at IS NULL;
