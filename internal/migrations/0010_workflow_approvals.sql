-- Workflow engine approval-chain persistence.
--
-- The workflow engine routes medium/high/sensitive access requests to a
-- human-approval lane (manager_approval / security_review). Each approver's
-- decision is recorded here as an append-only row so the full approval chain is
-- auditable and resumable across worker restarts: the engine re-derives whether
-- a request's chain is satisfied purely from these rows, never from in-memory
-- state.
--
-- NOTE: migration prefixes 0005-0009 are reserved by the PAM gateway schema,
-- so workflow approvals start at 0010. The runner keys schema_migrations by the
-- numeric prefix, so the prefix must be unique.
--
-- Tenant isolation: workspace_id scopes every row; the engine only ever queries
-- (workspace_id, request_id) together.

CREATE TABLE IF NOT EXISTS workflow_approvals (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id  UUID NOT NULL REFERENCES workspaces(id),
    request_id    UUID NOT NULL REFERENCES access_requests(id),
    approver      TEXT NOT NULL,
    approver_role TEXT,
    decision      TEXT NOT NULL,
    reason        TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_workflow_approvals_workspace ON workflow_approvals(workspace_id);
CREATE INDEX IF NOT EXISTS idx_workflow_approvals_request ON workflow_approvals(request_id);

-- One decision per approver per request: a re-submitted decision from the same
-- approver is idempotent (the engine does a transactional select-then-
-- insert/update keyed on this index) rather than inflating the chain. The
-- partial WHERE deleted_at IS NULL matches the GORM soft-delete model.
CREATE UNIQUE INDEX IF NOT EXISTS uq_workflow_approval
    ON workflow_approvals(workspace_id, request_id, approver)
    WHERE deleted_at IS NULL;
