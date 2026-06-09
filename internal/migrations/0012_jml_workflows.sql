-- Session WS3: JML no-code workflow builder schema.
--
-- Adds the declarative, versioned Joiner/Mover/Leaver workflow document
-- (draft → publish lifecycle, mirroring the policies table) and the workflow
-- run ledger that backs the JML dashboard (recent runs, status, per-step
-- breakdown). Dry-run simulations are NOT persisted as runs — they have no
-- side effects and cache their result on workflows.draft_simulation instead.
--
-- NOTE: prefixes 0005-0009 are reserved by Session 1D (PAM gateway) and 0010-
-- 0011 by Session 1E / PAM protocol expansion, so WS3 starts at 0012. The
-- runner keys schema_migrations by the numeric prefix, so the prefix must be
-- unique.
--
-- Tenant isolation: workspace_id scopes every row; the workflow service only
-- ever queries (workspace_id, id) together, and every run is scoped by
-- workspace.

-- workflows: declarative JML automation with a draft/simulate/publish
-- lifecycle. Only a 'published' workflow is executed by the engine; a 'draft'
-- never runs. draft_simulation caches the last dry-run output and is cleared on
-- every edit (the publish gate requires a non-empty cache).
CREATE TABLE IF NOT EXISTS workflows (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id     UUID NOT NULL REFERENCES workspaces(id),
    name             TEXT NOT NULL,
    trigger          TEXT NOT NULL DEFAULT 'manual',
    state            TEXT NOT NULL DEFAULT 'draft',
    version          INTEGER NOT NULL DEFAULT 1,
    definition       JSONB,
    draft_simulation JSONB,
    published_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_workflows_workspace ON workflows(workspace_id);

-- workflow_runs: one row per live execution of a published workflow for a
-- single subject. Append-only ledger for the dashboard; the per-step outcome
-- breakdown lives in the steps JSONB. mode is always 'live' here (dry-runs are
-- not persisted); kept explicit so the column can carry future replay modes.
CREATE TABLE IF NOT EXISTS workflow_runs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id        UUID NOT NULL REFERENCES workspaces(id),
    workflow_id         UUID NOT NULL REFERENCES workflows(id),
    workflow_version    INTEGER NOT NULL DEFAULT 1,
    trigger             TEXT,
    subject_external_id TEXT,
    mode                TEXT NOT NULL DEFAULT 'live',
    status              TEXT NOT NULL,
    steps               JSONB,
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_workspace ON workflow_runs(workspace_id);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_workflow ON workflow_runs(workflow_id);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_subject ON workflow_runs(subject_external_id);
