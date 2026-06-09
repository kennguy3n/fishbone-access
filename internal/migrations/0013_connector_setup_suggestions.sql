-- Workstream 2: AI-assisted connector setup assistant persistence.
--
-- Every invocation of the connector_setup_assistant skill is persisted here so
-- the model's structured plan, the inputs that produced it, and its provenance
-- (degraded fallback vs real response, LLM-enriched vs deterministic) are
-- auditable — the program contract requires the AI's rationale + inputs to be
-- retained whenever AI advises an operator. It also lets the console re-display
-- prior guidance for a connector without re-invoking the agent.
--
-- Tenant isolation: workspace_id scopes every row and is always derived from
-- the validated tenant context, never from client input. connector_id is
-- nullable because the assistant is normally run during the setup wizard,
-- before the connector instance exists; it is back-filled once an instance is
-- created. ON DELETE SET NULL keeps the suggestion (and its audit value) even
-- if the connector it was later associated with is removed.

CREATE TABLE IF NOT EXISTS connector_setup_suggestions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id  UUID NOT NULL REFERENCES workspaces(id),
    connector_id  UUID REFERENCES access_connectors(id) ON DELETE SET NULL,
    provider      TEXT NOT NULL,
    actor         TEXT,
    admin_intent  TEXT,
    strategy      TEXT,
    degraded      BOOLEAN NOT NULL DEFAULT false,
    model_used    BOOLEAN NOT NULL DEFAULT false,
    plan          JSONB,
    inputs        JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_connector_setup_suggestions_workspace
    ON connector_setup_suggestions(workspace_id);

-- The console lists a workspace's suggestions for a given provider newest-first.
CREATE INDEX IF NOT EXISTS idx_connector_setup_suggestions_ws_provider
    ON connector_setup_suggestions(workspace_id, provider, created_at DESC)
    WHERE deleted_at IS NULL;
