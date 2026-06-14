-- Row-Level Security tenant isolation backstop.
--
-- Every tenant-scoped table is already queried with an explicit
-- `WHERE workspace_id = ?`. That app-level scoping stays the primary mechanism;
-- this migration adds the database-tier backstop so a single forgotten clause
-- in a request handler can no longer leak one tenant's rows to another.
--
-- How it works: each workspace-scoped table gets a `tenant_isolation` policy
-- keyed on the `app.workspace_id` session GUC, which the application pool sets
-- per request from the authenticated workspace (internal/pkg/database/rls.go).
-- When the GUC is set, a row is visible/writable only if its workspace_id
-- matches; when it is NOT set (the empty string / NULL), the policy is
-- permissive so cross-workspace background workers, schedulers and this
-- migration runner keep working. RLS therefore enforces isolation on every
-- authenticated request path while leaving trusted cross-tenant jobs untouched.
--
-- RLS is FORCEd so it applies even when the application connects as the table
-- owner. NOTE: Postgres superusers and roles with BYPASSRLS are never subject to
-- RLS — the control plane must connect as an ordinary role for this to bite
-- (migrations may run as a privileged role; the request path must not).

-- app_current_workspace_id resolves the request's workspace from the GUC, or
-- NULL when unscoped. STABLE so the planner evaluates it once per query rather
-- than per row. NULLIF maps the unscoped sentinel ('') to NULL before the cast,
-- so an unset GUC never raises an invalid-uuid error.
CREATE OR REPLACE FUNCTION app_current_workspace_id() RETURNS uuid
    LANGUAGE sql STABLE
    AS $$ SELECT NULLIF(current_setting('app.workspace_id', true), '')::uuid $$;

-- Tables keyed by a workspace_id column.
DO $$
DECLARE
    t text;
    tables text[] := ARRAY[
        'access_anomalies',
        'access_connectors',
        'access_grants',
        'access_jobs',
        'access_orphan_accounts',
        'access_request_anomaly_flags',
        'access_request_state_history',
        'access_requests',
        'access_review_items',
        'access_reviews',
        'access_risk_verdicts',
        'access_sync_state',
        'audit_events',
        'certification_campaigns',
        'certification_items',
        'connector_setup_suggestions',
        'contractor_grant_extensions',
        'contractor_grants',
        'pam_connect_tokens',
        'pam_leases',
        'pam_session_commands',
        'pam_sessions',
        'pam_targets',
        'pam_totp_used_codes',
        'policies',
        'sod_rules',
        'team_members',
        'teams',
        'tenant_activity',
        'tenant_resource_budgets',
        'user_totp_secrets',
        'workflow_approvals',
        'workflow_runs',
        'workflows',
        'workspace_members'
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

-- The workspaces table is the tenant root: its own id is the workspace key.
ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspaces FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON workspaces;
CREATE POLICY tenant_isolation ON workspaces
    USING (app_current_workspace_id() IS NULL OR id = app_current_workspace_id())
    WITH CHECK (app_current_workspace_id() IS NULL OR id = app_current_workspace_id());
