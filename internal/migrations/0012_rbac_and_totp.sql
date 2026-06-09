-- WS1: RBAC role assignments, TOTP secret store, and TOTP replay-prevention.
--
-- Three tables, all workspace-scoped for tenant isolation:
--
--   workspace_members   -- the (workspace_id, user_id) -> role mapping that
--                          backs the RBAC layer (internal/services/authz). One
--                          role per user per workspace; hard-deleted (no
--                          soft-delete) so a removed membership stops
--                          authorizing immediately.
--   user_totp_secrets   -- enrolled RFC 6238 TOTP shared secrets, consumed by
--                          the step-up MFA verifier (internal/services/mfa).
--   pam_totp_used_codes -- accepted TOTP code hashes, so a code can be used at
--                          most once within its remaining validity window even
--                          though it stays mathematically valid for the step.
--
-- NOTE: the runner (internal/migrations/migrations.go) sorts embedded *.sql by
-- their NNNN_ numeric prefix and keys schema_migrations by it, so each prefix
-- must be unique. The latest existing migration is 0011; WS1 continues at 0012.

-- --- RBAC role assignments -------------------------------------------------
CREATE TABLE IF NOT EXISTS workspace_members (
    workspace_id UUID        NOT NULL REFERENCES workspaces(id),
    user_id      VARCHAR(255) NOT NULL,
    role         VARCHAR(32) NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id),
    CONSTRAINT workspace_members_role_check
        CHECK (role IN ('owner', 'admin', 'security_admin', 'operator', 'auditor'))
);

-- Index on role keeps the "count remaining owners" last-owner-guard query
-- (WHERE workspace_id = ? AND role = 'owner') off a full table scan.
CREATE INDEX IF NOT EXISTS idx_workspace_members_role
    ON workspace_members(workspace_id, role);

-- --- TOTP secret store ------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_totp_secrets (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID        NOT NULL REFERENCES workspaces(id),
    user_id      VARCHAR(255) NOT NULL,
    secret       VARCHAR(255) NOT NULL,
    verified     BOOLEAN     NOT NULL DEFAULT false,
    disabled_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_totp_secrets_ws_user
    ON user_totp_secrets(workspace_id, user_id);

-- At most one active (verified, non-disabled) secret per (workspace, user).
-- The partial WHERE matches the verifier's lookup predicate so re-enrollment
-- (insert a new active row) is rejected until the previous one is disabled.
CREATE UNIQUE INDEX IF NOT EXISTS uq_totp_secret_active
    ON user_totp_secrets(workspace_id, user_id)
    WHERE verified = true AND disabled_at IS NULL AND deleted_at IS NULL;

-- --- TOTP replay prevention -------------------------------------------------
-- Composite primary key (workspace_id, user_id, code_hash) is the anti-replay
-- claim: the verifier INSERTs ON CONFLICT DO NOTHING after validating a code
-- and treats a zero-row result as a replay. Only the SHA-256 hash of the code
-- is stored, never the code itself.
CREATE TABLE IF NOT EXISTS pam_totp_used_codes (
    workspace_id UUID        NOT NULL REFERENCES workspaces(id),
    user_id      VARCHAR(255) NOT NULL,
    code_hash    VARCHAR(64) NOT NULL,
    used_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id, code_hash)
);

-- Drives the background cleanup sweep (DELETE WHERE used_at < cutoff).
CREATE INDEX IF NOT EXISTS idx_pam_totp_used_codes_used_at
    ON pam_totp_used_codes(used_at);
