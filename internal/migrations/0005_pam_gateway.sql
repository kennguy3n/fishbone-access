-- Session 1D: PAM gateway schema.
--
-- The privileged-access gateway proxies SSH / PostgreSQL / MySQL / Kubernetes
-- sessions. These tables back the credential vault (pam_targets), the one-shot
-- connect-token broker (pam_connect_tokens), the proxied-session lifecycle
-- (pam_sessions), and the per-command audit log (pam_session_commands).
--
-- Every table carries workspace_id so the RequireTenant middleware + service
-- layer scope every query by workspace, exactly like the 1A/1C schema. The
-- per-command rows additionally land in the shared audit_events hash chain for
-- tamper evidence (see internal/services/lifecycle/audit.go); these tables hold
-- the queryable projection, the chain holds the integrity proof.

-- pam_targets: the credential vault. secret_envelope holds the AES-256-GCM
-- sealed upstream credential (never plaintext); secret_key_version records the
-- DEK version that sealed it so the EnvelopeEncryptor resolves the right key
-- across rotations. A workspace cannot have two live targets with the same
-- name (the partial unique index ignores soft-deleted rows).
CREATE TABLE IF NOT EXISTS pam_targets (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id       UUID NOT NULL REFERENCES workspaces(id),
    name               TEXT NOT NULL,
    protocol           TEXT NOT NULL,
    address            TEXT NOT NULL,
    username           TEXT,
    config             JSONB,
    secret_envelope    TEXT,
    secret_key_version INTEGER NOT NULL DEFAULT 1,
    require_mfa        BOOLEAN NOT NULL DEFAULT false,
    lease_ttl_seconds  INTEGER NOT NULL DEFAULT 0,
    secret_rotated_at  TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at         TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pam_targets_workspace ON pam_targets(workspace_id);
CREATE INDEX IF NOT EXISTS idx_pam_targets_deleted_at ON pam_targets(deleted_at);
CREATE UNIQUE INDEX IF NOT EXISTS uq_pam_targets_name ON pam_targets(workspace_id, name) WHERE deleted_at IS NULL;

-- pam_sessions: one proxied privileged connection. replay_key is the storage
-- key of the recorded I/O blob; terminated_by records the admin who killed an
-- active session via takeover.
CREATE TABLE IF NOT EXISTS pam_sessions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id  UUID NOT NULL REFERENCES workspaces(id),
    target_id     UUID NOT NULL REFERENCES pam_targets(id),
    subject       TEXT NOT NULL,
    protocol      TEXT NOT NULL,
    state         TEXT NOT NULL DEFAULT 'active',
    client_addr   TEXT,
    replay_key    TEXT,
    started_at    TIMESTAMPTZ,
    ended_at      TIMESTAMPTZ,
    terminated_by TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pam_sessions_workspace ON pam_sessions(workspace_id);
CREATE INDEX IF NOT EXISTS idx_pam_sessions_target ON pam_sessions(target_id);
CREATE INDEX IF NOT EXISTS idx_pam_sessions_subject ON pam_sessions(subject);
CREATE INDEX IF NOT EXISTS idx_pam_sessions_deleted_at ON pam_sessions(deleted_at);

-- pam_connect_tokens: one-shot, short-lived operator credentials. Only
-- token_hash (SHA-256 of the raw token) is stored, so a database read cannot
-- recover a usable token. Redemption atomically flips state pending → consumed
-- under the unique token_hash so a token authorizes at most one session.
CREATE TABLE IF NOT EXISTS pam_connect_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    target_id    UUID NOT NULL REFERENCES pam_targets(id),
    token_hash   TEXT NOT NULL,
    subject      TEXT NOT NULL,
    state        TEXT NOT NULL DEFAULT 'pending',
    expires_at   TIMESTAMPTZ NOT NULL,
    consumed_at  TIMESTAMPTZ,
    session_id   UUID,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_pam_connect_tokens_hash ON pam_connect_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_pam_connect_tokens_workspace ON pam_connect_tokens(workspace_id);
CREATE INDEX IF NOT EXISTS idx_pam_connect_tokens_target ON pam_connect_tokens(target_id);
CREATE INDEX IF NOT EXISTS idx_pam_connect_tokens_subject ON pam_connect_tokens(subject);
CREATE INDEX IF NOT EXISTS idx_pam_connect_tokens_session ON pam_connect_tokens(session_id);

-- pam_session_commands: append-only per-command audit projection. seq is a
-- per-session monotonic counter so the transcript reconstructs in order
-- independent of wall-clock timestamps.
CREATE TABLE IF NOT EXISTS pam_session_commands (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    session_id   UUID NOT NULL REFERENCES pam_sessions(id),
    seq          BIGINT NOT NULL DEFAULT 0,
    command      TEXT NOT NULL,
    decision     TEXT NOT NULL DEFAULT 'allow',
    reason       TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pam_cmds_session_seq ON pam_session_commands(workspace_id, session_id, seq DESC);
CREATE INDEX IF NOT EXISTS idx_pam_session_commands_deleted_at ON pam_session_commands(deleted_at);
