-- 0060_session_recordings: searchable forensic index for PAM session recordings.
--
-- The gateway captures every privileged session as a direction-tagged, framed
-- binary blob in the ReplayStore (FS or S3) and anchors its SHA-256 in the
-- per-workspace audit hash chain (0005_pam_gateway, internal/gateway/recorder.go).
-- That blob is integrity-only: there is no way to search across sessions or to
-- enumerate what was actually typed/executed without downloading and decoding
-- every recording. This table is the light, queryable PROJECTION of each
-- recording — operator, target, protocol, timing, command/deny counts, the
-- integrity digest, and the extracted command/keystroke text — so an auditor or
-- SME admin can find a session by who/what/when and by full-text over the
-- commands run, then open the heavy blob only for the one they want.
--
-- Cost discipline (5,000-SME fleet): the HEAVY replay blob stays in object
-- storage; only this light row + the FTS index live in Postgres. Prometheus
-- instruments stay aggregate-only (never per-tenant) — per-tenant attribution
-- is THIS row, which is cheap. The row is the durable forensic metadata: the
-- retention prune sweep (0062 + cmd/access-workflow-engine) tiers the blob away
-- while PRESERVING this row and the audit event, so search/forensic history
-- survives blob expiry.
--
-- It mirrors the GORM model models.SessionRecording, which is the source of
-- truth for the SQLite test path (AutoMigrate); the Postgres FTS index in 0061
-- is the only piece that lives solely in SQL (SQLite search falls back to LIKE).

CREATE TABLE IF NOT EXISTS session_recordings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id),
    session_id      UUID NOT NULL REFERENCES pam_sessions(id),
    target_id       UUID,
    operator        TEXT NOT NULL DEFAULT '',
    target_name     TEXT NOT NULL DEFAULT '',
    protocol        TEXT NOT NULL DEFAULT '',
    state           TEXT NOT NULL DEFAULT '',
    client_addr     TEXT NOT NULL DEFAULT '',
    started_at      TIMESTAMPTZ,
    ended_at        TIMESTAMPTZ,
    duration_ms     BIGINT NOT NULL DEFAULT 0 CHECK (duration_ms >= 0),
    command_count   INTEGER NOT NULL DEFAULT 0 CHECK (command_count >= 0),
    deny_count      INTEGER NOT NULL DEFAULT 0 CHECK (deny_count >= 0),
    frame_count     INTEGER NOT NULL DEFAULT 0 CHECK (frame_count >= 0),
    bytes           BIGINT NOT NULL DEFAULT 0 CHECK (bytes >= 0),
    truncated       BOOLEAN NOT NULL DEFAULT FALSE,
    replay_key      TEXT NOT NULL DEFAULT '',
    sha256          TEXT NOT NULL DEFAULT '',
    sha256_verified BOOLEAN NOT NULL DEFAULT FALSE,
    search_text     TEXT NOT NULL DEFAULT '',
    indexed_at      TIMESTAMPTZ,
    blob_pruned     BOOLEAN NOT NULL DEFAULT FALSE,
    blob_pruned_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ
);

-- One index row per session: the indexer upserts on this key (idempotent
-- re-index), so re-running the sweep over an already-indexed session updates in
-- place rather than duplicating.
CREATE UNIQUE INDEX IF NOT EXISTS uq_session_recordings_session
    ON session_recordings (workspace_id, session_id);

-- The default console listing is a tenant's own recordings newest-first; this
-- composite serves that scan directly. A partial expression is unnecessary —
-- every row carries a workspace_id.
CREATE INDEX IF NOT EXISTS idx_session_recordings_ws_started
    ON session_recordings (workspace_id, started_at DESC);

-- Faceted filters (operator / protocol / target) are equality-prefixed by
-- workspace, so these composite indexes keep each filter a cheap index scan
-- rather than a per-tenant table sweep.
CREATE INDEX IF NOT EXISTS idx_session_recordings_ws_operator
    ON session_recordings (workspace_id, operator);
CREATE INDEX IF NOT EXISTS idx_session_recordings_ws_protocol
    ON session_recordings (workspace_id, protocol);
CREATE INDEX IF NOT EXISTS idx_session_recordings_ws_target
    ON session_recordings (workspace_id, target_id);

-- The retention prune sweep scans for not-yet-pruned recordings whose end time
-- is older than the policy cutoff; this partial index keeps that sweep off the
-- already-tiered rows so a fleet-wide prune stays cheap even as history grows.
CREATE INDEX IF NOT EXISTS idx_session_recordings_prune
    ON session_recordings (workspace_id, ended_at)
    WHERE blob_pruned = FALSE;

-- Row-Level Security: session_recordings carries a workspace_id, so it joins the
-- 0024 tenant-isolation regime. RLS applies on the authenticated request path
-- (search/detail/stream handlers), where RequireTenant pins app.workspace_id and
-- the policy restricts a tenant to its OWN recordings — a privacy backstop
-- behind the explicit `WHERE workspace_id = ?`. The indexer and prune sweep run
-- UNSCOPED (no GUC) in the workflow engine, so the policy is permissive for them
-- and one sweep may index/tier rows for every workspace. app_current_workspace_id()
-- is defined in 0024.
ALTER TABLE session_recordings ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_recordings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON session_recordings;
CREATE POLICY tenant_isolation ON session_recordings
    USING (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id())
    WITH CHECK (app_current_workspace_id() IS NULL OR workspace_id = app_current_workspace_id());
