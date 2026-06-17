-- WebAuthn/FIDO2 step-up MFA: enrolled authenticators and in-flight ceremony
-- challenges, consumed by the WebAuthn step-up verifier (internal/services/mfa)
-- alongside the existing TOTP verifier behind the composite step-up gate.
--
-- Two tables, both workspace-scoped for tenant isolation (mirroring
-- user_totp_secrets / pam_totp_used_codes from 0015):
--
--   webauthn_credentials -- one enrolled authenticator (security key or platform
--                           authenticator) per row. credential_id is the raw
--                           lookup key WebAuthn selects on; sealed holds the
--                           AES-256-GCM envelope of the full webauthn.Credential
--                           record (public key never stored in plaintext),
--                           AAD-bound to (workspace, user, credential_id). The
--                           sign_count / clone_warning columns mirror the
--                           authenticator's monotonic counter and the library's
--                           clone-detection verdict for observability.
--   webauthn_challenges  -- the server-issued, single-use, short-lived ceremony
--                           state between a Begin* call and its Finish/Verify.
--                           Keyed (workspace_id, user_id, ceremony) so one
--                           registration and one authentication challenge are
--                           outstanding per user; re-issued (upserted) on Begin
--                           and atomically deleted on use. The challenge is a
--                           nonce (not a long-term secret), stored as plain JSON.
--
-- NOTE: numbered 0075 to follow the discovery/HA range (0070–0072, 0080) and to
-- sit within the 0063–0079 band declared reserved in
-- reserved_parallel_ranges_0080.go, so the contiguity check stays green while
-- sibling feature branches backfill the surrounding numbers. A
-- present-and-reserved version is harmless (the linter treats it as present).

-- --- Enrolled WebAuthn authenticators ---------------------------------------
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id  UUID         NOT NULL REFERENCES workspaces(id),
    user_id       VARCHAR(255) NOT NULL,
    -- Raw (non-encoded) credential id the authenticator returns; the lookup key
    -- WebAuthn uses to pick which stored public key verifies an assertion.
    credential_id BYTEA        NOT NULL,
    -- Base64 AES-256-GCM envelope of the full webauthn.Credential JSON (public
    -- key, attestation, transports, flags, counter), sealed with the DEK and
    -- AAD-bound to (workspace_id, user_id, credential_id). Never plaintext.
    sealed        TEXT         NOT NULL,
    friendly_name VARCHAR(255),
    -- Mirror of the authenticator's monotonic signature counter and the
    -- library's clone-detection verdict (the sealed record is the source of
    -- truth; these surface them for admin display without an open/decrypt).
    sign_count    BIGINT       NOT NULL DEFAULT 0,
    clone_warning BOOLEAN      NOT NULL DEFAULT false,
    aaguid        BYTEA,
    last_used_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at    TIMESTAMPTZ
);

-- Lists a user's enrolled authenticators and loads them for an assertion.
CREATE INDEX IF NOT EXISTS idx_webauthn_cred_ws_user
    ON webauthn_credentials(workspace_id, user_id);

-- A credential id is unique within a (workspace, user): the same authenticator
-- enrols once, and the verifier resolves an assertion's credential id to exactly
-- one stored public key.
CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_cred_ws_credid
    ON webauthn_credentials(workspace_id, credential_id);

-- --- In-flight ceremony challenges ------------------------------------------
-- Composite primary key (workspace_id, user_id, ceremony) keeps at most one
-- outstanding registration and one authentication challenge per user: Begin*
-- upserts the row, and Finish/Verify atomically deletes it (single-use). An
-- expired or already-consumed challenge is rejected (fail closed).
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    workspace_id UUID         NOT NULL REFERENCES workspaces(id),
    user_id      VARCHAR(255) NOT NULL,
    ceremony     VARCHAR(20)  NOT NULL,
    -- JSON of webauthn.SessionData (challenge nonce, allowed credential ids,
    -- user-verification requirement). A nonce, not a long-term secret, so it is
    -- stored in the clear; possession alone cannot forge an assertion.
    session_data BYTEA        NOT NULL,
    expires_at   TIMESTAMPTZ  NOT NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id, ceremony)
);

-- Drives the background sweep of expired, never-consumed challenges
-- (DELETE WHERE expires_at < now()).
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires_at
    ON webauthn_challenges(expires_at);
