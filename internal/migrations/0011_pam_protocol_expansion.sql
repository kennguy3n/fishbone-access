-- Workstream 1: PAM gateway protocol expansion.
--
-- The gateway grew from four proxied protocols (ssh, postgres, mysql, k8s-exec)
-- to ten by adding rdp, vnc, mongodb, redis, mssql and http ConnHandlers. The
-- 0005 schema left pam_targets.protocol / pam_sessions.protocol as free-form
-- TEXT, with the valid set enforced only in application code
-- (models.IsValidPAMProtocol / pam.validProtocol). This migration pins the same
-- invariant in the database via a CHECK constraint so a direct write or a future
-- code path cannot persist an unsupported protocol, and widens the allowed set
-- to the full ten.
--
-- The constraints are (re)created idempotently: each is dropped if present and
-- re-added, so the migration is safe to re-run and trivially extended when a
-- later workstream adds another protocol.

ALTER TABLE pam_targets DROP CONSTRAINT IF EXISTS chk_pam_targets_protocol;
ALTER TABLE pam_targets
    ADD CONSTRAINT chk_pam_targets_protocol
    CHECK (protocol IN (
        'ssh', 'postgres', 'mysql', 'k8s-exec',
        'rdp', 'vnc', 'mongodb', 'redis', 'mssql', 'http'
    ));

ALTER TABLE pam_sessions DROP CONSTRAINT IF EXISTS chk_pam_sessions_protocol;
ALTER TABLE pam_sessions
    ADD CONSTRAINT chk_pam_sessions_protocol
    CHECK (protocol IN (
        'ssh', 'postgres', 'mysql', 'k8s-exec',
        'rdp', 'vnc', 'mongodb', 'redis', 'mssql', 'http'
    ));
