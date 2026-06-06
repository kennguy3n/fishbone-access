-- 0002_connector_secret_key_version
--
-- Record which per-workspace DEK version sealed each connector's secret
-- envelope. The envelope encryptor (internal/services/access) returns a key
-- version on every Encrypt and needs it back on Decrypt so a row sealed under
-- DEK v1 still opens after the workspace's DEK rotates to v2. Existing rows
-- were sealed under the first (v1) key, so default to 1.

ALTER TABLE access_connectors
    ADD COLUMN IF NOT EXISTS secret_key_version INT NOT NULL DEFAULT 1;
