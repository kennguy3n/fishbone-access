-- Track the iam-core SSO Connection a connector federates, so that SSO
-- federation can be torn down when the connector is disconnected (no orphaned
-- iam-core connections) and re-configuration is idempotent. Empty string means
-- the connector has no SSO connection configured.
--
-- Lock-safe: a NOT NULL ADD COLUMN carries a DEFAULT, so existing rows are
-- backfilled without a table rewrite blocking writers (migrate-lint
-- RuleAddColumnNotNull).
ALTER TABLE access_connectors
    ADD COLUMN IF NOT EXISTS sso_connection_id TEXT NOT NULL DEFAULT '';
