-- 0071_discovery_stuck_onboard_index: partial index for the onboard self-heal.
--
-- The scheduled sweep heals assets left in the rare managed/target_id=NULL state
-- (a local-tx failure between PAM target creation and linkAssetTarget, or the
-- bind+link double-failure path) by re-linking them to their created target or
-- releasing the claim. To keep that pass cheap across the 5,000-tenant fleet,
-- the heal lookup must not scan every managed asset in a workspace (a busy
-- tenant accumulates thousands of managed rows). This PARTIAL index covers only
-- the handful of currently-stuck rows, so reconcileStuckOnboards' probe is an
-- index-only scan that returns ~0 rows on every healthy sweep.
--
-- Index-only (no new table) so no RLS policy block is required: discovered_assets
-- already carries tenant_isolation + FORCE ROW LEVEL SECURITY from 0070.
CREATE INDEX IF NOT EXISTS idx_discovered_assets_stuck_onboard
    ON discovered_assets (workspace_id, id)
    WHERE status = 'managed' AND target_id IS NULL;
