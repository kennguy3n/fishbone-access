-- 0061_session_recordings_fts: Postgres full-text search over executed commands.
--
-- Requirement: search a tenant's recordings by full text over the commands and
-- keystrokes executed in the session, cheaply, at 5,000 tenants and with NO new
-- infrastructure. Postgres FTS is the answer: a GIN index over
-- to_tsvector('english', search_text) turns the free-text query into an indexed
-- lookup instead of a per-tenant ILIKE table sweep.
--
-- The index is a FUNCTIONAL (expression) index rather than a stored tsvector
-- column: to_tsvector(regconfig, text) is IMMUTABLE, so the expression is
-- index-able directly, and the search service queries with the SAME expression
-- (to_tsvector('english', search_text) @@ plainto_tsquery('english', $1)) so the
-- planner uses this index. Keeping the tsvector out of the row also keeps the
-- light index row small — the searchable text is already in search_text.
--
-- This is the ONLY part of the recordings feature that is Postgres-specific and
-- lives solely in SQL: the GORM AutoMigrate test path (SQLite) has no tsvector,
-- so the search service falls back to a LIKE scan there. Production (Postgres)
-- always has this index.
--
-- A plain CREATE INDEX (NOT CONCURRENTLY) is correct here: this repo's migration
-- runner wraps each file in a single transaction, inside which CONCURRENTLY is
-- illegal. The table is new and empty at apply time, so the brief lock is a
-- non-event.

CREATE INDEX IF NOT EXISTS idx_session_recordings_fts
    ON session_recordings
    USING gin (to_tsvector('english', search_text));
