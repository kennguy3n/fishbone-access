package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Row-Level Security (RLS) tenant isolation.
//
// The control plane scopes every tenant query with an explicit
// `WHERE workspace_id = ?`. That is the primary isolation mechanism, but it is
// only as strong as the discipline of 200+ hand-written call sites: a single
// forgotten clause leaks one tenant's rows to another. RLS is the database-tier
// backstop that makes that class of bug non-exploitable.
//
// Mechanism: migration 0024 enables (and FORCEs) RLS on every workspace-scoped
// table with a `tenant_isolation` policy keyed on the `app.workspace_id` GUC.
// This file is the other half — it sets that GUC, per request, on the exact
// connection a query runs on.
//
// Why a connection hook and not `SET LOCAL` in a transaction: GORM hands most
// reads to database/sql outside an explicit transaction, and the pool hands a
// query whichever connection is free. The pgx stdlib driver lets us run a
// callback (a) just after a connection is opened and (b) before a pooled
// connection is reused for the next operation — both with that operation's
// context. We read the workspace id off the context and pin the GUC on the
// connection there, so it is correct for the statement (and any rows it
// streams) regardless of transaction boundaries, and is overwritten on the next
// checkout before another tenant can observe it.
//
// Fail-open-when-unset is deliberate: background workers, schedulers and the
// migration runner legitimately operate across workspaces and run with no
// workspace on their context, so they set the GUC to '' and the policy lets
// them through. The policy strictly enforces isolation only when a workspace IS
// set — which is every authenticated request path (RequireTenant injects it).
// So RLS closes the "missing WHERE in a request handler" hole without breaking
// cross-tenant background work. The periodic full-tenant sweeps remain trusted.
//
// IMPORTANT operational note: RLS (even FORCEd) is bypassed by Postgres
// superusers and roles with BYPASSRLS. For RLS to take effect the control plane
// MUST connect as an ordinary role (not the superuser used for migrations). See
// deploy/SCALE_SIZING.md.

// workspaceCtxKey is the unexported context key under which the resolved tenant
// workspace id travels from RequireTenant down to the database connection hook.
type workspaceCtxKey struct{}

// WithWorkspaceID returns a context carrying the tenant workspace id so that
// queries run on its behalf are pinned to that tenant by RLS. A Nil id is a
// no-op (the resulting context scopes nothing, i.e. a cross-tenant/worker
// context). It is set by middleware.RequireTenant on every authenticated
// request and may be set explicitly by background callers that want their work
// RLS-scoped to one tenant.
func WithWorkspaceID(ctx context.Context, id uuid.UUID) context.Context {
	if id == uuid.Nil {
		return ctx
	}
	return context.WithValue(ctx, workspaceCtxKey{}, id)
}

// WorkspaceIDFromContext returns the workspace id previously stored by
// WithWorkspaceID, and false when none is present.
func WorkspaceIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	v, ok := ctx.Value(workspaceCtxKey{}).(uuid.UUID)
	if !ok || v == uuid.Nil {
		return uuid.Nil, false
	}
	return v, true
}

// workspaceGUCValue is the string the app.workspace_id GUC is set to for ctx:
// the workspace UUID when one is present, or "" for an unscoped (worker/admin)
// context. The empty string is what the RLS policy treats as "not scoped".
func workspaceGUCValue(ctx context.Context) string {
	if id, ok := WorkspaceIDFromContext(ctx); ok {
		return id.String()
	}
	return ""
}

// setWorkspaceGUCSQL pins the per-connection tenant GUC. is_local=false (the
// third arg) makes it a session setting on this physical connection rather than
// a transaction-local one, so it governs statements run outside an explicit
// transaction too; it is rewritten on every connection checkout below, so it
// never outlives the operation that set it.
const setWorkspaceGUCSQL = `SELECT set_config('app.workspace_id', $1, false)`

// applyWorkspaceGUC sets app.workspace_id on conn from ctx. It runs as the pgx
// AfterConnect (new connection) and ResetSession (connection reuse) hook, so
// every operation observes exactly its own context's workspace and never a
// previous borrower's.
func applyWorkspaceGUC(ctx context.Context, conn *pgx.Conn) error {
	if _, err := conn.Exec(ctx, setWorkspaceGUCSQL, workspaceGUCValue(ctx)); err != nil {
		return fmt.Errorf("database: set tenant guc: %w", err)
	}
	return nil
}

// openPostgresRLS builds a GORM handle whose underlying database/sql pool sets
// the RLS tenant GUC from each operation's context. It is the production Open
// path; the GUC hook is a no-op for callers that pass an unscoped context.
func openPostgresRLS(dsn string, cfg *gorm.Config) (*gorm.DB, error) {
	connConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("database: parse dsn: %w", err)
	}
	connector := stdlib.GetConnector(*connConfig,
		stdlib.OptionAfterConnect(applyWorkspaceGUC),
		stdlib.OptionResetSession(applyWorkspaceGUC),
	)
	sqlDB := sql.OpenDB(connector)
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), cfg)
	if err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("database: open postgres: %w", err)
	}
	return db, nil
}
