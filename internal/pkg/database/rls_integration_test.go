//go:build integration

package database_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/migrations"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

// TestRLSTenantIsolation proves the database-tier backstop: with RLS enabled by
// migration 0024 and the app.workspace_id GUC pinned per request by Open's
// connection hooks, a query that FORGETS its `WHERE workspace_id = ?` clause
// still cannot observe or mutate another tenant's rows — while an unscoped
// (worker) context retains full cross-tenant access.
//
// It runs as an ordinary, non-superuser role because Postgres never applies RLS
// to superusers or BYPASSRLS roles — the same property the control plane relies
// on in production.
func TestRLSTenantIsolation(t *testing.T) {
	superDSN := os.Getenv("ACCESS_TEST_DATABASE_URL")
	if superDSN == "" {
		t.Skip("ACCESS_TEST_DATABASE_URL not set; skipping RLS integration test")
	}
	ctx := context.Background()

	// Privileged handle: reset schema, apply migrations, provision the app role.
	super, err := database.Open(superDSN)
	if err != nil {
		t.Fatalf("open super: %v", err)
	}
	superSQL, err := super.DB()
	if err != nil {
		t.Fatalf("super sql handle: %v", err)
	}
	t.Cleanup(func() { _ = superSQL.Close() })

	if _, err := superSQL.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if _, err := migrations.Run(ctx, superSQL); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	provisionAppRole(t, superSQL)

	// Seed two tenants with one policy row each, via the superuser handle (which
	// bypasses RLS) so the fixture is independent of the behaviour under test.
	wsA := seedWorkspacePolicy(t, super, "tenant-a", "policy-a")
	wsB := seedWorkspacePolicy(t, super, "tenant-b", "policy-b")

	// App handle connects as the non-superuser role, so RLS is in force.
	app, err := database.Open(appRoleDSN(t, superDSN))
	if err != nil {
		t.Fatalf("open app: %v", err)
	}
	appSQL, err := app.DB()
	if err != nil {
		t.Fatalf("app sql handle: %v", err)
	}
	t.Cleanup(func() { _ = appSQL.Close() })

	ctxA := database.WithWorkspaceID(ctx, wsA)
	ctxB := database.WithWorkspaceID(ctx, wsB)

	// 1. Unscoped SELECT (the "forgot the WHERE clause" bug) under tenant A sees
	//    ONLY tenant A's row — RLS filtered tenant B out transparently.
	if got := countPolicies(t, app, ctxA); got != 1 {
		t.Fatalf("tenant A unscoped count = %d, want 1 (RLS should hide tenant B)", got)
	}
	if got := countPolicies(t, app, ctxB); got != 1 {
		t.Fatalf("tenant B unscoped count = %d, want 1", got)
	}

	// 2. Tenant A cannot read tenant B's row even by its exact id.
	if n := countPolicyByWorkspace(t, app, ctxA, wsB); n != 0 {
		t.Fatalf("tenant A read of tenant B rows = %d, want 0", n)
	}

	// 3. Tenant A cannot INSERT a row tagged for tenant B (WITH CHECK).
	if err := insertPolicy(app, ctxA, wsB, "smuggled"); err == nil {
		t.Fatal("tenant A inserting a tenant-B row succeeded; WITH CHECK should have blocked it")
	}

	// 4. Tenant A cannot UPDATE tenant B's row (0 rows affected, not an error).
	if n := updatePolicyName(t, app, ctxA, wsB); n != 0 {
		t.Fatalf("tenant A update of tenant B rows affected %d, want 0", n)
	}

	// 5. An unscoped (worker) context retains full cross-tenant visibility, so
	//    background sweeps are not broken by the policy.
	if got := countPolicies(t, app, ctx); got != 2 {
		t.Fatalf("unscoped worker count = %d, want 2 (both tenants visible)", got)
	}
}

// TestRLSPgxPoolTenantIsolation proves the same database-tier backstop holds on
// the pgxpool path (OpenPool), not just the GORM pool: a query issued through a
// *pgxpool.Pool with a workspace-scoped context sees only that tenant's rows,
// and an unscoped (worker) context retains cross-tenant visibility. This guards
// the path the workspace-config and audit repositories use, and any future
// tenant-scoped query added on it.
func TestRLSPgxPoolTenantIsolation(t *testing.T) {
	superDSN := os.Getenv("ACCESS_TEST_DATABASE_URL")
	if superDSN == "" {
		t.Skip("ACCESS_TEST_DATABASE_URL not set; skipping RLS integration test")
	}
	ctx := context.Background()

	super, err := database.Open(superDSN)
	if err != nil {
		t.Fatalf("open super: %v", err)
	}
	superSQL, err := super.DB()
	if err != nil {
		t.Fatalf("super sql handle: %v", err)
	}
	t.Cleanup(func() { _ = superSQL.Close() })

	if _, err := superSQL.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if _, err := migrations.Run(ctx, superSQL); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	provisionAppRole(t, superSQL)

	wsA := seedWorkspacePolicy(t, super, "pgx-tenant-a", "pgx-policy-a")
	seedWorkspacePolicy(t, super, "pgx-tenant-b", "pgx-policy-b")

	// Connect the pool as the non-superuser role so RLS is in force.
	pool, err := database.OpenPool(ctx, appRoleDSN(t, superDSN), 0, 0, 0)
	if err != nil {
		t.Fatalf("open pgx pool: %v", err)
	}
	t.Cleanup(pool.Close)

	countPolicies := func(ctx context.Context) int64 {
		t.Helper()
		var n int64
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM policies`).Scan(&n); err != nil {
			t.Fatalf("pgx count policies: %v", err)
		}
		return n
	}

	// Scoped to tenant A, an unscoped SELECT (no WHERE) sees only A's row.
	if got := countPolicies(database.WithWorkspaceID(ctx, wsA)); got != 1 {
		t.Fatalf("pgx tenant A unscoped count = %d, want 1 (RLS should hide tenant B)", got)
	}
	// An unscoped worker context still sees both tenants.
	if got := countPolicies(ctx); got != 2 {
		t.Fatalf("pgx unscoped worker count = %d, want 2 (both tenants visible)", got)
	}
}

// provisionAppRole creates (idempotently) a non-superuser login role and grants
// it the table/function privileges the control plane uses, so the test can
// exercise RLS as production does. Grants run after migrations because the
// schema reset dropped the prior tables they referenced.
func provisionAppRole(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	stmts := []string{
		fmt.Sprintf(`DO $$ BEGIN
			IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '%[1]s') THEN
				CREATE ROLE %[1]s LOGIN PASSWORD '%[2]s';
			END IF;
		END $$;`, appRoleName, appRolePassword),
		fmt.Sprintf(`GRANT USAGE ON SCHEMA public TO %s`, appRoleName),
		fmt.Sprintf(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %s`, appRoleName),
		fmt.Sprintf(`GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO %s`, appRoleName),
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil {
			t.Fatalf("provision app role (%.40s...): %v", s, err)
		}
	}
}

func seedWorkspacePolicy(t *testing.T, db *gorm.DB, tenant, policyName string) uuid.UUID {
	t.Helper()
	var wsIDStr string
	if err := db.Raw(
		`INSERT INTO workspaces (name, iam_core_tenant_id) VALUES (?, ?) RETURNING id::text`,
		tenant, tenant,
	).Scan(&wsIDStr).Error; err != nil {
		t.Fatalf("seed workspace %s: %v", tenant, err)
	}
	wsID, err := uuid.Parse(wsIDStr)
	if err != nil {
		t.Fatalf("parse workspace id %q: %v", wsIDStr, err)
	}
	if err := db.Exec(
		`INSERT INTO policies (workspace_id, name) VALUES (?, ?)`, wsID, policyName,
	).Error; err != nil {
		t.Fatalf("seed policy %s: %v", policyName, err)
	}
	return wsID
}

func countPolicies(t *testing.T, db *gorm.DB, ctx context.Context) int64 {
	t.Helper()
	var n int64
	if err := db.WithContext(ctx).Raw(`SELECT count(*) FROM policies`).Scan(&n).Error; err != nil {
		t.Fatalf("count policies: %v", err)
	}
	return n
}

func countPolicyByWorkspace(t *testing.T, db *gorm.DB, ctx context.Context, ws uuid.UUID) int64 {
	t.Helper()
	var n int64
	if err := db.WithContext(ctx).Raw(`SELECT count(*) FROM policies WHERE workspace_id = ?`, ws).Scan(&n).Error; err != nil {
		t.Fatalf("count policies by ws: %v", err)
	}
	return n
}

func insertPolicy(db *gorm.DB, ctx context.Context, ws uuid.UUID, name string) error {
	return db.WithContext(ctx).Exec(`INSERT INTO policies (workspace_id, name) VALUES (?, ?)`, ws, name).Error
}

func updatePolicyName(t *testing.T, db *gorm.DB, ctx context.Context, ws uuid.UUID) int64 {
	t.Helper()
	res := db.WithContext(ctx).Exec(`UPDATE policies SET name = 'hijacked' WHERE workspace_id = ?`, ws)
	if res.Error != nil {
		t.Fatalf("update policy: %v", res.Error)
	}
	return res.RowsAffected
}

// appRoleDSN rewrites superDSN to authenticate as the non-superuser app role.
func appRoleDSN(t *testing.T, superDSN string) string {
	t.Helper()
	u, err := url.Parse(superDSN)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.User = url.UserPassword(appRoleName, appRolePassword)
	return u.String()
}

const (
	appRoleName     = "rls_test_app"
	appRolePassword = "rls_test_app"
)
