//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"

	// Register the pgx database/sql driver under the name "pgx".
	_ "github.com/jackc/pgx/v5/stdlib"
)

// openTestDB connects to the Postgres named by ACCESS_TEST_DATABASE_URL, or
// skips when it is unset so the default `go test` run stays hermetic.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("ACCESS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ACCESS_TEST_DATABASE_URL not set; skipping Postgres migration integration test")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	return db
}

// dropSchema resets public to a clean slate so the test is repeatable.
func dropSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
}

func TestRunAppliesAndIsIdempotent(t *testing.T) {
	db := openTestDB(t)
	dropSchema(t, db)
	ctx := context.Background()

	applied, err := Run(ctx, db)
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if len(applied) == 0 {
		t.Fatal("first Run applied no migrations")
	}

	// The ten core tables must exist.
	for _, table := range []string{
		"workspaces", "teams", "team_members", "access_connectors", "access_jobs",
		"access_requests", "access_grants", "access_reviews", "policies", "audit_events",
	} {
		var exists bool
		if err := db.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`, table,
		).Scan(&exists); err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if !exists {
			t.Errorf("table %q was not created", table)
		}
	}

	// A second Run must be a no-op (idempotent).
	applied2, err := Run(ctx, db)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if len(applied2) != 0 {
		t.Errorf("second Run applied %v, want none", applied2)
	}
}

// TestConcurrentRunsDoNotRace simulates many replicas booting simultaneously.
// Without the advisory lock, racing INSERTs into schema_migrations would crash
// the losers on the primary-key conflict; with it, exactly one runner applies
// the migrations and the rest observe them already applied.
func TestConcurrentRunsDoNotRace(t *testing.T) {
	db := openTestDB(t)
	dropSchema(t, db)
	ctx := context.Background()

	const replicas = 8
	var (
		wg          sync.WaitGroup
		mu          sync.Mutex
		errs        []error
		appliedRuns int
	)
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			applied, err := Run(ctx, db)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
			}
			if len(applied) > 0 {
				appliedRuns++
			}
		}()
	}
	wg.Wait()

	if len(errs) != 0 {
		t.Fatalf("concurrent Run errors (advisory lock should prevent these): %v", errs)
	}
	if appliedRuns != 1 {
		t.Errorf("exactly one runner should apply migrations, got %d", appliedRuns)
	}
}
