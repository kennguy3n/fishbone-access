//go:build integration

package tenancy

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/migrations"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

// This suite proves the 0018/0019 SQL migrations produce a schema the GORM
// model + Store operate on correctly ON POSTGRES — the gap a SQLite-only unit
// test cannot close (column names, CHECK constraints, ON CONFLICT, the set-based
// reconcile SQL). It applies the production migrations (not AutoMigrate) against
// a throwaway database, the same convention the other integration tests use.
func newPostgresStore(t *testing.T) (*gorm.DB, *Store) {
	t.Helper()
	dsn := os.Getenv("ACCESS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ACCESS_TEST_DATABASE_URL not set; skipping Postgres tenancy integration test")
	}
	ctx := context.Background()
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db handle: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	if _, err := sqlDB.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if _, err := migrations.Run(ctx, sqlDB); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	return db, NewStore(db)
}

func pgSeedWorkspace(t *testing.T, db *gorm.DB, createdAt time.Time) uuid.UUID {
	t.Helper()
	ws := &models.Workspace{
		Name:            "ws-" + uuid.NewString()[:8],
		IAMCoreTenantID: "tenant-" + uuid.NewString(),
		Plan:            "base",
	}
	if err := db.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	// Force created_at so the reconcile seed path can classify deterministically.
	if err := db.Model(&models.Workspace{}).Where("id = ?", ws.ID).
		Update("created_at", createdAt).Error; err != nil {
		t.Fatalf("backdate workspace: %v", err)
	}
	return ws.ID
}

func TestPostgresRecordActivityAndWake(t *testing.T) {
	db, store := newPostgresStore(t)
	clk := &fakeClock{t: time.Now().UTC()}
	store = store.WithClock(clk.now)
	ctx := context.Background()
	ws := pgSeedWorkspace(t, db, clk.now().Add(-time.Hour))

	woke, err := store.RecordActivity(ctx, ws, KindLogin)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if woke {
		t.Error("first activity should not wake")
	}

	// Drive to dormant via reconcile, then prove activity wakes it.
	clk.advance(20 * 24 * time.Hour)
	res, err := store.Reconcile(ctx, 14*24*time.Hour)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Hibernated != 1 {
		t.Fatalf("Hibernated = %d, want 1", res.Hibernated)
	}
	dormant, err := store.IsDormant(ctx, ws)
	if err != nil || !dormant {
		t.Fatalf("IsDormant = %v, %v; want true", dormant, err)
	}

	woke, err = store.RecordActivity(ctx, ws, KindAPI)
	if err != nil {
		t.Fatalf("record wake: %v", err)
	}
	if !woke {
		t.Fatal("activity must wake a dormant tenant")
	}
	dormant, _ = store.IsDormant(ctx, ws)
	if dormant {
		t.Error("tenant should be active after wake")
	}
}

// TestPostgresConcurrentWakeAndReconcile runs RecordActivity and Reconcile
// concurrently against the same just-dormant tenant and asserts the tenant is
// never left stuck dormant — the wake-vs-reconcile race the unit suite can only
// model sequentially (SQLite cannot do connection-concurrent writes). On
// Postgres the reconcile transaction row-locks the rows it updates, so the wake
// either commits its fresh last_activity_at before the sweep reads it (sweep
// won't hibernate) or serializes after the sweep and flips it back to active.
func TestPostgresConcurrentWakeAndReconcile(t *testing.T) {
	db, store := newPostgresStore(t)
	clk := &fakeClock{t: time.Now().UTC()}
	store = store.WithClock(clk.now)
	ctx := context.Background()
	ws := pgSeedWorkspace(t, db, clk.now().Add(-40*24*time.Hour))

	// Classify dormant first.
	if _, err := store.Reconcile(ctx, 14*24*time.Hour); err != nil {
		t.Fatalf("reconcile(seed dormant): %v", err)
	}
	if d, _ := store.IsDormant(ctx, ws); !d {
		t.Fatal("precondition: tenant should be dormant")
	}

	// Activity lands "now" concurrently with a sweep.
	clk.advance(time.Minute)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := store.RecordActivity(ctx, ws, KindAPI); err != nil {
			t.Errorf("concurrent RecordActivity: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := store.Reconcile(ctx, 14*24*time.Hour); err != nil {
			t.Errorf("concurrent Reconcile: %v", err)
		}
	}()
	wg.Wait()

	// A settling sweep must not re-hibernate: the recorded activity is fresh.
	if _, err := store.Reconcile(ctx, 14*24*time.Hour); err != nil {
		t.Fatalf("settling reconcile: %v", err)
	}
	if d, _ := store.IsDormant(ctx, ws); d {
		t.Fatal("tenant with fresh activity must not be left dormant after a concurrent sweep")
	}
}

func TestPostgresReconcileSeedsFromWorkspaces(t *testing.T) {
	db, store := newPostgresStore(t)
	now := time.Now().UTC()
	store = store.WithClock(func() time.Time { return now })
	ctx := context.Background()

	fresh := pgSeedWorkspace(t, db, now.Add(-24*time.Hour))
	stale := pgSeedWorkspace(t, db, now.Add(-40*24*time.Hour))

	res, err := store.Reconcile(ctx, 14*24*time.Hour)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Seeded != 2 {
		t.Fatalf("Seeded = %d, want 2", res.Seeded)
	}
	if d, _ := store.IsDormant(ctx, fresh); d {
		t.Error("fresh workspace should seed active")
	}
	if d, _ := store.IsDormant(ctx, stale); !d {
		t.Error("stale workspace should seed dormant")
	}
}

func TestPostgresBudgetOverridePersists(t *testing.T) {
	db, store := newPostgresStore(t)
	ctx := context.Background()
	ws := pgSeedWorkspace(t, db, time.Now().UTC())

	if err := store.SetBudget(ctx, TenantResourceBudget{
		WorkspaceID:        ws,
		Tier:               TierPro,
		MaxConcurrentSyncs: 7,
	}); err != nil {
		t.Fatalf("SetBudget: %v", err)
	}
	b, err := store.BudgetFor(ctx, ws, TierTrial)
	if err != nil {
		t.Fatalf("BudgetFor: %v", err)
	}
	if b.Tier != TierPro || b.MaxConcurrentSyncs != 7 || b.MaxPeriodicJobsPerHour != 60 {
		t.Errorf("budget = %+v, want pro tier with 7 concurrent syncs", b)
	}

	// Upsert again to prove ON CONFLICT updates rather than erroring.
	if err := store.SetBudget(ctx, TenantResourceBudget{
		WorkspaceID:        ws,
		Tier:               TierEnterprise,
		MaxConcurrentSyncs: 9,
	}); err != nil {
		t.Fatalf("SetBudget upsert: %v", err)
	}
	b, _ = store.BudgetFor(ctx, ws, TierTrial)
	if b.Tier != TierEnterprise || b.MaxConcurrentSyncs != 9 {
		t.Errorf("budget after upsert = %+v, want enterprise/9", b)
	}
}
