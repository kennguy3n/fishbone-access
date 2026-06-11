package tenancy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

// newTestDB opens an in-memory SQLite DB with the core schema (workspaces, …)
// plus the tenancy tables auto-migrated, mirroring the production schema the
// 0018/0019 SQL migrations create.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("core migrate: %v", err)
	}
	if err := NewStore(db).Migrate(); err != nil {
		t.Fatalf("tenancy migrate: %v", err)
	}
	return db
}

// seedWorkspace inserts a workspace with an explicit creation time so the
// reconcile sweep's "seed from created_at" path can be driven deterministically.
func seedWorkspace(t *testing.T, db *gorm.DB, id uuid.UUID, createdAt time.Time) {
	t.Helper()
	ws := models.Workspace{
		Base:            models.Base{ID: id, CreatedAt: createdAt, UpdatedAt: createdAt},
		Name:            "ws-" + id.String()[:8],
		IAMCoreTenantID: "tenant-" + id.String(),
	}
	if err := db.Create(&ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
}

// fakeClock is a movable clock for deterministic idle-threshold tests.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestRecordActivityCreatesRowThenWakes(t *testing.T) {
	db := newTestDB(t)
	clk := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	store := NewStore(db).WithClock(clk.now)
	ctx := context.Background()
	ws := uuid.New()

	// First activity creates the row, active, and does NOT report a wake (it
	// was never dormant).
	woke, err := store.RecordActivity(ctx, ws, KindLogin)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if woke {
		t.Error("first activity should not report a wake")
	}
	row, err := store.GetActivity(ctx, ws)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if row.State != StateActive || row.LastActivityKind != KindLogin {
		t.Errorf("row = %+v, want active/login", row)
	}
	if !row.LastActivityAt.Equal(clk.now()) {
		t.Errorf("last_activity_at = %s, want %s", row.LastActivityAt, clk.now())
	}

	// Force dormancy, then activity must report exactly one wake and set WokenAt.
	if err := db.Model(&TenantActivity{}).Where("workspace_id = ?", ws).
		Update("state", StateDormant).Error; err != nil {
		t.Fatalf("force dormant: %v", err)
	}
	clk.advance(time.Minute)
	woke, err = store.RecordActivity(ctx, ws, KindAPI)
	if err != nil {
		t.Fatalf("record(2): %v", err)
	}
	if !woke {
		t.Fatal("activity on a dormant tenant must report a wake")
	}
	row, _ = store.GetActivity(ctx, ws)
	if row.State != StateActive {
		t.Errorf("state = %q, want active after wake", row.State)
	}
	if row.WokenAt == nil || !row.WokenAt.Equal(clk.now()) {
		t.Errorf("WokenAt = %v, want %s", row.WokenAt, clk.now())
	}

	// A second activity while already active reports no wake (idempotent).
	woke, _ = store.RecordActivity(ctx, ws, KindAPI)
	if woke {
		t.Error("activity on an active tenant should not report a wake")
	}
}

func TestReconcileSeedsAndClassifies(t *testing.T) {
	db := newTestDB(t)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	clk := &fakeClock{t: now}
	store := NewStore(db).WithClock(clk.now)
	ctx := context.Background()

	fresh := uuid.New()      // created yesterday → active
	staleTrial := uuid.New() // created 30d ago, never touched → dormant
	seedWorkspace(t, db, fresh, now.Add(-24*time.Hour))
	seedWorkspace(t, db, staleTrial, now.Add(-30*24*time.Hour))

	res, err := store.Reconcile(ctx, 14*24*time.Hour)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Seeded != 2 {
		t.Errorf("Seeded = %d, want 2", res.Seeded)
	}
	assertState(t, store, fresh, StateActive)
	assertState(t, store, staleTrial, StateDormant)

	// The seeded dormant trial should have hibernated_at stamped.
	row, _ := store.GetActivity(ctx, staleTrial)
	if row.HibernatedAt == nil {
		t.Error("seeded dormant row should have HibernatedAt set")
	}
	if row.LastActivityKind != KindProvisioned {
		t.Errorf("seeded kind = %q, want provisioned", row.LastActivityKind)
	}

	// Re-running is idempotent: no new seeds, no transitions.
	res, err = store.Reconcile(ctx, 14*24*time.Hour)
	if err != nil {
		t.Fatalf("reconcile(2): %v", err)
	}
	if res.Seeded != 0 || res.Hibernated != 0 || res.Woken != 0 {
		t.Errorf("second reconcile changed state: %+v", res)
	}
}

func TestReconcileHibernatesAfterIdleAndWakesOnActivity(t *testing.T) {
	db := newTestDB(t)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	clk := &fakeClock{t: now}
	store := NewStore(db).WithClock(clk.now)
	svc := NewService(db, Config{Enabled: true, IdleThreshold: 14 * 24 * time.Hour}).WithClock(clk.now)
	ctx := context.Background()
	ws := uuid.New()
	seedWorkspace(t, db, ws, now.Add(-1*time.Hour))

	// Active after first activity; gate says run.
	if _, err := store.RecordActivity(ctx, ws, KindAPI); err != nil {
		t.Fatalf("record: %v", err)
	}
	assertRun(t, svc, ws, true)

	// Idle past the threshold, then reconcile → dormant; gate says skip.
	clk.advance(15 * 24 * time.Hour)
	res, err := store.Reconcile(ctx, 14*24*time.Hour)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Hibernated != 1 {
		t.Errorf("Hibernated = %d, want 1", res.Hibernated)
	}
	assertRun(t, svc, ws, false)

	// Activity wakes it; gate says run again. Wake latency is bounded by the
	// activity path, not the (slower) reconcile interval.
	woke, err := store.RecordActivity(ctx, ws, KindAPI)
	if err != nil {
		t.Fatalf("record wake: %v", err)
	}
	if !woke {
		t.Fatal("expected wake on post-dormancy activity")
	}
	assertRun(t, svc, ws, true)
}

func TestShouldRunPeriodicFailOpenAndDisabled(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ws := uuid.New()

	// Unknown tenant (no row) → fail-open run.
	svc := NewService(db, Config{Enabled: true, IdleThreshold: time.Hour})
	assertRun(t, svc, ws, true)

	// Disabled hibernation → always run, even for a dormant row.
	store := NewStore(db)
	if _, err := store.RecordActivity(ctx, ws, KindAPI); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := db.Model(&TenantActivity{}).Where("workspace_id = ?", ws).
		Update("state", StateDormant).Error; err != nil {
		t.Fatalf("force dormant: %v", err)
	}
	disabled := NewService(db, Config{Enabled: false, IdleThreshold: time.Hour})
	assertRun(t, disabled, ws, true)

	// Enabled + dormant → skip.
	enabled := NewService(db, Config{Enabled: true, IdleThreshold: time.Hour})
	assertRun(t, enabled, ws, false)
}

func TestReconcileRejectsNonPositiveThreshold(t *testing.T) {
	db := newTestDB(t)
	if _, err := NewStore(db).Reconcile(context.Background(), 0); err == nil {
		t.Fatal("expected error for non-positive idle threshold")
	}
}

func TestRecordActivityRejectsNilWorkspace(t *testing.T) {
	db := newTestDB(t)
	if _, err := NewStore(db).RecordActivity(context.Background(), uuid.Nil, KindAPI); err == nil {
		t.Fatal("expected error for nil workspace id")
	}
}

func TestServiceConfigFallbacks(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, Config{Enabled: true})
	if svc.Config().IdleThreshold != 14*24*time.Hour {
		t.Errorf("IdleThreshold fallback = %s, want 336h", svc.Config().IdleThreshold)
	}
	if svc.Config().DefaultTier != TierTrial {
		t.Errorf("DefaultTier fallback = %q, want trial", svc.Config().DefaultTier)
	}
}
func assertState(t *testing.T, store *Store, ws uuid.UUID, want string) {
	t.Helper()
	row, err := store.GetActivity(context.Background(), ws)
	if err != nil {
		t.Fatalf("get %s: %v", ws, err)
	}
	if row.State != want {
		t.Errorf("state(%s) = %q, want %q", ws, row.State, want)
	}
}

func assertRun(t *testing.T, gate HibernationGate, ws uuid.UUID, want bool) {
	t.Helper()
	got, err := gate.ShouldRunPeriodic(context.Background(), ws)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("ShouldRunPeriodic(%s): %v", ws, err)
	}
	if got != want {
		t.Errorf("ShouldRunPeriodic(%s) = %v, want %v", ws, got, want)
	}
}
