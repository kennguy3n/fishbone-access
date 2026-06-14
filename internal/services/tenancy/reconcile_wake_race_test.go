package tenancy

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// These tests audit the interplay between the reconcile sweep (which marks idle
// tenants dormant) and a wake driven by real activity (RecordActivity), in both
// orderings. The guarantee under test: hibernation may DEFER work for a
// confidently-dormant tenant, but a tenant with fresh activity must never be
// left dormant and its very next periodic cycle must run — there is no
// missed-wake window.
//
// The orderings are exercised sequentially because that is exactly how the
// database serializes them: reconcile runs its three statements in one
// transaction that row-locks the rows it touches, so a concurrent RecordActivity
// on the same workspace either commits its freshness write before the sweep
// reads (the wake-then-reconcile case) or blocks until the sweep commits and
// then observes the post-sweep state (the reconcile-then-wake case). The
// sequential tests model those two committed interleavings. The truly
// concurrent goroutine version lives in the Postgres integration suite
// (store_integration_test.go), because real row-locking is the mechanism that
// serializes the interleaving — SQLite's in-memory driver cannot model
// connection-concurrent writes.

const raceIdleThreshold = 14 * 24 * time.Hour

// TestWakeThenReconcile_DoesNotReHibernate proves a tenant that just woke is not
// immediately re-hibernated by the next reconcile sweep: the wake stamped
// last_activity_at=now, so the sweep's hibernate predicate (last_activity_at <
// cutoff) cannot match it.
func TestWakeThenReconcile_DoesNotReHibernate(t *testing.T) {
	db := newTestDB(t)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	clk := &fakeClock{t: now}
	store := NewStore(db).WithClock(clk.now)
	svc := NewService(db, Config{Enabled: true, IdleThreshold: raceIdleThreshold}).WithClock(clk.now)
	ctx := context.Background()
	ws := uuid.New()
	seedWorkspace(t, db, ws, now.Add(-30*24*time.Hour)) // stale trial

	// Sweep → dormant; gate skips.
	if _, err := store.Reconcile(ctx, raceIdleThreshold); err != nil {
		t.Fatalf("reconcile(1): %v", err)
	}
	assertState(t, store, ws, StateDormant)
	assertRun(t, svc, ws, false)

	// Real activity wakes it.
	woke, err := store.RecordActivity(ctx, ws, KindAPI)
	if err != nil {
		t.Fatalf("record wake: %v", err)
	}
	if !woke {
		t.Fatal("activity must wake the dormant tenant")
	}

	// A reconcile one interval later (still well within the idle threshold of
	// the wake) must NOT re-hibernate the freshly active tenant.
	clk.advance(time.Hour)
	res, err := store.Reconcile(ctx, raceIdleThreshold)
	if err != nil {
		t.Fatalf("reconcile(2): %v", err)
	}
	if res.Hibernated != 0 {
		t.Fatalf("reconcile re-hibernated a just-woken tenant: Hibernated=%d", res.Hibernated)
	}
	assertState(t, store, ws, StateActive)
	assertRun(t, svc, ws, true)
}

// TestReconcileThenWake_WakesPromptly proves there is no missed-wake window: the
// instant a dormant tenant records activity it is active again and its gate
// flips to run, without waiting for the (slower) reconcile interval.
func TestReconcileThenWake_WakesPromptly(t *testing.T) {
	db := newTestDB(t)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	clk := &fakeClock{t: now}
	store := NewStore(db).WithClock(clk.now)
	svc := NewService(db, Config{Enabled: true, IdleThreshold: raceIdleThreshold}).WithClock(clk.now)
	ctx := context.Background()
	ws := uuid.New()
	seedWorkspace(t, db, ws, now.Add(-30*24*time.Hour))

	if _, err := store.Reconcile(ctx, raceIdleThreshold); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	assertRun(t, svc, ws, false) // dormant: gate skips

	woke, err := store.RecordActivity(ctx, ws, KindLogin)
	if err != nil {
		t.Fatalf("record wake: %v", err)
	}
	if !woke {
		t.Fatal("activity on a dormant tenant must report a wake")
	}
	// Immediately (no further reconcile): the very next gate read must run.
	assertRun(t, svc, ws, true)
}

// TestReconcileBackstopWakesOnFreshActivity proves the sweep's step-3 wake
// backstop: if a tenant is dormant but its recorded activity has caught up to
// at/after the cutoff (e.g. activity landed between sweeps), the sweep itself
// flips it back to active rather than leaving it stuck dormant.
func TestReconcileBackstopWakesOnFreshActivity(t *testing.T) {
	db := newTestDB(t)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	clk := &fakeClock{t: now}
	store := NewStore(db).WithClock(clk.now)
	ctx := context.Background()
	ws := uuid.New()
	seedWorkspace(t, db, ws, now.Add(-30*24*time.Hour))

	if _, err := store.Reconcile(ctx, raceIdleThreshold); err != nil {
		t.Fatalf("reconcile(1): %v", err)
	}
	assertState(t, store, ws, StateDormant)

	// Simulate activity that refreshed last_activity_at while dormant but did
	// not run the wake transition (e.g. a partial/older code path) — the sweep
	// must still rescue it.
	if err := db.Model(&TenantActivity{}).Where("workspace_id = ?", ws).
		Update("last_activity_at", clk.now()).Error; err != nil {
		t.Fatalf("refresh activity: %v", err)
	}
	res, err := store.Reconcile(ctx, raceIdleThreshold)
	if err != nil {
		t.Fatalf("reconcile(2): %v", err)
	}
	if res.Woken != 1 {
		t.Fatalf("backstop Woken=%d, want 1", res.Woken)
	}
	assertState(t, store, ws, StateActive)
}
