package usage

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	s := NewStore(db)
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

// TestStoreAdditiveUpsert proves the database-level UPSERT ADDS rather than
// overwrites: two flushes for the same (workspace, period, metric) — as two
// replicas would produce — sum into one row. This is the contract that makes
// the per-replica posture correct.
func TestStoreAdditiveUpsert(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	ws := uuid.New()
	period := "2026-06"

	if err := s.AddUsage(ctx, []Delta{{WorkspaceID: ws, Period: period, Metric: MetricAPIRequests, Count: 4}}); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if err := s.AddUsage(ctx, []Delta{{WorkspaceID: ws, Period: period, Metric: MetricAPIRequests, Count: 6}}); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	rows, err := s.GetUsage(ctx, ws, period)
	if err != nil {
		t.Fatalf("get usage: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1 (the two flushes collapsed into one row)", len(rows))
	}
	if rows[0].Count != 10 {
		t.Fatalf("count = %d, want 10 (4 + 6 added, not overwritten)", rows[0].Count)
	}
}

// TestStoreReadIsTenantScoped proves GetCurrentUsage returns only the asked-for
// workspace's rows even when other tenants share the period — the explicit
// workspace scope (RLS is the DB-tier backstop on Postgres).
func TestStoreReadIsTenantScoped(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	s := newTestStore(t).WithClock(func() time.Time { return now })
	ctx := context.Background()
	wsA, wsB := uuid.New(), uuid.New()
	period := PeriodOf(now)

	if err := s.AddUsage(ctx, []Delta{
		{WorkspaceID: wsA, Period: period, Metric: MetricAPIRequests, Count: 11},
		{WorkspaceID: wsB, Period: period, Metric: MetricAPIRequests, Count: 22},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rows, err := s.GetCurrentUsage(ctx, wsA)
	if err != nil {
		t.Fatalf("get current usage: %v", err)
	}
	if len(rows) != 1 || rows[0].WorkspaceID != wsA || rows[0].Count != 11 {
		t.Fatalf("tenant A current usage = %+v, want one row for A with count 11", rows)
	}
}

// TestStoreCurrentUsageUsesCurrentPeriod proves GetCurrentUsage reads the
// clock's period, so last month's row is not returned this month.
func TestStoreCurrentUsageUsesCurrentPeriod(t *testing.T) {
	clock := time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC)
	s := newTestStore(t).WithClock(func() time.Time { return clock })
	ctx := context.Background()
	ws := uuid.New()

	if err := s.AddUsage(ctx, []Delta{{WorkspaceID: ws, Period: PeriodOf(clock), Metric: MetricAPIRequests, Count: 9}}); err != nil {
		t.Fatalf("seed May: %v", err)
	}
	// Advance to June; the May row must not surface as "current".
	clock = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	rows, err := s.GetCurrentUsage(ctx, ws)
	if err != nil {
		t.Fatalf("get current usage: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("June current usage = %+v, want empty (the row belongs to May)", rows)
	}
}

// TestStoreEmptyAndMalformedBatches proves a no-op batch and malformed deltas
// are skipped rather than erroring or poisoning the row set.
func TestStoreEmptyAndMalformedBatches(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.AddUsage(ctx, nil); err != nil {
		t.Fatalf("nil batch: %v", err)
	}
	ws := uuid.New()
	if err := s.AddUsage(ctx, []Delta{
		{WorkspaceID: uuid.Nil, Period: "2026-06", Metric: MetricAPIRequests, Count: 5}, // bad ws
		{WorkspaceID: ws, Period: "", Metric: MetricAPIRequests, Count: 5},              // bad period
		{WorkspaceID: ws, Period: "2026-06", Metric: "", Count: 5},                      // bad metric
		{WorkspaceID: ws, Period: "2026-06", Metric: MetricAPIRequests, Count: 0},       // non-positive
		{WorkspaceID: ws, Period: "2026-06", Metric: MetricAPIRequests, Count: 3},       // the only valid one
	}); err != nil {
		t.Fatalf("mixed batch: %v", err)
	}
	rows, err := s.GetUsage(ctx, ws, "2026-06")
	if err != nil {
		t.Fatalf("get usage: %v", err)
	}
	if len(rows) != 1 || rows[0].Count != 3 {
		t.Fatalf("rows = %+v, want one row with count 3 (malformed deltas skipped)", rows)
	}
}
