package billing

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/tenancy"
	"github.com/kennguy3n/fishbone-access/internal/services/usage"
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

// TestPlanForMissingRowReturnsDefault proves an un-assigned tenant (no row, the
// common case) resolves to the default plan rather than erroring.
func TestPlanForMissingRowReturnsDefault(t *testing.T) {
	s := newTestStore(t)
	p, err := s.PlanFor(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("PlanFor: %v", err)
	}
	if p.Plan != DefaultPlanTier {
		t.Errorf("plan = %q, want default %q", p.Plan, DefaultPlanTier)
	}
	if _, ok := p.QuotaFor(usage.MetricAPIRequests); !ok {
		t.Error("default plan should define the api_requests quota")
	}
}

// TestSetPlanThenPlanForRoundTrips proves an assignment persists and resolves
// with its overrides applied over the plan default.
func TestSetPlanThenPlanForRoundTrips(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	ws := uuid.New()

	if err := s.SetPlan(ctx, TenantPlan{WorkspaceID: ws, Plan: tenancy.TierPro, APIRequestsIncluded: 42_000_000}); err != nil {
		t.Fatalf("SetPlan: %v", err)
	}
	p, err := s.PlanFor(ctx, ws)
	if err != nil {
		t.Fatalf("PlanFor: %v", err)
	}
	if p.Plan != tenancy.TierPro {
		t.Errorf("plan = %q, want pro", p.Plan)
	}
	q, _ := p.QuotaFor(usage.MetricAPIRequests)
	if q.Included != 42_000_000 {
		t.Errorf("included = %d, want overridden 42_000_000", q.Included)
	}
}

// TestSetPlanUpserts proves a second SetPlan updates the same row in place
// rather than inserting a duplicate (the workspace_id is the primary key).
func TestSetPlanUpserts(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	ws := uuid.New()

	if err := s.SetPlan(ctx, TenantPlan{WorkspaceID: ws, Plan: tenancy.TierBase}); err != nil {
		t.Fatalf("first SetPlan: %v", err)
	}
	if err := s.SetPlan(ctx, TenantPlan{WorkspaceID: ws, Plan: tenancy.TierEnterprise}); err != nil {
		t.Fatalf("second SetPlan: %v", err)
	}
	p, err := s.PlanFor(ctx, ws)
	if err != nil {
		t.Fatalf("PlanFor: %v", err)
	}
	if p.Plan != tenancy.TierEnterprise {
		t.Errorf("plan = %q, want enterprise after update", p.Plan)
	}
}

// TestSetPlanNormalizesAndClamps proves an unknown tier coerces to the default
// and negative overrides clamp to zero ("inherit"), so a malformed write can
// never persist a value resolvePlan would misread.
func TestSetPlanNormalizesAndClamps(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	ws := uuid.New()

	if err := s.SetPlan(ctx, TenantPlan{
		WorkspaceID:         ws,
		Plan:                "BOGUS",
		APIRequestsIncluded: -5,
		APIRequestsHardCap:  -9,
	}); err != nil {
		t.Fatalf("SetPlan: %v", err)
	}
	p, err := s.PlanFor(ctx, ws)
	if err != nil {
		t.Fatalf("PlanFor: %v", err)
	}
	if p.Plan != DefaultPlanTier {
		t.Errorf("plan = %q, want default after normalizing unknown tier", p.Plan)
	}
	// Negative overrides clamped to zero -> the default ladder is inherited.
	q, _ := p.QuotaFor(usage.MetricAPIRequests)
	def, _ := defaultPlan().QuotaFor(usage.MetricAPIRequests)
	if q.Included != def.Included || q.HardCap != def.HardCap {
		t.Errorf("clamped overrides should inherit defaults: got %+v want %+v", q, def)
	}
}

// TestSetPlanRejectsNilWorkspace proves the guard against an empty workspace id.
func TestSetPlanRejectsNilWorkspace(t *testing.T) {
	s := newTestStore(t)
	if err := s.SetPlan(context.Background(), TenantPlan{Plan: tenancy.TierBase}); err == nil {
		t.Error("expected error for nil workspace id")
	}
}

// TestStoreWithServiceEndToEnd proves the store satisfies the service's
// PlanStore and yields a coherent statement through the real persistence path.
func TestStoreWithServiceEndToEnd(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	ws := uuid.New()
	if err := s.SetPlan(ctx, TenantPlan{WorkspaceID: ws, Plan: tenancy.TierBase}); err != nil {
		t.Fatalf("SetPlan: %v", err)
	}
	reader := &fakeUsageReader{count: 1_025_000}
	svc := NewService(s, reader, Config{now: func() time.Time { return time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC) }})
	defer svc.Stop()

	st, err := svc.CurrentStatement(ctx, ws)
	if err != nil {
		t.Fatalf("CurrentStatement: %v", err)
	}
	if st.Period != "2026-06" {
		t.Errorf("period = %q, want 2026-06", st.Period)
	}
	if st.TotalMinor != 5_050 {
		t.Errorf("total = %d, want 5050", st.TotalMinor)
	}
}
