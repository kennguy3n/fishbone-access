package billing

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/services/tenancy"
	"github.com/kennguy3n/fishbone-access/internal/services/usage"
)

// fakeClock is a concurrency-safe injectable clock so the janitor goroutine and
// the test can both read it under -race without a data race.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakePlanStore returns a fixed plan and counts lookups so a test can assert the
// cache elides DB reads.
type fakePlanStore struct {
	mu    sync.Mutex
	plan  Plan
	calls int
	err   error
	set   []TenantPlan
}

func (f *fakePlanStore) PlanFor(_ context.Context, _ uuid.UUID) (Plan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return Plan{}, f.err
	}
	return f.plan, nil
}

func (f *fakePlanStore) SetPlan(_ context.Context, p TenantPlan) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.set = append(f.set, p)
	return nil
}

func (f *fakePlanStore) planForCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// fakeUsageReader returns a fixed api_requests count for both the current-period
// and arbitrary-period reads.
type fakeUsageReader struct {
	mu    sync.Mutex
	count int64
	err   error
}

func (f *fakeUsageReader) rows(ws uuid.UUID) []usage.TenantUsage {
	return []usage.TenantUsage{{WorkspaceID: ws, Period: "2026-06", Metric: usage.MetricAPIRequests, Count: f.count}}
}

func (f *fakeUsageReader) GetCurrentUsage(_ context.Context, ws uuid.UUID) ([]usage.TenantUsage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.rows(ws), nil
}

func (f *fakeUsageReader) GetUsage(_ context.Context, ws uuid.UUID, _ string) ([]usage.TenantUsage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.rows(ws), nil
}

func basePlan() Plan { return resolvePlan(TenantPlan{Plan: tenancy.TierBase}) } // incl 1M, hard 2M

// TestDecideSoftHardBoundaries walks the classification boundaries exactly: at
// the included quota it is OK, one over is soft, just below the hard cap is
// soft, and at the hard cap it is hard.
func TestDecideSoftHardBoundaries(t *testing.T) {
	ws := uuid.New()
	cases := []struct {
		used int64
		want QuotaState
	}{
		{1_000_000, QuotaOK},           // exactly included
		{1_000_001, QuotaSoftExceeded}, // one over included
		{1_999_999, QuotaSoftExceeded}, // one below hard cap
		{2_000_000, QuotaHardExceeded}, // at hard cap
		{2_500_000, QuotaHardExceeded}, // above hard cap
	}
	for _, c := range cases {
		plans := &fakePlanStore{plan: basePlan()}
		reader := &fakeUsageReader{count: c.used}
		clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
		svc := NewService(plans, reader, Config{now: clk.now})
		d, err := svc.Decide(context.Background(), ws)
		svc.Stop()
		if err != nil {
			t.Fatalf("used=%d: unexpected error %v", c.used, err)
		}
		if d.State != c.want {
			t.Errorf("used=%d: state = %v, want %v", c.used, d.State, c.want)
		}
	}
}

// TestDecideDenyOnlyWhenEnforce proves a hard-exceeded decision denies ONLY when
// EnforceHardCap is on; in shadow mode the same usage is detected but allowed.
func TestDecideDenyOnlyWhenEnforce(t *testing.T) {
	ws := uuid.New()
	for _, enforce := range []bool{false, true} {
		plans := &fakePlanStore{plan: basePlan()}
		reader := &fakeUsageReader{count: 2_500_000} // hard-exceeded
		clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
		svc := NewService(plans, reader, Config{EnforceHardCap: enforce, now: clk.now})
		d, err := svc.Decide(context.Background(), ws)
		svc.Stop()
		if err != nil {
			t.Fatalf("enforce=%v: %v", enforce, err)
		}
		if d.State != QuotaHardExceeded {
			t.Fatalf("enforce=%v: state = %v, want hard", enforce, d.State)
		}
		if d.Deny != enforce {
			t.Errorf("enforce=%v: Deny = %v, want %v", enforce, d.Deny, enforce)
		}
		if d.Allowed() == enforce {
			t.Errorf("enforce=%v: Allowed() = %v, inconsistent with Deny", enforce, d.Allowed())
		}
	}
}

// TestDecideUnlimitedNeverHard proves a zero hard cap (enterprise) is unlimited:
// no amount of usage is ever hard-exceeded, though it can still be soft.
func TestDecideUnlimitedNeverHard(t *testing.T) {
	ws := uuid.New()
	plans := &fakePlanStore{plan: resolvePlan(TenantPlan{Plan: tenancy.TierEnterprise})} // hard cap 0
	reader := &fakeUsageReader{count: 500_000_000}                                       // way over included
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	svc := NewService(plans, reader, Config{EnforceHardCap: true, now: clk.now})
	defer svc.Stop()
	d, err := svc.Decide(context.Background(), ws)
	if err != nil {
		t.Fatal(err)
	}
	if d.State == QuotaHardExceeded || d.Deny {
		t.Errorf("unlimited plan hard-denied: state=%v deny=%v", d.State, d.Deny)
	}
	if d.State != QuotaSoftExceeded {
		t.Errorf("state = %v, want soft (over included, unlimited hard cap)", d.State)
	}
}

// TestDecideCacheTTL proves a decision is cached for CacheTTL: within the window
// the store is not re-read; after it expires the decision is recomputed.
func TestDecideCacheTTL(t *testing.T) {
	ws := uuid.New()
	plans := &fakePlanStore{plan: basePlan()}
	reader := &fakeUsageReader{count: 100}
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	svc := NewService(plans, reader, Config{CacheTTL: 30 * time.Second, now: clk.now})
	defer svc.Stop()

	if _, err := svc.Decide(context.Background(), ws); err != nil {
		t.Fatal(err)
	}
	if got := plans.planForCalls(); got != 1 {
		t.Fatalf("after first Decide, PlanFor calls = %d, want 1", got)
	}

	clk.advance(10 * time.Second) // within TTL
	if _, err := svc.Decide(context.Background(), ws); err != nil {
		t.Fatal(err)
	}
	if got := plans.planForCalls(); got != 1 {
		t.Fatalf("within TTL, PlanFor calls = %d, want still 1 (served from cache)", got)
	}

	clk.advance(30 * time.Second) // now past TTL
	if _, err := svc.Decide(context.Background(), ws); err != nil {
		t.Fatal(err)
	}
	if got := plans.planForCalls(); got != 2 {
		t.Fatalf("after TTL expiry, PlanFor calls = %d, want 2 (recomputed)", got)
	}
}

// TestDecideFailOpenOnError proves a lookup error is propagated (the middleware
// fails open on it). Both the plan and the usage error paths are exercised.
func TestDecideFailOpenOnError(t *testing.T) {
	ws := uuid.New()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}

	planErr := &fakePlanStore{err: errors.New("plan boom")}
	svc1 := NewService(planErr, &fakeUsageReader{}, Config{now: clk.now})
	if _, err := svc1.Decide(context.Background(), ws); err == nil {
		t.Error("expected error when plan lookup fails")
	}
	svc1.Stop()

	usageErr := &fakeUsageReader{err: errors.New("usage boom")}
	svc2 := NewService(&fakePlanStore{plan: basePlan()}, usageErr, Config{now: clk.now})
	if _, err := svc2.Decide(context.Background(), ws); err == nil {
		t.Error("expected error when usage lookup fails")
	}
	svc2.Stop()
}

// TestSetPlanInvalidatesCache proves SetPlan drops the cached decision so the new
// plan takes effect immediately rather than after the TTL.
func TestSetPlanInvalidatesCache(t *testing.T) {
	ws := uuid.New()
	plans := &fakePlanStore{plan: basePlan()}
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	svc := NewService(plans, &fakeUsageReader{count: 100}, Config{now: clk.now})
	defer svc.Stop()

	if _, err := svc.Decide(context.Background(), ws); err != nil {
		t.Fatal(err)
	}
	if svc.CacheLen() != 1 {
		t.Fatalf("cache len = %d, want 1 after Decide", svc.CacheLen())
	}
	if err := svc.SetPlan(context.Background(), TenantPlan{WorkspaceID: ws, Plan: tenancy.TierPro}); err != nil {
		t.Fatal(err)
	}
	if svc.CacheLen() != 0 {
		t.Fatalf("cache len = %d, want 0 after SetPlan invalidation", svc.CacheLen())
	}
	if len(plans.set) != 1 || plans.set[0].WorkspaceID != ws {
		t.Fatalf("SetPlan not delegated to store: %+v", plans.set)
	}
}

// TestEvictIdle proves the janitor's eviction drops entries unused for longer
// than IdleTTL, bounding memory to the active-tenant count.
func TestEvictIdle(t *testing.T) {
	ws := uuid.New()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	svc := NewService(&fakePlanStore{plan: basePlan()}, &fakeUsageReader{count: 1}, Config{IdleTTL: time.Minute, now: clk.now})
	defer svc.Stop()

	if _, err := svc.Decide(context.Background(), ws); err != nil {
		t.Fatal(err)
	}
	if svc.CacheLen() != 1 {
		t.Fatalf("cache len = %d, want 1", svc.CacheLen())
	}
	clk.advance(2 * time.Minute) // past IdleTTL
	svc.evictIdle(clk.now())
	if svc.CacheLen() != 0 {
		t.Fatalf("cache len = %d, want 0 after idle eviction", svc.CacheLen())
	}
}

// TestQuotaStatus proves the live read reports per-metric state and reflects the
// enforcement posture.
func TestQuotaStatus(t *testing.T) {
	ws := uuid.New()
	plans := &fakePlanStore{plan: basePlan()}
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	svc := NewService(plans, &fakeUsageReader{count: 1_500_000}, Config{EnforceHardCap: true, now: clk.now}) // soft
	defer svc.Stop()

	status, err := svc.QuotaStatus(context.Background(), ws)
	if err != nil {
		t.Fatal(err)
	}
	if !status.EnforcementActive {
		t.Error("EnforcementActive = false, want true")
	}
	if len(status.Metrics) != 1 {
		t.Fatalf("metrics = %+v, want 1", status.Metrics)
	}
	m := status.Metrics[0]
	if m.Metric != usage.MetricAPIRequests || m.Used != 1_500_000 || m.State != "soft_exceeded" {
		t.Errorf("metric status = %+v, want api_requests used=1.5M soft_exceeded", m)
	}
}

// TestStatementForDeterministicViaService proves the service path also yields a
// stable statement and rejects empty inputs.
func TestStatementForDeterministicViaService(t *testing.T) {
	ws := uuid.New()
	plans := &fakePlanStore{plan: basePlan()}
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	svc := NewService(plans, &fakeUsageReader{count: 1_025_000}, Config{now: clk.now})
	defer svc.Stop()

	a, err := svc.StatementFor(context.Background(), ws, "2026-06")
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.StatementFor(context.Background(), ws, "2026-06")
	if err != nil {
		t.Fatal(err)
	}
	if a.TotalMinor != b.TotalMinor || a.TotalMinor != 5_050 {
		t.Errorf("statement total not stable/correct: a=%d b=%d", a.TotalMinor, b.TotalMinor)
	}
	if _, err := svc.StatementFor(context.Background(), uuid.Nil, "2026-06"); err == nil {
		t.Error("expected error for empty workspace id")
	}
	if _, err := svc.StatementFor(context.Background(), ws, ""); err == nil {
		t.Error("expected error for empty period")
	}
}

// TestStopIdempotent proves Stop can be called more than once without panicking
// (the shutdown path may race with other teardown).
func TestStopIdempotent(t *testing.T) {
	svc := NewService(&fakePlanStore{plan: basePlan()}, &fakeUsageReader{}, Config{})
	svc.Stop()
	svc.Stop()
}
