package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/services/billing"
	"github.com/kennguy3n/fishbone-access/internal/services/tenancy"
	"github.com/kennguy3n/fishbone-access/internal/services/usage"
)

// countingMeter is a usage.Meter that just counts Record calls, so a test can
// assert exactly which requests were metered.
type countingMeter struct {
	mu    sync.Mutex
	calls int
}

func (m *countingMeter) Record(_ uuid.UUID, _ string) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
}

func (m *countingMeter) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// billingTestDeps wires the billing read/admin surface end-to-end through the
// real Auth + ResolveTenant + RequireTenant chain, backed by a billing plan
// store and the SAME usage rollup the meter writes (no second source of truth).
func billingTestDeps(t *testing.T) (Deps, *billing.Service, *usage.Store) {
	t.Helper()
	deps := lifecycleTestDeps(t)

	usageStore := usage.NewStore(deps.DB)
	if err := usageStore.Migrate(); err != nil {
		t.Fatalf("usage migrate: %v", err)
	}
	planStore := billing.NewStore(deps.DB)
	if err := planStore.Migrate(); err != nil {
		t.Fatalf("billing migrate: %v", err)
	}
	svc := billing.NewService(planStore, usageStore, billing.Config{EnforceHardCap: true})
	t.Cleanup(svc.Stop)
	deps.BillingReader = svc
	return deps, svc, usageStore
}

// TestBillingPlanDefaultsToTrial proves a tenant with no plan row reads back the
// default trial plan and its current-period (zero) quota status.
func TestBillingPlanDefaultsToTrial(t *testing.T) {
	deps, _, _ := billingTestDeps(t)
	r := NewRouter(deps)

	w := do(t, r, http.MethodGet, "/api/v1/billing/plan", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var body billing.PlanStatus
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Plan != tenancy.TierTrial {
		t.Errorf("plan = %q, want trial (default)", body.Plan)
	}
	if !body.EnforcementActive {
		t.Error("EnforcementActive = false, want true (configured EnforceHardCap)")
	}
	if len(body.Metrics) != 1 || body.Metrics[0].Metric != usage.MetricAPIRequests || body.Metrics[0].State != "ok" {
		t.Errorf("metrics = %+v, want one api_requests state=ok", body.Metrics)
	}
}

// TestBillingStatementCurrentPeriodOverage proves the statement derives from the
// usage rollup: seeding usage above the included quota yields the expected
// integer overage amount for the current period.
func TestBillingStatementCurrentPeriodOverage(t *testing.T) {
	deps, _, usageStore := billingTestDeps(t)
	r := NewRouter(deps)
	wsA := workspaceIDForTenant(t, deps, "tenant-a")

	// Put tenant-a on base (incl 1M, overage 50/10k) and seed 1.025M usage.
	w := do(t, r, http.MethodPut, "/api/v1/billing/plan", "tok-a", map[string]any{"plan": "base"})
	if w.Code != http.StatusOK {
		t.Fatalf("set plan status = %d, body=%s", w.Code, w.Body.String())
	}
	if err := usageStore.AddUsage(context.Background(), []usage.Delta{
		{WorkspaceID: wsA, Period: usage.PeriodOf(time.Now()), Metric: usage.MetricAPIRequests, Count: 1_025_000},
	}); err != nil {
		t.Fatalf("seed usage: %v", err)
	}

	w = do(t, r, http.MethodGet, "/api/v1/billing/statement", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("statement status = %d, body=%s", w.Code, w.Body.String())
	}
	var st billing.Statement
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if st.Period != usage.PeriodOf(time.Now()) {
		t.Errorf("period = %q, want %q", st.Period, usage.PeriodOf(time.Now()))
	}
	if st.Plan != tenancy.TierBase {
		t.Errorf("plan = %q, want base", st.Plan)
	}
	if st.TotalMinor != 5_050 { // base 4900 + ceil(25000/10000)=3 * 50
		t.Errorf("total = %d, want 5050", st.TotalMinor)
	}
}

// TestBillingStatementInvalidPeriod proves a malformed ?period= is a 400, not a
// silent empty statement.
func TestBillingStatementInvalidPeriod(t *testing.T) {
	deps, _, _ := billingTestDeps(t)
	r := NewRouter(deps)

	w := do(t, r, http.MethodGet, "/api/v1/billing/statement?period=2026-6", "tok-a", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for malformed period; body=%s", w.Code, w.Body.String())
	}
}

// TestBillingStatementExplicitPeriodEmptyIsValid proves an explicit period with
// no usage is a valid base-only statement (not a 404/500).
func TestBillingStatementExplicitPeriodEmptyIsValid(t *testing.T) {
	deps, _, _ := billingTestDeps(t)
	r := NewRouter(deps)

	w := do(t, r, http.MethodGet, "/api/v1/billing/statement?period=2020-01", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var st billing.Statement
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if st.Period != "2020-01" {
		t.Errorf("period = %q, want 2020-01", st.Period)
	}
}

// TestBillingSetPlanRejectsUnknown proves the admin write rejects an unknown
// tier with a 400 rather than coercing it.
func TestBillingSetPlanRejectsUnknown(t *testing.T) {
	deps, _, _ := billingTestDeps(t)
	r := NewRouter(deps)

	w := do(t, r, http.MethodPut, "/api/v1/billing/plan", "tok-a", map[string]any{"plan": "platinum"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for unknown plan; body=%s", w.Code, w.Body.String())
	}
}

// TestBillingSetPlanRejectsNegativeOverride proves a negative override is an
// explicit 400 (the handler does not silently clamp).
func TestBillingSetPlanRejectsNegativeOverride(t *testing.T) {
	deps, _, _ := billingTestDeps(t)
	r := NewRouter(deps)

	w := do(t, r, http.MethodPut, "/api/v1/billing/plan", "tok-a", map[string]any{
		"plan": "base", "api_requests_included": -1,
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for negative override; body=%s", w.Code, w.Body.String())
	}
}

// TestBillingSetPlanRejectsInvertedOverride proves an override whose effective
// hard cap would fall below the included allowance is an explicit 400, so an
// admin cannot persist a cap that hard-denies the tenant before it consumes the
// quota it is entitled to.
func TestBillingSetPlanRejectsInvertedOverride(t *testing.T) {
	deps, _, _ := billingTestDeps(t)
	r := NewRouter(deps)

	w := do(t, r, http.MethodPut, "/api/v1/billing/plan", "tok-a", map[string]any{
		"plan": "base", "api_requests_included": 2_000_000, "api_requests_hard_cap": 500_000,
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for inverted override (cap < included); body=%s", w.Code, w.Body.String())
	}
}

// TestBillingPlanCrossTenantIsolation proves setting tenant-a's plan never
// changes tenant-b's: each tenant only ever reads/writes its OWN plan (workspace
// derived from context, never the body).
func TestBillingPlanCrossTenantIsolation(t *testing.T) {
	deps, _, _ := billingTestDeps(t)
	r := NewRouter(deps)

	if w := do(t, r, http.MethodPut, "/api/v1/billing/plan", "tok-a", map[string]any{"plan": "enterprise"}); w.Code != http.StatusOK {
		t.Fatalf("set tenant-a plan status = %d, body=%s", w.Code, w.Body.String())
	}

	// tenant-b must still be on the default trial plan.
	w := do(t, r, http.MethodGet, "/api/v1/billing/plan", "tok-b", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("tenant-b plan status = %d, body=%s", w.Code, w.Body.String())
	}
	var body billing.PlanStatus
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Plan != tenancy.TierTrial {
		t.Errorf("tenant-b plan = %q, want trial (tenant-a's change must not leak)", body.Plan)
	}
}

// TestBillingNotMountedWithoutReader proves the billing routes are absent when
// no billing reader is wired (billing disabled / degraded boot), so the surface
// degrades cleanly rather than panicking on a nil service.
func TestBillingNotMountedWithoutReader(t *testing.T) {
	deps := lifecycleTestDeps(t) // no BillingReader
	r := NewRouter(deps)

	for _, path := range []string{"/api/v1/billing/plan", "/api/v1/billing/statement"} {
		w := do(t, r, http.MethodGet, path, "tok-a", nil)
		if w.Code != http.StatusNotFound {
			t.Fatalf("GET %s status = %d, want 404 (route unmounted without a billing reader)", path, w.Code)
		}
	}
}

// TestBillingHardDenyIsNotMetered proves the enforcement middleware is mounted
// BEFORE the usage meter in the tenant-scoped chain: a hard-denied 402 aborts
// before the meter runs, so a tenant is never billed for requests the platform
// refused — and a hard-capped tenant cannot feed its own rejected requests back
// into the usage rollup. The control request (a different tenant within quota)
// is admitted AND metered exactly once, proving the meter is still wired. The
// probed route (GET /api/v1/usage) is deliberately a NON-exempt, enforced route
// — the billing self-service surface is exempt from the cap (see
// TestBillingSelfServiceExemptFromHardCap).
func TestBillingHardDenyIsNotMetered(t *testing.T) {
	deps, svc, usageStore := billingTestDeps(t)
	meter := &countingMeter{}
	deps.UsageMeter = meter       // write side of metering
	deps.UsageReader = usageStore // mounts the enforced GET /api/v1/usage route
	deps.BillingEnforcer = svc    // EnforceHardCap is true (see billingTestDeps)
	r := NewRouter(deps)

	// tenant-a stays on the default trial plan (hard cap 75k); seed its
	// current-period usage above that ceiling so it is hard-exceeded.
	wsA := workspaceIDForTenant(t, deps, "tenant-a")
	if err := usageStore.AddUsage(context.Background(), []usage.Delta{
		{WorkspaceID: wsA, Period: usage.PeriodOf(time.Now()), Metric: usage.MetricAPIRequests, Count: 80_000},
	}); err != nil {
		t.Fatalf("seed usage: %v", err)
	}

	w := do(t, r, http.MethodGet, "/api/v1/usage", "tok-a", nil)
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("hard-capped request status = %d, want 402; body=%s", w.Code, w.Body.String())
	}
	if got := meter.count(); got != 0 {
		t.Errorf("hard-denied request was metered %d time(s), want 0 (enforce-before-meter)", got)
	}

	// Control: tenant-b is within quota, so it is admitted and metered once.
	w = do(t, r, http.MethodGet, "/api/v1/usage", "tok-b", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("within-quota request status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if got := meter.count(); got != 1 {
		t.Errorf("admitted request metered %d time(s), want 1", got)
	}
}

// TestBillingSelfServiceExemptFromHardCap proves the self-service billing
// surface stays reachable for a HARD-CAPPED tenant: the 402 body tells the
// tenant to "upgrade the plan", so the statement/plan reads and the plan
// upgrade must not themselves be capped (otherwise there is no API-side escape).
// A genuinely enforced route (GET /api/v1/usage) still 402s for the same tenant,
// proving enforcement is active and only the billing surface is exempt.
func TestBillingSelfServiceExemptFromHardCap(t *testing.T) {
	deps, svc, usageStore := billingTestDeps(t)
	deps.UsageReader = usageStore // mounts the enforced GET /api/v1/usage route
	deps.BillingEnforcer = svc    // EnforceHardCap is true (see billingTestDeps)
	r := NewRouter(deps)

	// Put tenant-a far over its hard cap on the current period.
	wsA := workspaceIDForTenant(t, deps, "tenant-a")
	if err := usageStore.AddUsage(context.Background(), []usage.Delta{
		{WorkspaceID: wsA, Period: usage.PeriodOf(time.Now()), Metric: usage.MetricAPIRequests, Count: 5_000_000},
	}); err != nil {
		t.Fatalf("seed usage: %v", err)
	}

	// A non-billing enforced route must be hard-denied — enforcement is live.
	if w := do(t, r, http.MethodGet, "/api/v1/usage", "tok-a", nil); w.Code != http.StatusPaymentRequired {
		t.Fatalf("enforced route status = %d, want 402 (cap is active); body=%s", w.Code, w.Body.String())
	}

	// The self-service billing surface must remain reachable so the tenant can
	// see what it owes and upgrade out of the cap.
	if w := do(t, r, http.MethodGet, "/api/v1/billing/plan", "tok-a", nil); w.Code != http.StatusOK {
		t.Errorf("GET /billing/plan status = %d, want 200 (exempt from cap); body=%s", w.Code, w.Body.String())
	}
	if w := do(t, r, http.MethodGet, "/api/v1/billing/statement", "tok-a", nil); w.Code != http.StatusOK {
		t.Errorf("GET /billing/statement status = %d, want 200 (exempt from cap); body=%s", w.Code, w.Body.String())
	}
	// The upgrade path itself — the one the 402 body points at — must work.
	if w := do(t, r, http.MethodPut, "/api/v1/billing/plan", "tok-a", map[string]any{"plan": "pro"}); w.Code != http.StatusOK {
		t.Errorf("PUT /billing/plan status = %d, want 200 (self-remediation must not be capped); body=%s", w.Code, w.Body.String())
	}
}
