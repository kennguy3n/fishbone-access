package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/billing"
	"github.com/kennguy3n/fishbone-access/internal/services/tenancy"
	"github.com/kennguy3n/fishbone-access/internal/services/usage"
)

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
