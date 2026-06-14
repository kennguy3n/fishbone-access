package billing

import (
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/tenancy"
	"github.com/kennguy3n/fishbone-access/internal/services/usage"
)

// TestNormalizePlan proves unknown/empty/whitespace/case values coerce to the
// safe default tier rather than granting a larger allowance.
func TestNormalizePlan(t *testing.T) {
	cases := map[string]string{
		"":                DefaultPlanTier,
		"   ":             DefaultPlanTier,
		"bogus":           DefaultPlanTier,
		"PRO":             tenancy.TierPro,
		"  Enterprise  ":  tenancy.TierEnterprise,
		tenancy.TierBase:  tenancy.TierBase,
		tenancy.TierTrial: tenancy.TierTrial,
	}
	for in, want := range cases {
		if got := NormalizePlan(in); got != want {
			t.Errorf("NormalizePlan(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestIsKnownPlan proves the admin-validation predicate accepts exactly the
// ladder tiers (case/space-insensitive) and rejects everything else.
func TestIsKnownPlan(t *testing.T) {
	for _, p := range KnownPlans() {
		if !IsKnownPlan(p) {
			t.Errorf("IsKnownPlan(%q) = false, want true", p)
		}
	}
	if IsKnownPlan("bogus") || IsKnownPlan("") {
		t.Error("IsKnownPlan accepted an unknown/empty plan")
	}
	if !IsKnownPlan("  PRO ") {
		t.Error("IsKnownPlan should normalize case/space")
	}
}

// TestResolvePlanAppliesOverrides proves a non-zero override replaces the plan
// default while a zero override inherits it.
func TestResolvePlanAppliesOverrides(t *testing.T) {
	p := resolvePlan(TenantPlan{
		Plan:                tenancy.TierBase,
		APIRequestsIncluded: 5_000_000, // override
		APIRequestsHardCap:  0,         // inherit default (2_000_000)
	})
	q, ok := p.QuotaFor(usage.MetricAPIRequests)
	if !ok {
		t.Fatal("base plan must define api_requests")
	}
	if q.Included != 5_000_000 {
		t.Errorf("included = %d, want overridden 5_000_000", q.Included)
	}
	if q.HardCap != 2_000_000 {
		t.Errorf("hard cap = %d, want inherited default 2_000_000", q.HardCap)
	}
}

// TestResolvePlanDoesNotMutateDefaults is the concurrency-safety guard: resolving
// a plan with overrides must NOT mutate the shared planDefaults map, or one
// tenant's override would leak into another's resolved plan.
func TestResolvePlanDoesNotMutateDefaults(t *testing.T) {
	// Resolve with an override, then resolve a plain default and confirm the
	// default ladder is untouched.
	_ = resolvePlan(TenantPlan{Plan: tenancy.TierBase, APIRequestsIncluded: 999})
	clean := resolvePlan(TenantPlan{Plan: tenancy.TierBase})
	q, _ := clean.QuotaFor(usage.MetricAPIRequests)
	if q.Included != 1_000_000 {
		t.Fatalf("planDefaults mutated: base included = %d, want 1_000_000", q.Included)
	}
	// And the package-level default map itself is intact.
	if planDefaults[tenancy.TierBase].Metrics[usage.MetricAPIRequests].Included != 1_000_000 {
		t.Fatal("planDefaults map was mutated by resolvePlan")
	}
}

// TestUnknownPlanResolvesToDefault proves an unknown tier resolves to the
// most-constrained default plan (defense in depth behind NormalizePlan).
func TestUnknownPlanResolvesToDefault(t *testing.T) {
	p := resolvePlan(TenantPlan{Plan: "bogus"})
	if p.Plan != DefaultPlanTier {
		t.Errorf("resolved plan = %q, want default %q", p.Plan, DefaultPlanTier)
	}
}
