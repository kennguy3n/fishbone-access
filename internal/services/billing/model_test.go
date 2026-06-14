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

// TestValidateOverrides exercises the effective-plan guard on the admin
// set-plan path: a resolved hard cap below the included allowance is rejected,
// while inherited defaults, unlimited (zero) caps, and a sane explicit override
// pass. The cases cover both a full override (both fields set) and the two
// partial overrides (one field set, the other inherited), since those are
// validated against the EFFECTIVE values, not just the request fields.
func TestValidateOverrides(t *testing.T) {
	cases := []struct {
		name    string
		row     TenantPlan
		wantErr bool
	}{
		{"default trial (no override)", TenantPlan{Plan: tenancy.TierTrial}, false},
		{"default enterprise unlimited cap", TenantPlan{Plan: tenancy.TierEnterprise}, false},
		{"sane full override", TenantPlan{Plan: tenancy.TierBase, APIRequestsIncluded: 500_000, APIRequestsHardCap: 1_000_000}, false},
		{"raise both above defaults", TenantPlan{Plan: tenancy.TierBase, APIRequestsIncluded: 5_000_000, APIRequestsHardCap: 8_000_000}, false},
		{"inverted full override", TenantPlan{Plan: tenancy.TierBase, APIRequestsIncluded: 2_000_000, APIRequestsHardCap: 500_000}, true},
		{"included raised past inherited cap", TenantPlan{Plan: tenancy.TierTrial, APIRequestsIncluded: 2_000_000}, true},
		{"cap lowered below inherited included", TenantPlan{Plan: tenancy.TierBase, APIRequestsHardCap: 500_000}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateOverrides(tc.row)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateOverrides(%+v) = nil, want error", tc.row)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateOverrides(%+v) = %v, want nil", tc.row, err)
			}
		})
	}
}
