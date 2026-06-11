package tenancy

import "strings"

// Tier names. Trial is the most constrained (the dormant-trial majority); the
// ladder widens to enterprise. A tenant with no explicit budget row resolves to
// the configured default tier (TenancyConfig.DefaultTier, "trial" by default),
// so an un-tiered tenant can never claim more than the smallest share.
const (
	TierTrial      = "trial"
	TierBase       = "base"
	TierPro        = "pro"
	TierEnterprise = "enterprise"
)

// Budget is the resolved, effective resource budget for one tenant: tier
// defaults with any non-zero per-workspace override applied on top.
type Budget struct {
	Tier                   string
	MaxConcurrentSyncs     int
	MaxPeriodicJobsPerHour int
	FairShareWeight        int
}

// tierDefaults are the built-in per-tier budgets. They are intentionally
// conservative for the low tiers so the dormant-trial majority cannot crowd out
// paying tenants even in the brief windows they are awake, and scale up with
// tier. Concurrency is the primary lever (it bounds simultaneous load); the
// per-hour cap bounds scheduling frequency; the weight biases fair scheduling.
var tierDefaults = map[string]Budget{
	TierTrial:      {Tier: TierTrial, MaxConcurrentSyncs: 1, MaxPeriodicJobsPerHour: 4, FairShareWeight: 1},
	TierBase:       {Tier: TierBase, MaxConcurrentSyncs: 2, MaxPeriodicJobsPerHour: 12, FairShareWeight: 2},
	TierPro:        {Tier: TierPro, MaxConcurrentSyncs: 4, MaxPeriodicJobsPerHour: 60, FairShareWeight: 4},
	TierEnterprise: {Tier: TierEnterprise, MaxConcurrentSyncs: 8, MaxPeriodicJobsPerHour: 240, FairShareWeight: 8},
}

// normalizeTier lower-cases/trims tier and maps an unknown or empty value to
// TierTrial — the safe, most-constrained fallback, so a typo cannot
// accidentally grant a tenant enterprise-sized headroom.
func normalizeTier(tier string) string {
	t := strings.ToLower(strings.TrimSpace(tier))
	if _, ok := tierDefaults[t]; ok {
		return t
	}
	return TierTrial
}

// TierBudget returns the built-in default budget for a tier, falling back to
// the trial budget for an unknown tier.
func TierBudget(tier string) Budget {
	return tierDefaults[normalizeTier(tier)]
}

// IsKnownTier reports whether tier (trimmed/lower-cased) names a recognised
// tier in the ladder. An unrecognised name still resolves safely to TierTrial
// at runtime, so this exists only so the boot path can warn loudly that a
// configured ACCESS_TENANCY_DEFAULT_TIER did not match a real tier — surfacing
// a typo early without coupling the leaf config package to the tier ladder.
func IsKnownTier(tier string) bool {
	_, ok := tierDefaults[strings.ToLower(strings.TrimSpace(tier))]
	return ok
}

// resolveBudget applies a per-workspace TenantResourceBudget row over the tier
// defaults: each non-zero override field wins, each zero field inherits the
// tier default. This lets one knob be pinned per tenant without restating the
// whole budget.
func resolveBudget(row TenantResourceBudget) Budget {
	b := TierBudget(row.Tier)
	if row.MaxConcurrentSyncs > 0 {
		b.MaxConcurrentSyncs = row.MaxConcurrentSyncs
	}
	if row.MaxPeriodicJobsPerHour > 0 {
		b.MaxPeriodicJobsPerHour = row.MaxPeriodicJobsPerHour
	}
	if row.FairShareWeight > 0 {
		b.FairShareWeight = row.FairShareWeight
	}
	return b
}
