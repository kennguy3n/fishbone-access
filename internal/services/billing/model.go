package billing

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/services/tenancy"
	"github.com/kennguy3n/fishbone-access/internal/services/usage"
)

// Currency is the ISO-4217 code all amounts are denominated in. Amounts
// themselves are integer MINOR units (cents), never floats, so statement totals
// never drift; this code is informational metadata on the statement.
const Currency = "USD"

// MetricQuota is the per-metric quota ladder and overage price for one plan.
// All fields are integers: counts are exact, and OverageUnitMinor is a price in
// minor units (cents) charged per OverageBlock units consumed beyond Included.
type MetricQuota struct {
	// Included is the count bundled into the plan for the period (the SOFT
	// cap). Usage at or below this is covered by the base price; usage above it
	// is overage and trips a soft warning.
	Included int64
	// HardCap is the absolute ceiling for the period. Usage at or above it is
	// rejected by enforcement. Zero means UNLIMITED (no hard ceiling) — the
	// enterprise posture — so a metric with a zero hard cap is never hard-denied.
	HardCap int64
	// OverageUnitMinor is the price in minor units charged per OverageBlock
	// units consumed beyond Included. Zero means overage is not billed (the
	// trial posture, where the tight hard cap — not a bill — is the control).
	OverageUnitMinor int64
	// OverageBlock is the granularity overage is billed in (e.g. per 10,000
	// calls). A non-positive value is treated as 1 (per-unit) at compute time so
	// a misconfigured block can never divide by zero.
	OverageBlock int64
}

// Plan is a tenant's RESOLVED plan: the tier identity, the base price for the
// period, and the per-metric quota ladder with any per-workspace overrides
// already applied. It is derived from the plan defaults plus the tenant_plan
// row; callers never construct it directly (see Store.PlanFor / resolvePlan).
type Plan struct {
	// Plan is the tier identity, one of tenancy.TierTrial/Base/Pro/Enterprise.
	// It is the SAME ladder the tenancy resource budgets use, not a parallel
	// billing taxonomy.
	Plan string
	// BasePriceMinor is the recurring period charge in minor units, billed
	// regardless of usage.
	BasePriceMinor int64
	// Metrics maps a metered metric name (e.g. usage.MetricAPIRequests) to its
	// quota ladder. Only metrics present here are billed or enforced.
	Metrics map[string]MetricQuota
}

// QuotaFor returns the metric's quota ladder and whether the plan defines one.
func (p Plan) QuotaFor(metric string) (MetricQuota, bool) {
	q, ok := p.Metrics[metric]
	return q, ok
}

// planDefaults are the built-in per-tier billing ladders, keyed by the tenancy
// tier constants so the plan ladder and the resource-budget ladder share one
// taxonomy. They mirror the tenancy.tierDefaults philosophy: the low tiers are
// deliberately tight (the dormant-trial majority cannot run up a shared-resource
// bill) and widen with tier. The trial tier is hard-capped close to its included
// quota and bills no overage — a trial is gated, not invoiced — while the paid
// tiers bundle a generous included quota, bill overage in coarse blocks, and
// (enterprise) lift the hard ceiling entirely.
//
// Quotas are PER BILLING PERIOD (a usage.PeriodOf month). Amounts are minor
// units (USD cents).
var planDefaults = map[string]Plan{
	tenancy.TierTrial: {
		Plan:           tenancy.TierTrial,
		BasePriceMinor: 0,
		Metrics: map[string]MetricQuota{
			usage.MetricAPIRequests: {Included: 50_000, HardCap: 75_000, OverageUnitMinor: 0, OverageBlock: 0},
		},
	},
	tenancy.TierBase: {
		Plan:           tenancy.TierBase,
		BasePriceMinor: 4_900,
		Metrics: map[string]MetricQuota{
			usage.MetricAPIRequests: {Included: 1_000_000, HardCap: 2_000_000, OverageUnitMinor: 50, OverageBlock: 10_000},
		},
	},
	tenancy.TierPro: {
		Plan:           tenancy.TierPro,
		BasePriceMinor: 19_900,
		Metrics: map[string]MetricQuota{
			usage.MetricAPIRequests: {Included: 10_000_000, HardCap: 20_000_000, OverageUnitMinor: 40, OverageBlock: 10_000},
		},
	},
	tenancy.TierEnterprise: {
		Plan:           tenancy.TierEnterprise,
		BasePriceMinor: 99_900,
		Metrics: map[string]MetricQuota{
			// HardCap 0 = unlimited: an enterprise tenant is never hard-denied;
			// it is billed for whatever it consumes beyond the (large) included
			// quota.
			usage.MetricAPIRequests: {Included: 100_000_000, HardCap: 0, OverageUnitMinor: 25, OverageBlock: 10_000},
		},
	},
}

// DefaultPlanTier is the plan a tenant with no explicit tenant_plan row resolves
// to. It is the most-constrained tier, mirroring tenancy's default so an
// un-assigned tenant can never claim more than the smallest allowance.
const DefaultPlanTier = tenancy.TierTrial

// KnownPlans returns the recognised plan tiers in ladder order. Used by the
// admin set-plan handler to validate input and by tests to enumerate the ladder.
func KnownPlans() []string {
	return []string{tenancy.TierTrial, tenancy.TierBase, tenancy.TierPro, tenancy.TierEnterprise}
}

// NormalizePlan lower-cases/trims plan and maps an unknown or empty value to
// DefaultPlanTier — the safe, most-constrained fallback, so a typo cannot
// accidentally grant a tenant an enterprise-sized allowance. It mirrors
// tenancy.normalizeTier exactly for the same ladder.
func NormalizePlan(plan string) string {
	p := strings.ToLower(strings.TrimSpace(plan))
	if _, ok := planDefaults[p]; ok {
		return p
	}
	return DefaultPlanTier
}

// IsKnownPlan reports whether plan (trimmed/lower-cased) names a recognised
// tier. The admin set-plan path uses it to reject an unknown plan with a 400
// rather than silently coercing it to trial.
func IsKnownPlan(plan string) bool {
	_, ok := planDefaults[strings.ToLower(strings.TrimSpace(plan))]
	return ok
}

// TenantPlan is one per-tenant plan-assignment row: the tenant's plan tier plus
// any non-zero per-workspace quota overrides. It is the GORM source of truth for
// the SQLite test/dev path; the production schema is 0026_tenant_plan.sql.
//
// It deliberately does NOT embed models.Base: identity is the workspace_id (no
// surrogate UUID) and the row is hard-updated in place rather than soft-deleted
// — the same modelling choice as tenancy.TenantResourceBudget and
// usage.TenantUsage. A zero override column means "inherit the plan default" at
// resolve time (see resolvePlan).
type TenantPlan struct {
	// WorkspaceID is the tenant boundary (FK to workspaces.id), 1:1 with an
	// iam-core tenant_id, and the primary key.
	WorkspaceID uuid.UUID `gorm:"type:uuid;primaryKey" json:"workspace_id"`
	// Plan is the tier identity; normalized on write. CHECK-constrained to the
	// tier ladder in the SQL migration.
	Plan string `gorm:"type:varchar(32);not null;default:trial" json:"plan"`
	// APIRequestsIncluded overrides the plan default included quota for the
	// api_requests metric. Zero means inherit the plan default.
	APIRequestsIncluded int64 `gorm:"not null;default:0" json:"api_requests_included"`
	// APIRequestsHardCap overrides the plan default hard ceiling for the
	// api_requests metric. Zero means inherit the plan default (NOT "unlimited"
	// — unlimited is expressed by the plan default itself being zero).
	APIRequestsHardCap int64     `gorm:"not null;default:0" json:"api_requests_hard_cap"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// TableName pins the table name so the SQL migration and the GORM model target
// the same identifier regardless of GORM pluralization (mirrors
// usage.TenantUsage.TableName).
func (TenantPlan) TableName() string { return "tenant_plan" }

// resolvePlan applies a tenant_plan row's non-zero overrides over its plan's
// built-in ladder, returning the effective Plan. A missing/zero override leaves
// the default in place. The defaults map is never mutated — the metric map is
// copied before any override is applied — so concurrent resolves are safe.
func resolvePlan(row TenantPlan) Plan {
	base := planDefaults[NormalizePlan(row.Plan)]
	out := Plan{
		Plan:           base.Plan,
		BasePriceMinor: base.BasePriceMinor,
		Metrics:        make(map[string]MetricQuota, len(base.Metrics)),
	}
	for metric, q := range base.Metrics {
		out.Metrics[metric] = q
	}
	if q, ok := out.Metrics[usage.MetricAPIRequests]; ok {
		if row.APIRequestsIncluded > 0 {
			q.Included = row.APIRequestsIncluded
		}
		if row.APIRequestsHardCap > 0 {
			q.HardCap = row.APIRequestsHardCap
		}
		out.Metrics[usage.MetricAPIRequests] = q
	}
	return out
}

// defaultPlan returns the resolved default plan (no overrides) for a tenant with
// no tenant_plan row.
func defaultPlan() Plan { return resolvePlan(TenantPlan{Plan: DefaultPlanTier}) }
