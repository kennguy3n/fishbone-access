// Package usage is the per-tenant usage-metering foundation: it accumulates
// per-tenant usage counts (API calls today) in process and flushes them to a
// Postgres rollup so cost-to-serve is attributable per tenant — the "who is
// using what" half of the 5,000-tenant SaaS cost story (the per-tenant rate
// limiter is the "cap the abuser" half).
//
// Cardinality is the operative constraint at this tenant count, exactly as for
// the Prometheus instruments in internal/pkg/observability: a per-tenant label
// on a Prometheus series would explode the time-series count (5,000 tenants ×
// routes). So per-tenant attribution lives in Postgres, where a row per
// (workspace, period, metric) is cheap, and ONLY aggregate (non-tenant)
// counters are exported to /metrics. The rollup is read back per tenant through
// an authenticated endpoint, never scraped per tenant.
//
// The aggregator is in-memory and therefore per-replica: each replica flushes
// its own deltas with an additive UPSERT (count = count + delta), so N replicas
// sum correctly into one shared row rather than overwriting one another. This
// mirrors the per-replica posture of internal/pkg/ratelimit and needs no extra
// infrastructure; a globally exact, real-time count would use a shared store
// (the ACCESS_REDIS_URL seam), which the Sink interface here can be re-backed
// onto later without touching the call sites.
package usage

import (
	"time"

	"github.com/google/uuid"
)

// Metered usage metrics. These are a small, FIXED set of identifiers (not
// tenant- or route-derived), so they are safe to use as a bounded Prometheus
// label on the aggregate counters and as the `metric` column of the rollup.
const (
	// MetricAPIRequests counts authenticated, tenant-scoped API requests — the
	// primary cost-to-serve signal and the must-have meter.
	MetricAPIRequests = "api_requests"
)

// TenantUsage is one usage rollup row: the running count of a single metric for
// one workspace within one billing period. The primary key is the composite
// (workspace_id, period, metric), so a replica's additive UPSERT targets
// exactly one row and concurrent replicas accumulate into it.
//
// It deliberately does NOT embed models.Base: the identity is the composite key
// (there is no surrogate UUID), and the row is an operational counter that is
// hard-updated in place rather than soft-deleted — the same modelling choice as
// tenancy.TenantActivity. The schema is reproduced for production in
// internal/migrations/0025_tenant_usage.sql; this struct is the source of truth
// for GORM auto-migrate on the SQLite test/dev path.
type TenantUsage struct {
	// WorkspaceID is the tenant boundary (FK to workspaces.id), 1:1 with an
	// iam-core tenant_id. Part of the composite primary key.
	WorkspaceID uuid.UUID `gorm:"type:uuid;primaryKey" json:"workspace_id"`
	// Period is the billing window this count belongs to, formatted "YYYY-MM"
	// in UTC (see PeriodOf). Part of the composite primary key so a new period
	// starts a fresh row rather than mutating the previous month's total.
	Period string `gorm:"type:varchar(7);primaryKey" json:"period"`
	// Metric names what is being counted (e.g. MetricAPIRequests). Part of the
	// composite primary key so distinct metrics for a tenant/period are
	// distinct rows.
	Metric string `gorm:"type:varchar(64);primaryKey" json:"metric"`
	// Count is the accumulated total. Written only via the additive UPSERT, so
	// concurrent per-replica flushes sum rather than clobber.
	Count int64 `gorm:"not null;default:0" json:"count"`
	// CreatedAt / UpdatedAt bracket the row's life; UpdatedAt advances on every
	// flush so an operator can see when a tenant was last active in a period.
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName pins the table name so the SQL migration and the GORM model target
// the same identifier regardless of GORM pluralization (mirrors
// tenancy.TenantActivity.TableName).
func (TenantUsage) TableName() string { return "tenant_usage" }

// PeriodOf returns the billing-period key for t: its UTC year and month as
// "YYYY-MM". Billing is monthly, so a count is attributed to the month in which
// the request occurred; using UTC makes the boundary deterministic across
// replicas in different local zones.
func PeriodOf(t time.Time) string {
	return t.UTC().Format("2006-01")
}
