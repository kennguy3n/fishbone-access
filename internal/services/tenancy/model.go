package tenancy

import (
	"time"

	"github.com/google/uuid"
)

// Lifecycle states for a tenant. The state machine is intentionally tiny:
//
//	active  ──(idle ≥ threshold, set by Reconcile)──▶  dormant
//	dormant ──(any recorded activity, by RecordActivity)──▶  active
//
// State is the authoritative signal the HibernationGate reads. It is persisted
// (not derived on read) so the gate is a single indexed primary-key lookup and
// so a wake is observable (the dormant→active transition reports whether it
// fired) rather than recomputed from timestamps on every check.
const (
	StateActive  = "active"
	StateDormant = "dormant"
)

// Activity kinds label what woke or touched a tenant. They are advisory
// (observability only) — classification depends solely on LastActivityAt — but
// they make the audit trail and metrics legible ("woken by api" vs "by sync").
const (
	KindAPI         = "api"
	KindLogin       = "login"
	KindSync        = "sync"
	KindAdmin       = "admin"
	KindProvisioned = "provisioned"
	KindUnknown     = "unknown"
)

// TenantActivity is the per-tenant activity + dormancy record. Exactly one row
// per workspace (workspace_id is the primary key), created lazily by the first
// RecordActivity or seeded by Reconcile from the workspace's creation time, so
// a trial that has never been touched is still classified correctly.
//
// It deliberately does NOT embed models.Base: the identity is the workspace_id
// (1:1 with the tenant), there is no surrogate UUID, and the row is operational
// state that is hard-updated in place rather than soft-deleted. The schema is
// reproduced for production in internal/migrations/0018_tenant_activity.sql; the
// struct is the source of truth for GORM auto-migrate on the SQLite test path.
type TenantActivity struct {
	// WorkspaceID is the tenant boundary (FK to workspaces.id), 1:1 with an
	// iam-core tenant_id. Primary key: one activity row per tenant.
	WorkspaceID uuid.UUID `gorm:"type:uuid;primaryKey" json:"workspace_id"`
	// LastActivityAt is the most recent real interaction. Indexed because the
	// Reconcile sweep classifies on (state, last_activity_at) ranges.
	LastActivityAt time.Time `gorm:"not null;index" json:"last_activity_at"`
	// LastActivityKind is advisory: which surface last touched the tenant.
	LastActivityKind string `gorm:"type:varchar(32);not null;default:unknown" json:"last_activity_kind"`
	// State is "active" or "dormant" — the gate's authoritative signal.
	State string `gorm:"type:varchar(16);not null;default:active;index" json:"state"`
	// StateChangedAt is when State last transitioned (observability/SLA).
	StateChangedAt time.Time `gorm:"not null" json:"state_changed_at"`
	// HibernatedAt / WokenAt record the most recent transition timestamps; nil
	// until the first transition of each kind. They are reporting aids, not
	// part of the classification logic.
	HibernatedAt *time.Time `json:"hibernated_at,omitempty"`
	WokenAt      *time.Time `json:"woken_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// TableName pins the table name so the migration and the GORM model target the
// same identifier regardless of GORM pluralization.
func (TenantActivity) TableName() string { return "tenant_activity" }

// Dormant reports whether the tenant is currently hibernated.
func (a TenantActivity) Dormant() bool { return a.State == StateDormant }

// TenantResourceBudget is the per-tenant resource budget: a tier plus optional
// explicit caps. A zero cap means "inherit the tier default" (see TierBudget),
// so an operator can pin one knob for one tenant without restating the whole
// budget. Exactly one row per workspace; absence ⇒ the configured default tier.
//
// The schema is reproduced for production in
// internal/migrations/0019_tenant_resource_budgets.sql.
type TenantResourceBudget struct {
	WorkspaceID uuid.UUID `gorm:"type:uuid;primaryKey" json:"workspace_id"`
	// Tier names the budget class ("trial" | "base" | "pro" | "enterprise").
	Tier string `gorm:"type:varchar(32);not null;default:trial" json:"tier"`
	// MaxConcurrentSyncs caps simultaneous periodic jobs (connector syncs,
	// reconciles) for this tenant. 0 ⇒ inherit the tier default.
	MaxConcurrentSyncs int `gorm:"not null;default:0" json:"max_concurrent_syncs"`
	// MaxPeriodicJobsPerHour rate-limits how often a tenant's periodic work may
	// be scheduled. 0 ⇒ inherit the tier default.
	MaxPeriodicJobsPerHour int `gorm:"not null;default:0" json:"max_periodic_jobs_per_hour"`
	// FairShareWeight biases the FairScheduler so higher tiers get a larger
	// share of the global periodic-work budget. 0 ⇒ inherit the tier default.
	FairShareWeight int       `gorm:"not null;default:0" json:"fair_share_weight"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// TableName pins the table name (see TenantActivity.TableName).
func (TenantResourceBudget) TableName() string { return "tenant_resource_budgets" }
