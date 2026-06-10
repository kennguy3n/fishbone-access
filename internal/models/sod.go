package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// Separation-of-Duties (SoD) governance models.
//
// SoD analytics catch *toxic entitlement combinations* — pairs of entitlements
// that are individually fine but dangerous when held together by the same
// identity (the classic "create-vendor" + "approve-payment" fraud pair). This
// is a different concern from the pairwise grant-vs-deny PolicyConflict
// detector: a conflict is two policies disagreeing about the SAME (subject,
// resource) pair, whereas an SoD violation is one subject accumulating two
// DIFFERENT entitlements that must stay segregated.
//
// A rule is expressed as two entitlement *selectors* (A and B). Each selector
// matches a held entitlement — an (resource, role) pair drawn from a subject's
// live AccessGrants — by resource and role, where the empty string or "*" is a
// wildcard. A subject violates the rule when their effective entitlement set
// contains two distinct entitlements, one matching selector A and one matching
// selector B. Selector evaluation lives in the lifecycle SoD engine so the
// models package stays free of business logic.

// SoD rule severities, ordered low → critical. The engine treats high and
// critical as "blocking" for the catastrophic-change promote guardrail; low and
// medium are flagged for review but do not block.
const (
	SodSeverityLow      = "low"
	SodSeverityMedium   = "medium"
	SodSeverityHigh     = "high"
	SodSeverityCritical = "critical"
)

// SodRule models one toxic entitlement combination for a workspace. ResourceA/
// RoleA and ResourceB/RoleB are the two entitlement selectors; an empty value
// or "*" is a wildcard that matches any resource/role. Only Enabled rules are
// evaluated, so an operator can retire a rule without losing its history.
type SodRule struct {
	Base
	WorkspaceID uuid.UUID `gorm:"type:uuid;index;not null" json:"workspace_id"`
	Name        string    `gorm:"not null" json:"name"`
	Description string    `json:"description,omitempty"`
	Severity    string    `gorm:"not null;default:high" json:"severity"`
	Enabled     bool      `gorm:"not null;default:true" json:"enabled"`

	// Selector A.
	ResourceA string `gorm:"not null;default:*" json:"resource_a"`
	RoleA     string `gorm:"not null;default:*" json:"role_a"`
	// Selector B.
	ResourceB string `gorm:"not null;default:*" json:"resource_b"`
	RoleB     string `gorm:"not null;default:*" json:"role_b"`
}

// TableName pins the table created by internal/migrations/0020_sod_rules.sql.
func (SodRule) TableName() string { return "sod_rules" }

// Access-anomaly dispositions. A scheduled detector records an anomaly already
// auto-triaged ("flagged") so the dispositioned-anomaly evidence the SOC2 CC7.3
// control reads (orphan.detected + orphan.disposition.*) is produced without an
// operator round-trip; an operator may later escalate or acknowledge it.
const (
	AnomalyDispositionFlagged      = "flagged"
	AnomalyDispositionAcknowledged = "acknowledged"
	AnomalyDispositionResolved     = "resolved"
)

// Access-anomaly kinds.
const (
	AnomalyKindSodViolation = "sod_violation"
)

// AccessAnomaly is a detected, dispositioned access anomaly — currently an SoD
// toxic-combination violation found among a workspace's LIVE grants by the
// scheduled detector (as opposed to a what-if simulation, which never
// persists). It exists so the detector is idempotent (Fingerprint dedupes a
// recurring violation across sweeps) and so operators get a real anomaly
// worklist. Detection and disposition each append to the per-workspace audit
// hash chain, which is where the compliance evidence stream is projected from —
// this model is the detector's own state, not a parallel evidence log.
//
// Lives in sod.go because the only anomaly source today is the SoD engine; new
// anomaly kinds would extend this type rather than add a parallel table.
type AccessAnomaly struct {
	Base
	WorkspaceID uuid.UUID      `gorm:"type:uuid;index;not null" json:"workspace_id"`
	Kind        string         `gorm:"not null" json:"kind"`
	Subject     string         `gorm:"index;not null" json:"subject"`
	RuleID      *uuid.UUID     `gorm:"type:uuid;index" json:"rule_id,omitempty"`
	Severity    string         `gorm:"not null;default:high" json:"severity"`
	Detail      datatypes.JSON `json:"detail,omitempty"`
	Disposition string         `gorm:"not null;default:flagged" json:"disposition"`
	DetectedAt  time.Time      `json:"detected_at"`
	// Fingerprint is a stable digest of (kind, subject, rule, entitlement pair)
	// so re-detecting the same standing violation on the next sweep is a no-op
	// instead of emitting duplicate evidence. Unique per workspace.
	Fingerprint string `gorm:"not null;index" json:"fingerprint"`
}

// TableName pins the table created by internal/migrations/0021_access_anomalies.sql.
func (AccessAnomaly) TableName() string { return "access_anomalies" }
