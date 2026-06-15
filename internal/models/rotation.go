package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Credential rotation models.
//
// These back the automatic-rotation feature layered on top of the PAM vault:
// a per-target RotationPolicy drives interval / on-checkin rotation and
// dynamic database credentials; a RotationEvent is the queryable per-target
// history of rotation attempts; a DynamicCredential tracks the lifecycle of an
// ephemeral per-lease database role so a reaper can drop it upstream when the
// lease ends. All three are workspace-scoped and covered by the RLS
// tenant_isolation policy (see internal/migrations/0050–0052).

// Rotation modes govern the time-interval sweep. rotate_on_checkin and dynamic
// credentials are orthogonal booleans on the policy, not modes.
const (
	// RotationModeDisabled means no interval rotation (the default). The policy
	// may still rotate on checkin or issue dynamic credentials if those flags
	// are set.
	RotationModeDisabled = "disabled"
	// RotationModeInterval rotates the sealed credential every IntervalSeconds.
	RotationModeInterval = "interval"
)

// Rotation triggers identify what caused a rotation attempt; recorded on every
// RotationEvent.
const (
	RotationTriggerManual    = "manual"
	RotationTriggerScheduled = "scheduled"
	RotationTriggerCheckin   = "checkin"
)

// Rotation outcome statuses.
const (
	RotationStatusSuccess = "success"
	RotationStatusFailed  = "failed"
)

// Dynamic credential lifecycle states. A credential leaves Active only once the
// upstream role has actually been dropped (or the drop is no longer possible),
// so the reaper's active-set scan is authoritative.
const (
	DynamicCredentialStateActive  = "active"
	DynamicCredentialStateRevoked = "revoked"
	DynamicCredentialStateExpired = "expired"
	DynamicCredentialStateFailed  = "failed"
)

// MinRotationInterval is the smallest accepted interval for interval rotation.
// A floor keeps a misconfigured policy from hammering an upstream and keeps the
// scheduler's per-tenant work bounded at 5k-tenant scale.
const MinRotationInterval = time.Hour

// RotationPolicy is the per-workspace, per-target rotation configuration. Each
// live target has at most one policy (enforced by uq_pam_rotation_policies_target).
type RotationPolicy struct {
	Base
	WorkspaceID uuid.UUID `gorm:"type:uuid;index;not null" json:"workspace_id"`
	TargetID    uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:uq_pam_rotation_policies_target,where:deleted_at IS NULL" json:"target_id"`

	Mode              string `gorm:"not null;default:disabled" json:"mode"`
	IntervalSeconds   int64  `gorm:"not null;default:0" json:"interval_seconds"`
	RotateOnCheckin   bool   `gorm:"not null;default:false" json:"rotate_on_checkin"`
	DynamicEnabled    bool   `gorm:"not null;default:false" json:"dynamic_enabled"`
	DynamicTTLSeconds int64  `gorm:"not null;default:0" json:"dynamic_ttl_seconds"`
	Enabled           bool   `gorm:"not null;default:true" json:"enabled"`

	LastRotationAt *time.Time `json:"last_rotation_at,omitempty"`
	NextRotationAt *time.Time `json:"next_rotation_at,omitempty"`
	LastStatus     string     `json:"last_status,omitempty"`
	LastError      string     `json:"last_error,omitempty"`
}

// TableName pins the table so the acronymless struct name does not drift from
// the migration's pam_-prefixed table.
func (RotationPolicy) TableName() string { return "pam_rotation_policies" }

// IntervalRotationActive reports whether the policy should be swept on the
// time interval. A disabled policy, a non-interval mode, or a non-positive
// interval all mean "never on a timer".
func (p *RotationPolicy) IntervalRotationActive() bool {
	return p != nil && p.Enabled && p.Mode == RotationModeInterval && p.IntervalSeconds > 0
}

// Interval returns the configured rotation interval as a duration.
func (p *RotationPolicy) Interval() time.Duration {
	if p == nil || p.IntervalSeconds <= 0 {
		return 0
	}
	return time.Duration(p.IntervalSeconds) * time.Second
}

// ComputeNextRotation returns the next-due instant for interval rotation given
// a base time (normally the moment of the rotation that just completed), or nil
// when the policy is not on a timer. Storing this lets the scheduler select due
// policies with a single indexed range scan rather than recomputing per row.
func (p *RotationPolicy) ComputeNextRotation(from time.Time) *time.Time {
	if !p.IntervalRotationActive() {
		return nil
	}
	next := from.Add(p.Interval())
	return &next
}

// DynamicTTL returns the lifetime of a dynamic credential minted under this
// policy, or 0 when dynamic credentials are not enabled / no TTL is set.
func (p *RotationPolicy) DynamicTTL() time.Duration {
	if p == nil || !p.DynamicEnabled || p.DynamicTTLSeconds <= 0 {
		return 0
	}
	return time.Duration(p.DynamicTTLSeconds) * time.Second
}

// RotationEvent is one row of per-target rotation history. The authoritative
// tamper-evident record remains the audit hash chain; this is the projection
// the console timeline reads.
type RotationEvent struct {
	ID          uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	WorkspaceID uuid.UUID  `gorm:"type:uuid;index;not null" json:"workspace_id"`
	TargetID    uuid.UUID  `gorm:"type:uuid;not null" json:"target_id"`
	PolicyID    *uuid.UUID `gorm:"type:uuid" json:"policy_id,omitempty"`
	Trigger     string     `gorm:"not null" json:"trigger"`
	Status      string     `gorm:"not null" json:"status"`
	Protocol    string     `json:"protocol,omitempty"`
	Actor       string     `json:"actor,omitempty"`
	LeaseID     *uuid.UUID `gorm:"type:uuid" json:"lease_id,omitempty"`
	KeyVersion  int        `gorm:"not null;default:0" json:"key_version"`
	Detail      string     `json:"detail,omitempty"`
	Error       string     `json:"error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// TableName pins the table name.
func (RotationEvent) TableName() string { return "pam_rotation_events" }

// BeforeCreate assigns a UUID + creation timestamp when unset. RotationEvent
// does not embed Base (it is immutable — no updated_at / soft delete), so it
// carries its own hook rather than relying on a Postgres-only column default,
// keeping the SQLite test path working.
func (e *RotationEvent) BeforeCreate(*gorm.DB) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	return nil
}

// DynamicCredential tracks the lifecycle of an ephemeral per-lease database
// role. The role's password is returned to the caller once at mint time and is
// never persisted (same posture as a connect token).
type DynamicCredential struct {
	Base
	WorkspaceID uuid.UUID  `gorm:"type:uuid;index;not null" json:"workspace_id"`
	TargetID    uuid.UUID  `gorm:"type:uuid;not null" json:"target_id"`
	LeaseID     *uuid.UUID `gorm:"type:uuid;index" json:"lease_id,omitempty"`
	Protocol    string     `gorm:"not null" json:"protocol"`
	DBUsername  string     `gorm:"not null" json:"db_username"`
	State       string     `gorm:"not null;default:active" json:"state"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
}

// TableName pins the table name.
func (DynamicCredential) TableName() string { return "pam_dynamic_credentials" }

// IsLive reports whether a dynamic credential is still active and unexpired at
// the given instant.
func (c *DynamicCredential) IsLive(now time.Time) bool {
	if c == nil || c.State != DynamicCredentialStateActive {
		return false
	}
	return c.ExpiresAt == nil || c.ExpiresAt.After(now)
}
