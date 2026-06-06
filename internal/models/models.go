// Package models defines the GORM database models for the ShieldNet Access
// control plane. Every tenant-scoped row carries a WorkspaceID that maps 1:1 to
// an iam-core tenant_id (see docs/iam-core-integration.md); all queries MUST be
// scoped by workspace to enforce tenant isolation.
//
// The schema here is the canonical source for GORM auto-migrate in dev/test.
// Production schema evolution goes through the ordered SQL files in
// internal/migrations, which are kept consistent with these structs.
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// Base is embedded by every model: a UUID primary key and audit timestamps.
//
// DeletedAt is gorm.DeletedAt (not *time.Time) so GORM v2 activates soft
// delete: Delete emits UPDATE ... SET deleted_at = now() and every query is
// implicitly scoped WHERE deleted_at IS NULL. With a plain *time.Time GORM
// would hard-DELETE rows and return soft-deleted records, so the choice here is
// load-bearing for the 1B–1E handlers that query these models. The underlying
// column stays a nullable TIMESTAMPTZ (gorm.DeletedAt is sql.NullTime), matching
// internal/migrations/0001_init.sql, and still marshals to null/omitted in JSON.
type Base struct {
	ID        uuid.UUID      `gorm:"type:uuid;primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// Workspace is the top-level tenant isolation boundary. WorkspaceID == iam-core
// tenant_id for every downstream row.
type Workspace struct {
	Base
	Name            string `gorm:"not null" json:"name"`
	IAMCoreTenantID string `gorm:"uniqueIndex;not null" json:"iam_core_tenant_id"`
	Plan            string `gorm:"not null;default:base" json:"plan"`
	DataResidency   string `json:"data_residency,omitempty"`
	DefaultLocale   string `gorm:"default:en" json:"default_locale"`
	SSOConnectionID string `json:"sso_connection_id,omitempty"`
}

// Team is a group of members within a workspace.
type Team struct {
	Base
	WorkspaceID uuid.UUID `gorm:"type:uuid;index;not null" json:"workspace_id"`
	Name        string    `gorm:"not null" json:"name"`
	Description string    `json:"description,omitempty"`
}

// TeamMember binds an iam-core user to a team with a role.
type TeamMember struct {
	Base
	WorkspaceID   uuid.UUID `gorm:"type:uuid;index;not null" json:"workspace_id"`
	TeamID        uuid.UUID `gorm:"type:uuid;index;not null" json:"team_id"`
	IAMCoreUserID string    `gorm:"index;not null" json:"iam_core_user_id"`
	Role          string    `gorm:"not null;default:member" json:"role"`
}

// AccessConnector is a configured integration with an external identity or
// resource provider. Secrets is an AES-GCM sealed envelope (never plaintext).
type AccessConnector struct {
	Base
	WorkspaceID    uuid.UUID      `gorm:"type:uuid;index;not null" json:"workspace_id"`
	Provider       string         `gorm:"not null" json:"provider"`
	DisplayName    string         `json:"display_name"`
	Status         string         `gorm:"not null;default:pending" json:"status"`
	Config         datatypes.JSON `json:"config"`
	SecretEnvelope string         `json:"-"`
	LastSyncedAt   *time.Time     `json:"last_synced_at,omitempty"`
}

// AccessJob is a unit of background work (sync, provision, revoke) for the
// access-connector-worker queue.
type AccessJob struct {
	Base
	WorkspaceID uuid.UUID      `gorm:"type:uuid;index;not null" json:"workspace_id"`
	ConnectorID uuid.UUID      `gorm:"type:uuid;index" json:"connector_id"`
	Type        string         `gorm:"not null" json:"type"`
	Status      string         `gorm:"not null;default:queued" json:"status"`
	Attempts    int            `gorm:"not null;default:0" json:"attempts"`
	Payload     datatypes.JSON `json:"payload"`
	LastError   string         `json:"last_error,omitempty"`
	RunAfter    time.Time      `json:"run_after"`
}

// AccessRequest is a user's request for access to a resource, driven through
// the request state machine (requested → approved → provisioning → ...).
//
// TargetUserID is the iam-core user the access is for; it defaults to
// RequesterID for a self-service request but differs when an admin requests
// access on behalf of another user (and for JML joiner-driven requests). The
// provisioning service uses TargetUserID as the connector's external user id.
type AccessRequest struct {
	Base
	WorkspaceID   uuid.UUID      `gorm:"type:uuid;index;not null" json:"workspace_id"`
	RequesterID   string         `gorm:"index;not null" json:"requester_id"`
	TargetUserID  string         `gorm:"index" json:"target_user_id,omitempty"`
	ConnectorID   *uuid.UUID     `gorm:"type:uuid;index" json:"connector_id,omitempty"`
	ResourceRef   string         `gorm:"not null" json:"resource_ref"`
	Role          string         `json:"role"`
	Justification string         `json:"justification"`
	State         string         `gorm:"not null;default:requested" json:"state"`
	RiskLevel     string         `json:"risk_level,omitempty"`
	RiskFactors   datatypes.JSON `json:"risk_factors,omitempty"`
	ExpiresAt     *time.Time     `json:"expires_at,omitempty"`
}

// AccessRequestStateHistory is one immutable transition record for an access
// request. The AccessRequestService writes one row per FSM transition inside
// the same transaction that mutates AccessRequest.State, so the lifecycle and
// its audit trail can never diverge. The initial "" → requested row is written
// at creation time.
type AccessRequestStateHistory struct {
	Base
	WorkspaceID uuid.UUID `gorm:"type:uuid;index;not null" json:"workspace_id"`
	RequestID   uuid.UUID `gorm:"type:uuid;index;not null" json:"request_id"`
	FromState   string    `json:"from_state"`
	ToState     string    `gorm:"not null" json:"to_state"`
	Actor       string    `json:"actor,omitempty"`
	Reason      string    `json:"reason,omitempty"`
}

// AccessGrant is an active (or revoked) entitlement materialised on a provider.
type AccessGrant struct {
	Base
	WorkspaceID   uuid.UUID  `gorm:"type:uuid;index;not null" json:"workspace_id"`
	RequestID     *uuid.UUID `gorm:"type:uuid;index" json:"request_id,omitempty"`
	ConnectorID   uuid.UUID  `gorm:"type:uuid;index;not null" json:"connector_id"`
	IAMCoreUserID string     `gorm:"index;not null" json:"iam_core_user_id"`
	ResourceRef   string     `gorm:"not null" json:"resource_ref"`
	Role          string     `json:"role"`
	State         string     `gorm:"not null;default:active" json:"state"`
	GrantedAt     time.Time  `json:"granted_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}

// AccessReview is an access-certification campaign over a set of grants.
type AccessReview struct {
	Base
	WorkspaceID uuid.UUID  `gorm:"type:uuid;index;not null" json:"workspace_id"`
	Name        string     `gorm:"not null" json:"name"`
	State       string     `gorm:"not null;default:active" json:"state"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// Policy is an access policy with a draft/simulate/promote lifecycle. Drafts
// never touch the data plane. Definition holds the JSON rule
// ({action, subjects, resources}); DraftImpact caches the last Simulate output
// while State is still "draft"; PromotedAt is stamped when a draft is promoted
// to State "active".
type Policy struct {
	Base
	WorkspaceID uuid.UUID      `gorm:"type:uuid;index;not null" json:"workspace_id"`
	Name        string         `gorm:"not null" json:"name"`
	State       string         `gorm:"not null;default:draft" json:"state"`
	Version     int            `gorm:"not null;default:1" json:"version"`
	Definition  datatypes.JSON `json:"definition"`
	DraftImpact datatypes.JSON `json:"draft_impact,omitempty"`
	PromotedAt  *time.Time     `json:"promoted_at,omitempty"`
}

// AccessReviewItem is one per-grant certification decision within an
// AccessReview campaign. StartCampaign enumerates the workspace's active grants
// into pending items; reviewers then certify / revoke / escalate each one.
type AccessReviewItem struct {
	Base
	WorkspaceID uuid.UUID  `gorm:"type:uuid;index;not null" json:"workspace_id"`
	ReviewID    uuid.UUID  `gorm:"type:uuid;index;not null" json:"review_id"`
	GrantID     uuid.UUID  `gorm:"type:uuid;index;not null" json:"grant_id"`
	Decision    string     `gorm:"not null;default:pending" json:"decision"`
	DecidedBy   string     `json:"decided_by,omitempty"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	Reason      string     `json:"reason,omitempty"`
}

// AccessOrphanAccount is an upstream provider account with no matching live
// grant in ShieldNet Access, surfaced by the OrphanReconciler. Disposition is
// the operator's decision (pending → ignore | disable).
type AccessOrphanAccount struct {
	Base
	WorkspaceID    uuid.UUID `gorm:"type:uuid;index;not null" json:"workspace_id"`
	ConnectorID    uuid.UUID `gorm:"type:uuid;index;not null" json:"connector_id"`
	ExternalUserID string    `gorm:"not null" json:"external_user_id"`
	DisplayName    string    `json:"display_name,omitempty"`
	Disposition    string    `gorm:"not null;default:pending" json:"disposition"`
}

// AuditEvent is a tamper-evident audit record. ChainHash links rows into a
// per-workspace SHA-256 hash chain (PrevHash → ChainHash).
type AuditEvent struct {
	Base
	WorkspaceID uuid.UUID      `gorm:"type:uuid;index;not null" json:"workspace_id"`
	Actor       string         `json:"actor"`
	Action      string         `gorm:"not null" json:"action"`
	TargetRef   string         `json:"target_ref,omitempty"`
	Metadata    datatypes.JSON `json:"metadata,omitempty"`
	PrevHash    string         `json:"prev_hash,omitempty"`
	ChainHash   string         `gorm:"not null" json:"chain_hash"`
}

// All returns every model for GORM auto-migrate. Keep in sync with the SQL
// migrations in internal/migrations.
func All() []any {
	return []any{
		&Workspace{},
		&Team{},
		&TeamMember{},
		&AccessConnector{},
		&AccessJob{},
		&AccessRequest{},
		&AccessRequestStateHistory{},
		&AccessGrant{},
		&AccessReview{},
		&AccessReviewItem{},
		&Policy{},
		&AccessOrphanAccount{},
		&AuditEvent{},
	}
}
