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
// resource provider. SecretEnvelope is an AES-GCM sealed envelope (never
// plaintext); SecretKeyVersion records which per-workspace DEK version sealed
// it so the envelope encryptor can resolve the right key to open it across DEK
// rotations.
type AccessConnector struct {
	Base
	WorkspaceID      uuid.UUID      `gorm:"type:uuid;index;not null" json:"workspace_id"`
	Provider         string         `gorm:"not null" json:"provider"`
	DisplayName      string         `json:"display_name"`
	Status           string         `gorm:"not null;default:pending" json:"status"`
	Config           datatypes.JSON `json:"config"`
	SecretEnvelope   string         `json:"-"`
	SecretKeyVersion int            `gorm:"not null;default:1" json:"-"`
	LastSyncedAt     *time.Time     `json:"last_synced_at,omitempty"`
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
type AccessRequest struct {
	Base
	WorkspaceID   uuid.UUID  `gorm:"type:uuid;index;not null" json:"workspace_id"`
	RequesterID   string     `gorm:"index;not null" json:"requester_id"`
	ResourceRef   string     `gorm:"not null" json:"resource_ref"`
	Role          string     `json:"role"`
	Justification string     `json:"justification"`
	State         string     `gorm:"not null;default:requested" json:"state"`
	RiskLevel     string     `json:"risk_level,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
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
}

// AccessReview is an access-certification campaign over a set of grants.
type AccessReview struct {
	Base
	WorkspaceID uuid.UUID  `gorm:"type:uuid;index;not null" json:"workspace_id"`
	Name        string     `gorm:"not null" json:"name"`
	State       string     `gorm:"not null;default:draft" json:"state"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// Policy is an access policy with a draft/simulate/promote lifecycle. Drafts
// never touch the data plane.
type Policy struct {
	Base
	WorkspaceID uuid.UUID      `gorm:"type:uuid;index;not null" json:"workspace_id"`
	Name        string         `gorm:"not null" json:"name"`
	State       string         `gorm:"not null;default:draft" json:"state"`
	Version     int            `gorm:"not null;default:1" json:"version"`
	Definition  datatypes.JSON `json:"definition"`
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

// AccessSyncState persists per-connector incremental-sync checkpoints. A
// delta-capable provider (e.g. Microsoft Entra / Graph) hands back an opaque
// delta link or cursor at the end of each sync; storing it here lets the next
// run fetch only what changed instead of a full re-enumeration. Scoped by
// workspace for tenant isolation; one row per (workspace, connector, sync_type).
type AccessSyncState struct {
	Base
	WorkspaceID  uuid.UUID  `gorm:"type:uuid;index;not null;uniqueIndex:uq_sync_state" json:"workspace_id"`
	ConnectorID  uuid.UUID  `gorm:"type:uuid;index;not null;uniqueIndex:uq_sync_state" json:"connector_id"`
	SyncType     string     `gorm:"not null;default:identities;uniqueIndex:uq_sync_state" json:"sync_type"`
	DeltaLink    string     `json:"delta_link,omitempty"`
	LastSyncedAt *time.Time `json:"last_synced_at,omitempty"`
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
		&AccessGrant{},
		&AccessReview{},
		&Policy{},
		&AuditEvent{},
		&AccessSyncState{},
	}
}
