package models

import (
	"time"

	"github.com/google/uuid"
)

// Contractor / external access lifecycle models.
//
// Contractor access is time-boxed by construction: every grant carries a
// mandatory ExpiresAt and a named internal sponsor who owns the engagement.
// The lifecycle is request → sponsor approval → provisioned active grant →
// automatic expiry (which runs the JML leaver kill switch to deprovision
// everywhere). An expiry can be pushed out only by a sponsor-approved, audited
// extension (ContractorGrantExtension), never silently — so external access can
// never outlive its justification.

// Contractor-grant lifecycle states.
const (
	ContractorStatePendingApproval = "pending_approval"
	ContractorStateActive          = "active"
	ContractorStateRejected        = "rejected"
	ContractorStateExpired         = "expired"
	ContractorStateRevoked         = "revoked"
)

// ContractorGrant is a time-boxed, sponsor-approved external/contractor access
// grant. ContractorUserID is the connector-side (iam-core) identity the access
// is for; SponsorID is the internal owner accountable for it. ExpiresAt is
// mandatory — a contractor grant with no expiry is rejected at creation. GrantID
// links to the materialized AccessGrant once the grant is approved and
// provisioned, so expiry/revocation can deprovision the real entitlement.
type ContractorGrant struct {
	Base
	WorkspaceID      uuid.UUID  `gorm:"type:uuid;index;not null" json:"workspace_id"`
	ContractorUserID string     `gorm:"index;not null" json:"contractor_user_id"`
	DisplayName      string     `json:"display_name,omitempty"`
	ConnectorID      uuid.UUID  `gorm:"type:uuid;index;not null" json:"connector_id"`
	ResourceRef      string     `gorm:"not null" json:"resource_ref"`
	Role             string     `json:"role"`
	SponsorID        string     `gorm:"index;not null" json:"sponsor_id"`
	RequestedBy      string     `json:"requested_by,omitempty"`
	Justification    string     `json:"justification,omitempty"`
	State            string     `gorm:"not null;default:pending_approval" json:"state"`
	ExpiresAt        time.Time  `gorm:"not null;index" json:"expires_at"`
	ApprovedBy       string     `json:"approved_by,omitempty"`
	ApprovedAt       *time.Time `json:"approved_at,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	GrantID          *uuid.UUID `gorm:"type:uuid;index" json:"grant_id,omitempty"`
}

// TableName pins the table created by internal/migrations/0022_contractor_grants.sql.
func (ContractorGrant) TableName() string { return "contractor_grants" }

// ContractorGrantExtension records one sponsor-approved extension of a
// contractor grant's expiry. Every extension is its own audited row (old → new
// expiry, approver, reason) so the full time-box history of an external
// engagement is reconstructable — an auditor can see exactly when and by whom
// access was prolonged, never just the latest ExpiresAt.
type ContractorGrantExtension struct {
	Base
	WorkspaceID       uuid.UUID `gorm:"type:uuid;index;not null" json:"workspace_id"`
	ContractorGrantID uuid.UUID `gorm:"type:uuid;index;not null" json:"contractor_grant_id"`
	PreviousExpiresAt time.Time `gorm:"not null" json:"previous_expires_at"`
	NewExpiresAt      time.Time `gorm:"not null" json:"new_expires_at"`
	ApprovedBy        string    `gorm:"not null" json:"approved_by"`
	Reason            string    `json:"reason,omitempty"`
}

// TableName pins the table created by internal/migrations/0023_contractor_grant_extensions.sql.
func (ContractorGrantExtension) TableName() string { return "contractor_grant_extensions" }
