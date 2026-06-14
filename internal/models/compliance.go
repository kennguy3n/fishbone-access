package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// Certification-campaign states. The lifecycle is running → closed; closing a
// campaign applies the staged revoke decisions (the destructive teardown is
// deferred to close so it can be previewed first — the same test-before-effect
// guardrail the policy promote path enforces). There is no separate "decided"
// state: whether every item carries a terminal decision is derived for the
// report rather than stored, so the state machine stays minimal and the
// "all decided" signal can never drift from the underlying item rows.
const (
	CertificationStateRunning = "running"
	CertificationStateClosed  = "closed"
)

// Per-grant certification decisions. Mirror the access-review vocabulary so
// the two surfaces read consistently, but a revoke here is STAGED (recorded
// without tearing the grant down) and only applied when the campaign closes.
const (
	CertificationDecisionPending  = "pending"
	CertificationDecisionCertify  = "certify"
	CertificationDecisionRevoke   = "revoke"
	CertificationDecisionEscalate = "escalate"
)

// CertificationCampaign is a scoped, reviewer-assigned, due-dated access
// certification campaign — the "full" expansion of the AccessReview primitive.
// Scope fields narrow which live grants are enumerated into items; an empty
// scope field matches every grant. Reviewers is a JSON array of iam-core user
// ids assigned to the worklist (advisory: any tenant operator may decide, but
// the worklist surfaces a reviewer's queue). Framework optionally tags the
// campaign with the compliance framework it evidences. Everything is
// workspace-scoped.
type CertificationCampaign struct {
	Base
	WorkspaceID      uuid.UUID      `gorm:"type:uuid;index;not null" json:"workspace_id"`
	Name             string         `gorm:"not null" json:"name"`
	State            string         `gorm:"not null;default:running" json:"state"`
	Framework        string         `json:"framework,omitempty"`
	ScopeResource    string         `json:"scope_resource,omitempty"`
	ScopeRole        string         `json:"scope_role,omitempty"`
	ScopeConnectorID *uuid.UUID     `gorm:"type:uuid" json:"scope_connector_id,omitempty"`
	Reviewers        datatypes.JSON `json:"reviewers,omitempty"`
	DueAt            *time.Time     `json:"due_at,omitempty"`
	StartedAt        *time.Time     `json:"started_at,omitempty"`
	ClosedAt         *time.Time     `json:"closed_at,omitempty"`
	// OverdueAt is stamped the first time a running campaign is observed past
	// its DueAt with pending items, so the overdue transition is audited exactly
	// once rather than re-fired on every sweep.
	OverdueAt *time.Time `json:"overdue_at,omitempty"`
}

// CertificationItem is one per-grant certification decision within a campaign.
// StartCampaign enumerates the in-scope active grants into pending items;
// reviewers then certify / revoke / escalate each one. RevokedAt is stamped
// when a staged revoke is actually applied at campaign close, which makes
// re-closing idempotent and the teardown independently auditable.
type CertificationItem struct {
	Base
	WorkspaceID uuid.UUID  `gorm:"type:uuid;index;not null" json:"workspace_id"`
	CampaignID  uuid.UUID  `gorm:"type:uuid;index;not null" json:"campaign_id"`
	GrantID     uuid.UUID  `gorm:"type:uuid;index;not null" json:"grant_id"`
	Reviewer    string     `json:"reviewer,omitempty"`
	Decision    string     `gorm:"not null;default:pending" json:"decision"`
	DecidedBy   string     `json:"decided_by,omitempty"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	Reason      string     `json:"reason,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}
