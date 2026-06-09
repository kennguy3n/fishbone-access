package models

import (
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// AccessRiskVerdict is one immutable AI risk assessment of an access request,
// persisted for audit. The lifecycle.RiskReviewService appends exactly one row
// each time a request is reviewed (today: once, at creation), and the latest
// row (highest created_at, tie-broken by chain-ordered id) is the operative
// verdict that drives workflow routing. Rows are never mutated or deleted so
// the full risk-assessment trail of a request — including the exact signals fed
// to the model and the model's rationale — is reconstructable for an auditor.
//
// Score is the normalized low/medium/high band; Recommendation is the
// routing-facing verdict (auto_approve_eligible / needs_review / high_risk).
// Both are validated/normalized on the Go side before persistence so a
// malformed model response can never write an out-of-band value. Degraded is
// true when the AI agent was unreachable and the fail-open fallback supplied
// the verdict (which is never auto_approve_eligible), letting the UI and audit
// distinguish an AI-derived score from a degraded one.
//
// Workspace-scoped like every other lifecycle row: a cross-tenant request id is
// invisible because every query filters by workspace_id.
type AccessRiskVerdict struct {
	Base
	WorkspaceID    uuid.UUID      `gorm:"type:uuid;index;not null" json:"workspace_id"`
	RequestID      uuid.UUID      `gorm:"type:uuid;index;not null" json:"request_id"`
	Score          string         `gorm:"not null" json:"score"`
	Recommendation string         `gorm:"not null" json:"recommendation"`
	Factors        datatypes.JSON `json:"factors,omitempty"`
	Rationale      string         `json:"rationale,omitempty"`
	Inputs         datatypes.JSON `json:"inputs,omitempty"`
	Source         string         `gorm:"not null;default:ai_agent" json:"source"`
	Degraded       bool           `gorm:"not null;default:false" json:"degraded"`
}

// AccessRequestAnomalyFlag is one anomaly observation surfaced by the
// access-anomaly-detection skill against an approved elevation. Approved
// elevations are fed to the anomaly skill (fail-open: an unreachable agent
// yields no flags rather than blocking the approval), and any returned
// observation is persisted here so it surfaces both on the request detail and,
// because it is workspace-scoped and grant-linked, inside access reviews.
//
// Anomaly detection is advisory — a flag never changes the FSM state — so these
// rows are informative signals for a human reviewer, not an enforcement gate.
type AccessRequestAnomalyFlag struct {
	Base
	WorkspaceID uuid.UUID  `gorm:"type:uuid;index;not null" json:"workspace_id"`
	RequestID   uuid.UUID  `gorm:"type:uuid;index;not null" json:"request_id"`
	GrantID     *uuid.UUID `gorm:"type:uuid;index" json:"grant_id,omitempty"`
	Kind        string     `gorm:"not null" json:"kind"`
	Severity    string     `json:"severity,omitempty"`
	Reason      string     `json:"reason,omitempty"`
	Confidence  float64    `json:"confidence,omitempty"`
}
