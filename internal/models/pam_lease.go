package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// PAM lease states. A lease is the unit of just-in-time privileged access: an
// operator Requests it, an approver Approves it (which grants a time-boxed
// window), the credential broker turns an approved lease Active the moment a
// session is opened against it, and the lease finally Expires (its TTL elapses)
// or is Revoked (an admin kills it early). The state is DERIVED from the
// (granted_at, activated_at, expires_at, revoked_at) tuple rather than stored
// in a column, so the database can never disagree with the timestamps that are
// the real source of truth — the same derived-state convention the lifecycle
// AccessGrant model uses. PAMLease.Status is the single function that maps the
// tuple to one of these labels.
const (
	// PAMLeaseStateRequested: awaiting approval (granted_at is nil).
	PAMLeaseStateRequested = "requested"
	// PAMLeaseStateApproved: granted and within its TTL window but no session
	// has been opened yet (granted_at set, activated_at nil). The credential is
	// brokerable in this state — opening a session transitions it to active.
	PAMLeaseStateApproved = "approved"
	// PAMLeaseStateActive: granted, within TTL, and at least one session has
	// been opened against the lease (activated_at set).
	PAMLeaseStateActive = "active"
	// PAMLeaseStateExpired: granted but the TTL window has closed (expires_at is
	// in the past) without a revoke. Terminal.
	PAMLeaseStateExpired = "expired"
	// PAMLeaseStateRevoked: an admin (or the holder) killed the lease before its
	// TTL elapsed (revoked_at set). Terminal, and takes precedence over expiry.
	PAMLeaseStateRevoked = "revoked"
)

// PAMLease is one just-in-time grant of privileged access to a PAMTarget for a
// single subject. It is workspace-scoped and its lifecycle is a strict state
// machine (Requested → Approved → Active → Expired/Revoked) enforced by
// PAMLeaseService with every transition appended to the workspace audit hash
// chain.
//
// The credential broker (connect-token mint/redeem) is gated on the lease being
// live (granted, not revoked, not expired): a target's sealed secret is only
// ever decrypted into a session that a live lease authorizes, so expiring or
// revoking the lease immediately removes the holder's ability to open new
// sessions and the expiry/revoke sweep terminates any session still running on
// it. This is what binds "the credential is brokered only while Active" to the
// lease rather than to the long-lived target row.
//
// Risk fields capture the AI risk assessment computed at request time (the
// Bonsai Ternary-8B via the server-side aiclient). The assessment is advisory
// and fail-OPEN — an unreachable model yields a degraded "medium" score and the
// request still proceeds to human approval — but the model's score, factors,
// and rationale are persisted here for audit regardless.
type PAMLease struct {
	Base
	WorkspaceID uuid.UUID `gorm:"type:uuid;index;not null" json:"workspace_id"`
	TargetID    uuid.UUID `gorm:"type:uuid;index;not null" json:"target_id"`
	// Subject is the iam-core user_id the lease grants access for. The credential
	// broker requires the redeeming subject to equal this value.
	Subject string `gorm:"index;not null" json:"subject"`
	// RequestedBy is the iam-core subject that created the request (usually the
	// same as Subject; differs when an operator requests on someone's behalf).
	RequestedBy string `gorm:"not null" json:"requested_by"`
	// Reason is the justification supplied at request time (audited).
	Reason string `json:"reason,omitempty"`
	// RequestID optionally links the lease to the lifecycle AccessRequest row
	// that backs it, so the JIT lease and the joiner/mover request lane share one
	// approval history. Nil when the lease is requested directly.
	RequestID *uuid.UUID `gorm:"type:uuid;index" json:"request_id,omitempty"`
	// ApprovedBy is the iam-core subject that approved the lease (audited).
	ApprovedBy string `json:"approved_by,omitempty"`
	// RequestedTTLSeconds is the access window the requester asked for. It is
	// set once at request time and never overwritten — an approver who grants a
	// different window (via duration override) does not mutate this field, so it
	// stays the durable record of the original ask. The granted window is
	// ExpiresAt (the effective expiry); the granted TTL is ExpiresAt-GrantedAt.
	RequestedTTLSeconds int `gorm:"not null;default:0" json:"requested_ttl_seconds"`

	// RiskLevel/RiskFactors/RiskReason/RiskDegraded capture the request-time AI
	// risk assessment (persisted for audit even when degraded).
	RiskLevel    string         `json:"risk_level,omitempty"`
	RiskFactors  datatypes.JSON `json:"risk_factors,omitempty"`
	RiskReason   string         `json:"risk_reason,omitempty"`
	RiskDegraded bool           `gorm:"not null;default:false" json:"risk_degraded"`

	GrantedAt   *time.Time `json:"granted_at,omitempty"`
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	// ExpiredAt records when the TTL-expiry sweep observed and audited this
	// lease's expiry. It is NOT the source of the derived "expired" state (that
	// remains expires_at, the hard cliff) — it is purely the sweep's
	// idempotency + side-effect marker: the sweep only audits the expiry and
	// tears down sessions for leases where it is still nil, so re-running the
	// cron does not double-audit a lease that already expired.
	ExpiredAt    *time.Time `json:"expired_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokeReason string     `json:"revoke_reason,omitempty"`

	// State is a transient, derived field populated by the service layer (which
	// owns the clock) before the lease is returned to a caller. It is never
	// stored (gorm:"-") so the timestamp tuple remains the single source of
	// truth; it exists so API responses carry the machine state without every
	// client re-deriving it.
	State string `gorm:"-" json:"state,omitempty"`
}

// Status maps the lease's timestamp tuple to its machine state at instant now.
// Revoked takes precedence over expiry (an explicit kill is recorded as a
// revoke even if the TTL also lapsed), and expiry takes precedence over
// active/approved.
func (l *PAMLease) Status(now time.Time) string {
	switch {
	case l.RevokedAt != nil:
		return PAMLeaseStateRevoked
	case l.GrantedAt == nil:
		return PAMLeaseStateRequested
	case l.ExpiresAt != nil && !l.ExpiresAt.After(now):
		return PAMLeaseStateExpired
	case l.ActivatedAt != nil:
		return PAMLeaseStateActive
	default:
		return PAMLeaseStateApproved
	}
}

// IsLive reports whether the lease currently authorizes brokering a credential:
// it has been granted, has not been revoked, and has not expired. This is the
// canonical predicate the connect-token broker consults before minting or
// redeeming a token, and the expiry/revoke sweep consults before deciding a
// running session must be torn down.
func (l *PAMLease) IsLive(now time.Time) bool {
	return l.GrantedAt != nil &&
		l.RevokedAt == nil &&
		(l.ExpiresAt == nil || l.ExpiresAt.After(now))
}

// IsTerminal reports whether the lease has reached a state from which no
// further transition is possible (revoked, or expired). A terminal lease cannot
// be approved or re-activated.
func (l *PAMLease) IsTerminal(now time.Time) bool {
	s := l.Status(now)
	return s == PAMLeaseStateRevoked || s == PAMLeaseStateExpired
}
