package pam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/aiclient"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// Lease sentinel errors. They are coarse on purpose: a lease in another
// workspace is indistinguishable from a missing one (ErrLeaseNotFound) so the
// service never leaks cross-tenant existence, and the two transition errors map
// to 409 Conflict at the HTTP edge.
var (
	// ErrLeaseNotFound is returned when no lease with the id exists in the
	// workspace.
	ErrLeaseNotFound = errors.New("pam: lease not found")
	// ErrLeaseTerminal is returned when a transition is attempted on a lease
	// that is already revoked or expired (a terminal state).
	ErrLeaseTerminal = errors.New("pam: lease is in a terminal state")
	// ErrLeaseNotApproved is returned when an operation requires a granted lease
	// (e.g. credential brokering) but the lease has not been approved.
	ErrLeaseNotApproved = errors.New("pam: lease is not approved")
)

// maxLeaseTTL bounds an approval's access window. A request may ask for less;
// an approver may not grant more, so a single misconfigured approval cannot
// mint a quasi-permanent privileged credential. Five thousand SME tenants share
// this control plane — the cap is a hard backstop, not advice.
const maxLeaseTTL = 24 * time.Hour

// defaultRequestTTL is applied when neither the request nor the approval names
// a duration and the target carries no LeaseTTLSeconds.
const defaultRequestTTL = 30 * time.Minute

// LeaseNotifier is an optional async sink notified on lease grant and revoke so
// the operator (and the lease subject) learn the window opened or closed
// out-of-band. It is best-effort: a notifier error never fails the transition
// (the audit chain is the durable record), so a flaky notification channel
// cannot block a security-relevant state change. Implementations must be
// non-blocking or self-bounded.
type LeaseNotifier interface {
	LeaseApproved(ctx context.Context, lease *models.PAMLease)
	LeaseRevoked(ctx context.Context, lease *models.PAMLease)
}

// LeaseSessionTerminator tears down any live gateway session bound to a lease
// when the lease leaves its live window (revoked or swept-expired). It is the
// pam.SessionManager in production; declaring it as an interface keeps the
// lease service unit-testable and breaks the otherwise-circular construction
// dependency (the session manager depends on the gateway live-controller, not
// on the lease service). Best-effort: a terminate error is logged, not
// propagated, because the lease transition itself must still commit.
type LeaseSessionTerminator interface {
	TerminateLeaseSessions(ctx context.Context, workspaceID, leaseID uuid.UUID, reason string) error
}

// PAMLeaseService owns the just-in-time lease state machine: it creates leases
// (scoring request-time risk via the AI agent, fail-open), approves them into a
// time-boxed window, revokes them early, and sweeps expired ones. Every
// transition appends to the per-workspace audit hash chain in the same
// transaction as the row mutation, so a lease can never change state without a
// tamper-evident record (and a failed append rolls the transition back).
//
// All reads and writes are workspace-scoped; the workspace id is supplied by
// the caller from the RequireTenant context, never from a request body.
type PAMLeaseService struct {
	db         *gorm.DB
	ai         *aiclient.AIClient
	aiTier     string
	notifier   LeaseNotifier
	terminator LeaseSessionTerminator
	now        func() time.Time
	// afterScan is a test-only seam: when non-nil it runs once in ExpireLeases
	// after the (non-transactional) due-lease scan and before the per-lease
	// claim loop, letting a test deterministically inject a concurrent revoke
	// into the scan→claim window. nil in production.
	afterScan func()
}

// NewPAMLeaseService wires a lease service. ai may be nil (degraded boot): the
// request-time risk assessment then degrades to a fail-open "medium" score
// rather than blocking, because an AI outage must never stop a human-approvable
// access request. notifier and terminator may be nil.
func NewPAMLeaseService(db *gorm.DB, ai *aiclient.AIClient) *PAMLeaseService {
	return &PAMLeaseService{db: db, ai: ai, now: time.Now}
}

// SetClock overrides the time source (tests).
func (s *PAMLeaseService) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// SetAITier selects the per-workspace LLM tier passed to the AI agent ("" →
// the agent's default/deterministic tier).
func (s *PAMLeaseService) SetAITier(tier string) { s.aiTier = tier }

// SetNotifier installs the async grant/revoke notifier.
func (s *PAMLeaseService) SetNotifier(n LeaseNotifier) { s.notifier = n }

// SetSessionTerminator installs the live-session terminator invoked on
// revoke/expire so a lease leaving its live window tears down any session still
// running on it.
func (s *PAMLeaseService) SetSessionTerminator(t LeaseSessionTerminator) { s.terminator = t }

// RequestLeaseInput describes a new JIT lease request. The subject and
// requester are derived by the handler from the validated token, never from the
// request body.
type RequestLeaseInput struct {
	WorkspaceID uuid.UUID
	TargetID    uuid.UUID
	// Subject is the iam-core user the access is for.
	Subject string
	// RequestedBy is the actor creating the request (== Subject unless an
	// operator requests on someone's behalf).
	RequestedBy string
	// TTL is the access window the requester asks for. Zero falls back to the
	// target's LeaseTTLSeconds, then defaultRequestTTL. Clamped to maxLeaseTTL.
	TTL time.Duration
	// Reason is the audited justification.
	Reason string
	// RequestID optionally links to a lifecycle AccessRequest backing this lease.
	RequestID *uuid.UUID
}

// RequestLease creates a lease in the Requested state and scores its risk via
// the AI agent. Risk scoring is advisory and fail-OPEN: an unreachable agent
// yields a degraded "medium" assessment and the request still proceeds to human
// approval. The model's score, factors, and rationale are persisted on the
// lease for audit regardless of whether they came from the model or the
// fallback.
func (s *PAMLeaseService) RequestLease(ctx context.Context, in RequestLeaseInput) (*models.PAMLease, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("pam: PAMLeaseService not initialised")
	}
	if in.WorkspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if in.TargetID == uuid.Nil {
		return nil, fmt.Errorf("%w: target_id is required", ErrValidation)
	}
	if in.Subject == "" {
		return nil, fmt.Errorf("%w: subject is required", ErrValidation)
	}

	// Resolve the target inside its workspace first: a lease can only be
	// requested against a target the caller's tenant owns, and the target's
	// protocol/address feed the risk assessment. A target in another workspace
	// is indistinguishable from a missing one (ErrTargetNotFound).
	var target models.PAMTarget
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", in.WorkspaceID, in.TargetID).
		Take(&target).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrTargetNotFound
		}
		return nil, fmt.Errorf("pam: load target for lease request: %w", err)
	}

	ttl := s.resolveRequestTTL(in.TTL, target.LeaseTTLSeconds)

	// Score risk advisory + fail-OPEN: a model outage must not block a request a
	// human could still approve. The assessment (including the degraded marker)
	// is persisted for audit.
	risk := aiclient.AssessRiskWithFallback(ctx, s.ai, s.aiTier, aiclient.RiskAssessmentInput{
		Role:               target.Username,
		ResourceExternalID: target.Name,
		ResourceTags:       []string{"pam", target.Protocol},
		DurationHours:      durationHoursCeil(ttl),
		Justification:      in.Reason,
	}, false)

	factorsJSON, err := marshalFactors(risk.Factors)
	if err != nil {
		return nil, err
	}

	lease := &models.PAMLease{
		WorkspaceID:         in.WorkspaceID,
		TargetID:            in.TargetID,
		Subject:             in.Subject,
		RequestedBy:         in.RequestedBy,
		Reason:              in.Reason,
		RequestID:           in.RequestID,
		RequestedTTLSeconds: int(ttl.Seconds()),
		RiskLevel:           risk.Score,
		RiskFactors:         factorsJSON,
		RiskReason:          risk.Reason,
		RiskDegraded:        risk.Degraded,
	}
	lease.ID = uuid.New()

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(lease).Error; err != nil {
			return fmt.Errorf("pam: create lease: %w", err)
		}
		return s.auditTx(ctx, tx, in.WorkspaceID, in.RequestedBy, "pam.lease.requested", lease.ID.String(), map[string]any{
			"target_id":     in.TargetID.String(),
			"subject":       in.Subject,
			"ttl_seconds":   lease.RequestedTTLSeconds,
			"risk_level":    risk.Score,
			"risk_degraded": risk.Degraded,
		})
	}); err != nil {
		return nil, err
	}
	s.stampState(lease)
	return lease, nil
}

// ApproveLease grants a requested lease, opening a time-boxed window: it stamps
// granted_at = now and expires_at = now + TTL. It is idempotent — approving an
// already-approved lease returns it unchanged — and fail-closed against terminal
// states: a revoked or expired lease cannot be approved (ErrLeaseTerminal).
//
// durationOverride, when > 0, overrides the requested TTL (clamped to
// maxLeaseTTL); otherwise the requested TTL is used. The window is measured from
// the approval instant, not the request instant, so approval latency does not
// eat into the operator's access window.
func (s *PAMLeaseService) ApproveLease(ctx context.Context, workspaceID, leaseID uuid.UUID, approverID string, durationOverride time.Duration) (*models.PAMLease, error) {
	if workspaceID == uuid.Nil || leaseID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id and lease_id are required", ErrValidation)
	}
	if approverID == "" {
		return nil, fmt.Errorf("%w: approver is required", ErrValidation)
	}

	var out *models.PAMLease
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		lease, err := s.loadForUpdate(ctx, tx, workspaceID, leaseID)
		if err != nil {
			return err
		}
		now := s.now().UTC()

		// Idempotent: an already-granted, still-live lease is returned as-is so a
		// retried approval is a no-op rather than extending the window. Liveness
		// is part of the guard: a granted lease whose TTL has lapsed is terminal,
		// not idempotently-approvable, so it must fall through to the IsTerminal
		// check below and surface ErrLeaseTerminal (409) rather than a silent 200.
		if lease.GrantedAt != nil && lease.RevokedAt == nil &&
			(lease.ExpiresAt == nil || lease.ExpiresAt.After(now)) {
			out = lease
			return nil
		}
		// Fail-closed against terminal states.
		if lease.IsTerminal(now) {
			return fmt.Errorf("%w: cannot approve lease %s", ErrLeaseTerminal, leaseID)
		}

		// The granted window may differ from the requester's ask (an approver can
		// shorten/extend via durationOverride). We do NOT write it back over
		// requested_ttl_seconds: that column stays the immutable record of what
		// was asked for, and the granted window is captured durably by expires_at
		// (granted TTL == expires_at - granted_at). The approve audit records the
		// granted TTL explicitly below.
		ttl := s.resolveApprovalTTL(durationOverride, lease.RequestedTTLSeconds)
		expires := now.Add(ttl)
		if err := tx.Model(&models.PAMLease{}).
			Where("workspace_id = ? AND id = ? AND granted_at IS NULL AND revoked_at IS NULL", workspaceID, leaseID).
			Updates(map[string]any{
				"granted_at":  now,
				"expires_at":  expires,
				"approved_by": approverID,
				"updated_at":  now,
			}).Error; err != nil {
			return fmt.Errorf("pam: approve lease: %w", err)
		}
		lease.GrantedAt = &now
		lease.ExpiresAt = &expires
		lease.ApprovedBy = approverID
		out = lease
		return s.auditTx(ctx, tx, workspaceID, approverID, "pam.lease.approved", leaseID.String(), map[string]any{
			"subject":     lease.Subject,
			"expires_at":  expires.Format(time.RFC3339),
			"ttl_seconds": int(ttl.Seconds()),
		})
	})
	if err != nil {
		return nil, err
	}
	s.stampState(out)
	if s.notifier != nil && out.ActivatedAt == nil {
		s.notifier.LeaseApproved(ctx, out)
	}
	return out, nil
}

// RevokeLease ends a lease early. It is idempotent (revoking an already-revoked
// lease is a no-op) and works from any non-revoked state, including Requested
// (denying a pending request) and Expired (recording an explicit kill on a
// lease whose TTL also lapsed — revoke takes precedence in the derived state).
// On revoke it tears down any live session bound to the lease so the credential
// stops being brokered immediately.
func (s *PAMLeaseService) RevokeLease(ctx context.Context, workspaceID, leaseID uuid.UUID, actor, reason string) (*models.PAMLease, error) {
	if workspaceID == uuid.Nil || leaseID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id and lease_id are required", ErrValidation)
	}

	var out *models.PAMLease
	alreadyRevoked := false
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		lease, err := s.loadForUpdate(ctx, tx, workspaceID, leaseID)
		if err != nil {
			return err
		}
		if lease.RevokedAt != nil {
			alreadyRevoked = true
			out = lease
			return nil
		}
		now := s.now().UTC()
		if err := tx.Model(&models.PAMLease{}).
			Where("workspace_id = ? AND id = ? AND revoked_at IS NULL", workspaceID, leaseID).
			Updates(map[string]any{
				"revoked_at":    now,
				"revoke_reason": reason,
				"updated_at":    now,
			}).Error; err != nil {
			return fmt.Errorf("pam: revoke lease: %w", err)
		}
		lease.RevokedAt = &now
		lease.RevokeReason = reason
		out = lease
		return s.auditTx(ctx, tx, workspaceID, actor, "pam.lease.revoked", leaseID.String(), map[string]any{
			"subject": lease.Subject,
			"reason":  reason,
		})
	})
	if err != nil {
		return nil, err
	}
	s.stampState(out)
	if !alreadyRevoked {
		s.terminateLeaseSessions(ctx, workspaceID, leaseID, "lease revoked")
		if s.notifier != nil {
			s.notifier.LeaseRevoked(ctx, out)
		}
	}
	return out, nil
}

// ExpireLeases is the TTL auto-expire sweep. It finds every live lease whose
// expires_at has passed, appends a pam.lease.expired audit event for each, and
// tears down any session still running on it. It returns the number of leases
// expired. Expiry is application-layer (cron), not a database TTL, so each
// expiry is audited and its sessions are cleaned up — a silently-dropped row
// would leave an orphaned live session brokering a credential past its window.
//
// The sweep is workspace-scoped and idempotent via the expired_at marker: only
// leases that are live (granted, not revoked), past their TTL, AND not yet
// swept (expired_at IS NULL) are processed, and each is stamped expired_at in
// the same transaction as its audit append. Re-running the cron therefore
// neither double-audits nor re-tears-down an already-swept lease. The stamp is
// conditional (WHERE expired_at IS NULL) so two concurrent sweepers cannot both
// claim the same lease.
func (s *PAMLeaseService) ExpireLeases(ctx context.Context, workspaceID uuid.UUID) (int, error) {
	if workspaceID == uuid.Nil {
		return 0, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	now := s.now().UTC()

	var due []models.PAMLease
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND granted_at IS NOT NULL AND revoked_at IS NULL AND expired_at IS NULL AND expires_at IS NOT NULL AND expires_at <= ?", workspaceID, now).
		Find(&due).Error; err != nil {
		return 0, fmt.Errorf("pam: scan expired leases: %w", err)
	}

	if s.afterScan != nil {
		s.afterScan()
	}

	expired := 0
	for i := range due {
		lease := &due[i]
		claimed := false
		// Stamp expired_at and audit the expiry atomically. The conditional
		// update claims the lease for exactly one sweeper; if another sweeper
		// already claimed it (RowsAffected == 0) we skip the audit/teardown so
		// the side-effects run once. expired_at is a bookkeeping marker only —
		// the derived "expired" state still comes from expires_at.
		//
		// The claim re-checks revoked_at IS NULL inside the transaction (the
		// scan above is non-transactional): if RevokeLease lands between the
		// scan and this claim, revoke wins (it already stamped, audited, and tore
		// down the session), so we must not also stamp expired_at and append a
		// misleading pam.lease.expired event to the tamper-evident chain.
		if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			res := tx.Model(&models.PAMLease{}).
				Where("workspace_id = ? AND id = ? AND expired_at IS NULL AND revoked_at IS NULL", workspaceID, lease.ID).
				Updates(map[string]any{"expired_at": now, "updated_at": now})
			if res.Error != nil {
				return fmt.Errorf("pam: claim expired lease: %w", res.Error)
			}
			if res.RowsAffected == 0 {
				return nil
			}
			claimed = true
			return s.auditTx(ctx, tx, workspaceID, "system", "pam.lease.expired", lease.ID.String(), map[string]any{
				"subject":    lease.Subject,
				"expired_at": now.Format(time.RFC3339),
			})
		}); err != nil {
			logger.Errorf(ctx, "pam: audit lease expiry %s: %v", lease.ID, err)
			continue
		}
		if !claimed {
			continue
		}
		s.terminateLeaseSessions(ctx, workspaceID, lease.ID, "lease expired")
		expired++
	}
	return expired, nil
}

// GetLease loads a single lease scoped to its workspace, with the derived state
// stamped.
func (s *PAMLeaseService) GetLease(ctx context.Context, workspaceID, leaseID uuid.UUID) (*models.PAMLease, error) {
	if workspaceID == uuid.Nil || leaseID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id and lease_id are required", ErrValidation)
	}
	var lease models.PAMLease
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, leaseID).
		Take(&lease).Error
	switch {
	case err == nil:
		s.stampState(&lease)
		return &lease, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, ErrLeaseNotFound
	default:
		return nil, fmt.Errorf("pam: load lease: %w", err)
	}
}

// ListLeasesFilters narrows ListLeases.
type ListLeasesFilters struct {
	TargetID   uuid.UUID
	Subject    string
	ActiveOnly bool
	Limit      int
}

// ListLeases returns a workspace's leases newest-first, each with its derived
// state stamped. ActiveOnly restricts to leases that are currently live
// (granted, not revoked, not expired).
func (s *PAMLeaseService) ListLeases(ctx context.Context, workspaceID uuid.UUID, f ListLeasesFilters) ([]models.PAMLease, error) {
	if workspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	q := s.db.WithContext(ctx).Where("workspace_id = ?", workspaceID)
	if f.TargetID != uuid.Nil {
		q = q.Where("target_id = ?", f.TargetID)
	}
	if f.Subject != "" {
		q = q.Where("subject = ?", f.Subject)
	}
	if f.ActiveOnly {
		now := s.now().UTC()
		q = q.Where("granted_at IS NOT NULL AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)", now)
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var leases []models.PAMLease
	if err := q.Order("created_at DESC").Limit(limit).Find(&leases).Error; err != nil {
		return nil, fmt.Errorf("pam: list leases: %w", err)
	}
	for i := range leases {
		s.stampState(&leases[i])
	}
	return leases, nil
}

// ValidateActiveLease reports whether a lease currently authorizes brokering a
// credential. It is the predicate the connect-token broker consults before
// minting or redeeming a lease-bound token. The check is intentionally a hard
// cliff on expiry — a lease one second past its window is no longer
// authoritative. When targetID is non-nil it also enforces the confused-deputy
// guard: a lease for target-A must not authorize a session against target-B even
// inside the same workspace.
func (s *PAMLeaseService) ValidateActiveLease(ctx context.Context, workspaceID, leaseID uuid.UUID, subject string, targetID uuid.UUID) error {
	if workspaceID == uuid.Nil || leaseID == uuid.Nil {
		return fmt.Errorf("%w: workspace_id and lease_id are required", ErrValidation)
	}
	var lease models.PAMLease
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, leaseID).
		Take(&lease).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrLeaseNotFound
		}
		return fmt.Errorf("pam: load lease for validation: %w", err)
	}
	return s.validateLease(&lease, subject, targetID)
}

// ValidateLeaseTx is the broker's transactional liveness check: it loads the
// lease inside the redemption transaction (so it sees the same snapshot as the
// token consume) and applies the live-lease + subject/target guards. It
// satisfies the connect-token broker's LeaseValidator contract.
func (s *PAMLeaseService) ValidateLeaseTx(ctx context.Context, tx *gorm.DB, workspaceID, leaseID uuid.UUID, subject string, targetID uuid.UUID) error {
	var lease models.PAMLease
	if err := tx.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, leaseID).
		Take(&lease).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrLeaseNotFound
		}
		return fmt.Errorf("pam: load lease for validation: %w", err)
	}
	return s.validateLease(&lease, subject, targetID)
}

// MarkActivatedTx flips an approved lease to active on first session open by
// stamping activated_at (if not already set) inside tx. It is idempotent — a
// lease that already has a session keeps its original activation time — so the
// approved→active transition records the first redemption only.
func (s *PAMLeaseService) MarkActivatedTx(ctx context.Context, tx *gorm.DB, workspaceID, leaseID uuid.UUID, now time.Time) error {
	if err := tx.WithContext(ctx).Model(&models.PAMLease{}).
		Where("workspace_id = ? AND id = ? AND activated_at IS NULL", workspaceID, leaseID).
		Updates(map[string]any{"activated_at": now.UTC(), "updated_at": now.UTC()}).Error; err != nil {
		return fmt.Errorf("pam: mark lease activated: %w", err)
	}
	return nil
}

// loadForUpdate loads a lease for a transition inside tx with a row lock so
// concurrent transitions on the same lease serialize.
func (s *PAMLeaseService) loadForUpdate(ctx context.Context, tx *gorm.DB, workspaceID, leaseID uuid.UUID) (*models.PAMLease, error) {
	var lease models.PAMLease
	err := tx.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("workspace_id = ? AND id = ?", workspaceID, leaseID).
		Take(&lease).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrLeaseNotFound
		}
		return nil, fmt.Errorf("pam: load lease for update: %w", err)
	}
	return &lease, nil
}

// validateLease applies the live-lease predicate plus the subject/target
// confused-deputy guards.
func (s *PAMLeaseService) validateLease(lease *models.PAMLease, subject string, targetID uuid.UUID) error {
	now := s.now().UTC()
	if lease.GrantedAt == nil {
		return fmt.Errorf("%w: lease %s", ErrLeaseNotApproved, lease.ID)
	}
	if lease.RevokedAt != nil {
		return fmt.Errorf("%w: lease %s is revoked", ErrLeaseTerminal, lease.ID)
	}
	if lease.ExpiresAt != nil && !lease.ExpiresAt.After(now) {
		return fmt.Errorf("%w: lease %s is expired", ErrLeaseTerminal, lease.ID)
	}
	if subject != "" && lease.Subject != subject {
		return fmt.Errorf("%w: lease %s is bound to a different subject", ErrValidation, lease.ID)
	}
	if targetID != uuid.Nil && lease.TargetID != targetID {
		return fmt.Errorf("%w: lease %s is bound to a different target", ErrValidation, lease.ID)
	}
	return nil
}

// terminateLeaseSessions tears down live sessions bound to a lease, best-effort.
func (s *PAMLeaseService) terminateLeaseSessions(ctx context.Context, workspaceID, leaseID uuid.UUID, reason string) {
	if s.terminator == nil {
		return
	}
	if err := s.terminator.TerminateLeaseSessions(ctx, workspaceID, leaseID, reason); err != nil {
		logger.Errorf(ctx, "pam: terminate sessions for lease %s: %v", leaseID, err)
	}
}

// durationHoursCeil reports an access window in whole hours, rounding up. The
// risk scorer's DurationHours is an int and risk is monotonic in duration, so a
// sub-hour or fractional window must never be truncated down (a 30-minute lease
// is one hour of exposure, not zero; 90 minutes is two, not one). Returns 0 only
// for a non-positive duration, which the TTL resolvers never produce.
func durationHoursCeil(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int((d + time.Hour - 1) / time.Hour)
}

func (s *PAMLeaseService) resolveRequestTTL(req time.Duration, targetTTLSeconds int) time.Duration {
	ttl := req
	if ttl <= 0 && targetTTLSeconds > 0 {
		ttl = time.Duration(targetTTLSeconds) * time.Second
	}
	if ttl <= 0 {
		ttl = defaultRequestTTL
	}
	if ttl > maxLeaseTTL {
		ttl = maxLeaseTTL
	}
	return ttl
}

func (s *PAMLeaseService) resolveApprovalTTL(override time.Duration, requestedSeconds int) time.Duration {
	ttl := override
	if ttl <= 0 {
		ttl = time.Duration(requestedSeconds) * time.Second
	}
	if ttl <= 0 {
		ttl = defaultRequestTTL
	}
	if ttl > maxLeaseTTL {
		ttl = maxLeaseTTL
	}
	return ttl
}

// stampState fills the transient derived State field for API responses.
func (s *PAMLeaseService) stampState(lease *models.PAMLease) {
	if lease != nil {
		lease.State = lease.Status(s.now().UTC())
	}
}

// auditTx appends one lease event to the workspace audit hash chain inside tx.
func (s *PAMLeaseService) auditTx(ctx context.Context, tx *gorm.DB, workspaceID uuid.UUID, actor, action, targetRef string, meta map[string]any) error {
	md, err := marshalMeta(meta)
	if err != nil {
		return err
	}
	return lifecycle.AppendAuditTx(ctx, tx, s.now(), lifecycle.AuditInput{
		WorkspaceID: workspaceID,
		Actor:       actor,
		Action:      action,
		TargetRef:   targetRef,
		Metadata:    md,
	})
}

// marshalFactors encodes the AI risk factors slice as JSON for the
// risk_factors column, tolerating an empty slice (→ "[]").
func marshalFactors(factors []string) (datatypes.JSON, error) {
	if len(factors) == 0 {
		return datatypes.JSON([]byte("[]")), nil
	}
	b, err := json.Marshal(factors)
	if err != nil {
		return nil, fmt.Errorf("pam: marshal risk factors: %w", err)
	}
	return datatypes.JSON(b), nil
}
