package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// Grant states stored in models.AccessGrant.State.
const (
	GrantStateActive  = "active"
	GrantStateRevoked = "revoked"
	GrantStateExpired = "expired"
)

// ResolvedConnector is a connector ready to call: the registered
// implementation plus its decrypted config and secrets. The provisioning
// service depends on this (via ConnectorResolver) rather than on connector
// secret-sealing details, which are owned by the connector-management layer
// (Session 1B). This keeps 1C independent of 1B at compile time.
type ResolvedConnector struct {
	Provider string
	Impl     access.AccessConnector
	Config   map[string]any
	Secrets  map[string]any
}

// ConnectorResolver turns a workspace's connector id into a ResolvedConnector.
// Implementations load the connector row, open its sealed secret envelope, and
// look up the registered implementation. The provisioning/JML/reconciler
// services depend only on this interface.
type ConnectorResolver interface {
	Resolve(ctx context.Context, workspaceID, connectorID uuid.UUID) (*ResolvedConnector, error)
}

// AccessProvisioningService orchestrates the approved → provisioning →
// provisioned → active leg (and the provision_failed retry path) against a
// connector. Network I/O to the provider happens OUTSIDE any DB transaction;
// the state flip + access_grants insert happen together in a transaction so a
// materialized grant always has a matching provisioned/active request.
type AccessProvisioningService struct {
	db          *gorm.DB
	requests    *AccessRequestService
	resolver    ConnectorResolver
	now         func() time.Time
	maxAttempts int
	backoff     func(attempt int) time.Duration
}

// NewAccessProvisioningService wires the provisioning service. requests and
// resolver must be non-nil. Retry defaults to 3 attempts with a short linear
// backoff; tests shorten the backoff via SetRetryPolicy.
func NewAccessProvisioningService(db *gorm.DB, requests *AccessRequestService, resolver ConnectorResolver) *AccessProvisioningService {
	return &AccessProvisioningService{
		db:          db,
		requests:    requests,
		resolver:    resolver,
		now:         time.Now,
		maxAttempts: 3,
		backoff:     func(attempt int) time.Duration { return time.Duration(attempt) * 200 * time.Millisecond },
	}
}

// SetClock overrides the time source (tests).
func (s *AccessProvisioningService) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// SetRetryPolicy overrides retry attempts and backoff (tests use 0 backoff).
func (s *AccessProvisioningService) SetRetryPolicy(maxAttempts int, backoff func(attempt int) time.Duration) {
	if maxAttempts > 0 {
		s.maxAttempts = maxAttempts
	}
	if backoff != nil {
		s.backoff = backoff
	}
}

// Provision drives an approved (or previously failed) request to a live grant.
// On connector success the request ends in StateActive with an access_grants
// row; on connector failure (after retries) it ends in StateProvisionFailed and
// the error is returned and recorded — the request can be retried by calling
// Provision again.
func (s *AccessProvisioningService) Provision(ctx context.Context, workspaceID, requestID uuid.UUID, actor string) (*models.AccessGrant, error) {
	req, err := s.requests.GetRequest(ctx, workspaceID, requestID)
	if err != nil {
		return nil, err
	}
	if req.ConnectorID == nil || *req.ConnectorID == uuid.Nil {
		return nil, fmt.Errorf("%w: request %s has no connector", ErrConnectorNotConfigured, requestID)
	}

	// Move into provisioning from either approved or a prior failure.
	switch req.State {
	case StateApproved:
		if err := s.transition(ctx, workspaceID, requestID, StateProvisioning, actor, "provisioning started"); err != nil {
			return nil, err
		}
	case StateProvisionFailed:
		if err := s.transition(ctx, workspaceID, requestID, StateProvisioning, actor, "provisioning retry"); err != nil {
			return nil, err
		}
	case StateProvisioning:
		// Already provisioning (e.g. a crashed prior attempt); continue.
	default:
		return nil, fmt.Errorf("%w: cannot provision a request in state %q", ErrInvalidStateTransition, req.State)
	}

	resolved, err := s.resolver.Resolve(ctx, workspaceID, *req.ConnectorID)
	if err != nil {
		// Could not even resolve the connector: fail the request so it is not
		// stuck in provisioning, then surface the error.
		_ = s.transition(ctx, workspaceID, requestID, StateProvisionFailed, actor, "connector resolve failed: "+err.Error())
		// Surface the resolver's own error verbatim: Resolve wraps a genuinely
		// unusable connector (missing row / unknown provider / no encryptor) with
		// ErrConnectorNotConfigured (→422) but leaves transient DB/decode errors
		// unwrapped (→500). Re-wrapping everything with ErrConnectorNotConfigured
		// would misreport a DB outage as "connector not configured".
		return nil, err
	}

	grant := access.AccessGrant{
		UserExternalID:     req.TargetUserID,
		ResourceExternalID: req.ResourceRef,
		Role:               req.Role,
		GrantedAt:          s.now(),
		ExpiresAt:          req.ExpiresAt,
	}
	provErr := s.withRetry(ctx, func() error {
		return resolved.Impl.ProvisionAccess(ctx, resolved.Config, resolved.Secrets, grant)
	})
	if provErr != nil {
		_ = s.transition(ctx, workspaceID, requestID, StateProvisionFailed, actor, "connector provision failed: "+provErr.Error())
		return nil, fmt.Errorf("lifecycle: provision access: %w", provErr)
	}

	// Success: materialize the grant and flip provisioning → provisioned →
	// active atomically.
	now := s.now()
	row := &models.AccessGrant{
		WorkspaceID:   workspaceID,
		RequestID:     &requestID,
		ConnectorID:   *req.ConnectorID,
		IAMCoreUserID: req.TargetUserID,
		ResourceRef:   req.ResourceRef,
		Role:          req.Role,
		State:         GrantStateActive,
		GrantedAt:     now,
		ExpiresAt:     req.ExpiresAt,
	}
	// Assign the id up front rather than relying on the BeforeCreate hook so the
	// audit event below records the real grant id regardless of GORM callback
	// ordering (a zero id in the audit trail would be silently wrong).
	row.ID = uuid.New()
	row.CreatedAt = now
	row.UpdatedAt = now

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Idempotency guard for crash/retry: ProvisionAccess ran before this
		// transaction, so a prior attempt that succeeded at the provider but
		// crashed (or a concurrent provision) may already have materialized the
		// grant. There is one live grant per request by construction, so if one
		// already exists, reuse it instead of inserting a duplicate row. The
		// FOR UPDATE row lock TransitionInTx takes below serializes concurrent
		// provisions of the same request so only one reaches the Create.
		var existing models.AccessGrant
		findErr := tx.WithContext(ctx).
			Where("workspace_id = ? AND request_id = ? AND state = ? AND revoked_at IS NULL", workspaceID, requestID, GrantStateActive).
			Take(&existing).Error
		switch {
		case findErr == nil:
			// A live grant already exists for this request (a prior attempt that
			// committed, or a concurrent provision). Reuse it instead of inserting
			// a duplicate. In the normal path the grant insert and the
			// provisioned→active transitions commit together in this transaction,
			// so the request is already active here. Reconcile defensively so the
			// request state can never lag a materialized grant even if that
			// atomicity is ever changed: drive a still-pending request forward to
			// active. This is a no-op when the request is already active.
			row = &existing
			return s.reconcileToActive(ctx, tx, workspaceID, requestID, actor)
		case errors.Is(findErr, gorm.ErrRecordNotFound):
			// No live grant yet — fall through to materialize one.
		default:
			return fmt.Errorf("lifecycle: check existing grant: %w", findErr)
		}

		if _, err := s.requests.TransitionInTx(ctx, tx, workspaceID, requestID, StateProvisioned, actor, "connector provisioned"); err != nil {
			return err
		}
		if err := tx.Create(row).Error; err != nil {
			return fmt.Errorf("lifecycle: insert access_grant: %w", err)
		}
		if _, err := s.requests.TransitionInTx(ctx, tx, workspaceID, requestID, StateActive, actor, "grant active"); err != nil {
			return err
		}
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      "access_grant.created",
			TargetRef:   row.ID.String(),
		})
	})
	if err != nil {
		return nil, err
	}
	return row, nil
}

// reconcileToActive drives a request that already has a live grant up to
// StateActive, walking provisioning → provisioned → active as needed. It runs
// inside the provision idempotency guard's transaction and is a no-op when the
// request is already active (the normal case, since the grant insert and the
// active transition commit together) or terminal. It exists so the guard's
// "reuse the existing grant" path can never leave the request state lagging a
// materialized grant.
func (s *AccessProvisioningService) reconcileToActive(ctx context.Context, tx *gorm.DB, workspaceID, requestID uuid.UUID, actor string) error {
	var req models.AccessRequest
	if err := forUpdate(tx.WithContext(ctx)).
		Where("workspace_id = ? AND id = ?", workspaceID, requestID).
		Take(&req).Error; err != nil {
		return fmt.Errorf("lifecycle: load request for reconcile: %w", err)
	}
	switch req.State {
	case StateProvisioning:
		if _, err := s.requests.TransitionInTx(ctx, tx, workspaceID, requestID, StateProvisioned, actor, "reconcile: connector provisioned"); err != nil {
			return err
		}
		if _, err := s.requests.TransitionInTx(ctx, tx, workspaceID, requestID, StateActive, actor, "reconcile: grant active"); err != nil {
			return err
		}
	case StateProvisioned:
		if _, err := s.requests.TransitionInTx(ctx, tx, workspaceID, requestID, StateActive, actor, "reconcile: grant active"); err != nil {
			return err
		}
	default:
		// active (normal case) or terminal — nothing to reconcile.
	}
	return nil
}

// ProvisionAtProvider resolves the connector and calls ProvisionAccess (with
// the same retry policy as Provision) WITHOUT writing any row. A caller that
// owns its own aggregate — e.g. the contractor lifecycle materializing a grant
// bound to a contractor_grants row — uses this so it can insert the resulting
// access_grant inside its own transaction and keep the two writes atomic. It
// returns the resolver's classified error on failure (sentinel → 422, raw → 500)
// and the connector error (wrapped) when the provider call itself fails.
func (s *AccessProvisioningService) ProvisionAtProvider(ctx context.Context, workspaceID, connectorID uuid.UUID, grant access.AccessGrant) error {
	if connectorID == uuid.Nil {
		return fmt.Errorf("%w: connector is required to provision", ErrValidation)
	}
	resolved, err := s.resolver.Resolve(ctx, workspaceID, connectorID)
	if err != nil {
		return err
	}
	if err := s.withRetry(ctx, func() error {
		return resolved.Impl.ProvisionAccess(ctx, resolved.Config, resolved.Secrets, grant)
	}); err != nil {
		return fmt.Errorf("lifecycle: provision access at provider: %w", err)
	}
	return nil
}

// RevokeGrant revokes a live grant on the provider and flips the grant (and its
// originating request, if any) to revoked. It is idempotent: a grant that is
// already revoked returns nil so the leaver kill switch can re-run cleanly.
func (s *AccessProvisioningService) RevokeGrant(ctx context.Context, workspaceID, grantID uuid.UUID, actor, reason string) error {
	var g models.AccessGrant
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, grantID).
		Take(&g).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrGrantNotFound
	}
	if err != nil {
		return fmt.Errorf("lifecycle: load grant for revoke: %w", err)
	}
	if g.State != GrantStateActive {
		// Only a live (active) grant can be revoked. An already-revoked grant
		// makes the leaver kill switch's re-run a clean no-op; an expired grant is
		// likewise already torn down at the provider, so revoke is a no-op rather
		// than flipping expired→revoked and losing the expiry record.
		return nil
	}

	resolved, err := s.resolver.Resolve(ctx, workspaceID, g.ConnectorID)
	if err != nil {
		// Preserve Resolve's classification (sentinel → 422, raw DB error → 500).
		return err
	}
	grant := access.AccessGrant{
		UserExternalID:     g.IAMCoreUserID,
		ResourceExternalID: g.ResourceRef,
		Role:               g.Role,
	}
	if revErr := s.withRetry(ctx, func() error {
		return resolved.Impl.RevokeAccess(ctx, resolved.Config, resolved.Secrets, grant)
	}); revErr != nil {
		return fmt.Errorf("lifecycle: revoke access: %w", revErr)
	}

	return s.markGrantRevoked(ctx, workspaceID, &g, actor, reason)
}

// ExpireGrant revokes a grant on the provider and flips the grant (and its
// originating request, if any) to expired. Used by the expiry enforcer for
// grants past their ExpiresAt. Idempotent on an already-terminal grant.
func (s *AccessProvisioningService) ExpireGrant(ctx context.Context, workspaceID, grantID uuid.UUID, actor string) error {
	var g models.AccessGrant
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, grantID).
		Take(&g).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrGrantNotFound
	}
	if err != nil {
		return fmt.Errorf("lifecycle: load grant for expiry: %w", err)
	}
	if g.State != GrantStateActive {
		return nil // idempotent no-op: only a live grant can expire
	}

	resolved, err := s.resolver.Resolve(ctx, workspaceID, g.ConnectorID)
	if err != nil {
		// Preserve Resolve's classification (sentinel → 422, raw DB error → 500).
		return err
	}
	if revErr := s.withRetry(ctx, func() error {
		return resolved.Impl.RevokeAccess(ctx, resolved.Config, resolved.Secrets, access.AccessGrant{
			UserExternalID:     g.IAMCoreUserID,
			ResourceExternalID: g.ResourceRef,
			Role:               g.Role,
		})
	}); revErr != nil {
		return fmt.Errorf("lifecycle: revoke expired access: %w", revErr)
	}
	return s.markGrantTerminal(ctx, workspaceID, &g, GrantStateExpired, StateExpired, actor, "grant expired")
}

// markGrantRevoked flips the grant + originating request to revoked in one
// transaction. Split out so the leaver kill switch can reuse it.
func (s *AccessProvisioningService) markGrantRevoked(ctx context.Context, workspaceID uuid.UUID, g *models.AccessGrant, actor, reason string) error {
	return s.markGrantTerminal(ctx, workspaceID, g, GrantStateRevoked, StateRevoked, actor, reason)
}

// markGrantTerminal flips a grant to a terminal grant state (revoked/expired)
// and, when it backs an active request, drives that request to the matching
// terminal request state — all in one transaction.
func (s *AccessProvisioningService) markGrantTerminal(ctx context.Context, workspaceID uuid.UUID, g *models.AccessGrant, grantState string, reqState RequestState, actor, reason string) error {
	now := s.now()
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// revoked_at marks a *revocation*, not termination in general. An expired
		// grant is terminal too, but stamping revoked_at on it would conflate the
		// two states in the API (a grant reporting state="expired" with a
		// revoked_at timestamp is a contradiction) and would let consumers no
		// longer tell automatic expiry from manual revoke. The grant's state +
		// updated_at + expires_at already record the expiry; every "live grant"
		// query pairs revoked_at IS NULL with state = 'active', so leaving
		// revoked_at NULL for the expired path is safe.
		updates := map[string]any{"state": grantState, "updated_at": now}
		if grantState == GrantStateRevoked {
			updates["revoked_at"] = now
		}
		if err := tx.Model(&models.AccessGrant{}).
			Where("workspace_id = ? AND id = ?", workspaceID, g.ID).
			Updates(updates).Error; err != nil {
			return fmt.Errorf("lifecycle: update grant %s: %w", grantState, err)
		}
		// Best-effort request transition: only active requests move on.
		if g.RequestID != nil {
			var req models.AccessRequest
			if err := tx.WithContext(ctx).
				Where("workspace_id = ? AND id = ?", workspaceID, *g.RequestID).
				Take(&req).Error; err == nil && req.State == StateActive {
				if _, err := s.requests.TransitionInTx(ctx, tx, workspaceID, *g.RequestID, reqState, actor, reason); err != nil {
					return err
				}
			}
		}
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      "access_grant." + grantState,
			TargetRef:   g.ID.String(),
		})
	})
}

// transition runs a single request transition in its own transaction.
func (s *AccessProvisioningService) transition(ctx context.Context, workspaceID, requestID uuid.UUID, to RequestState, actor, reason string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		_, err := s.requests.TransitionInTx(ctx, tx, workspaceID, requestID, to, actor, reason)
		return err
	})
}

// withRetry runs fn up to maxAttempts times with backoff between attempts,
// aborting early if the context is cancelled.
func (s *AccessProvisioningService) withRetry(ctx context.Context, fn func() error) error {
	var lastErr error
	for attempt := 1; attempt <= s.maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if lastErr = fn(); lastErr == nil {
			return nil
		}
		if attempt < s.maxAttempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(s.backoff(attempt)):
			}
		}
	}
	return lastErr
}
