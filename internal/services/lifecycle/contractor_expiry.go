package lifecycle

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// contractorExpiryActor attributes the automatic expiry/offboard path.
const contractorExpiryActor = "system:contractor-expiry"

// ContractorExpiryEnforcer enforces the mandatory time box on contractor
// grants: it expires every active grant past its ExpiresAt and deprovisions the
// access. Deprovision is precise per grant, and when an expiry leaves a
// contractor with NO remaining active contractor grants it runs the existing JML
// kill switch to fully offboard the external identity (revoke sessions, disable
// the account, SCIM deprovision) — automatic deprovision via the kill switch
// without prematurely tearing down a contractor who still has another live
// engagement.
//
// It is driven by the lifecycle Scheduler (every 5m by default) but is also
// directly invocable (EnforceExpired) for a seeded scenario or a test.
type ContractorExpiryEnforcer struct {
	db          *gorm.DB
	service     *ContractorService
	provisioner *AccessProvisioningService
	jml         *JMLService
	now         func() time.Time
}

// NewContractorExpiryEnforcer wires the enforcer. jml is required for the
// identity-offboard kill switch; provisioner is required for the precise
// per-grant revoke.
func NewContractorExpiryEnforcer(db *gorm.DB, service *ContractorService, provisioner *AccessProvisioningService, jml *JMLService) *ContractorExpiryEnforcer {
	return &ContractorExpiryEnforcer{db: db, service: service, provisioner: provisioner, jml: jml, now: time.Now}
}

// SetClock overrides the time source (tests).
func (e *ContractorExpiryEnforcer) SetClock(now func() time.Time) {
	if now != nil {
		e.now = now
	}
}

// EnforceExpired expires and deprovisions every overdue contractor grant in the
// workspace, returning the number expired. It is idempotent: a grant already in
// a terminal state is never selected, so re-running it is safe.
func (e *ContractorExpiryEnforcer) EnforceExpired(ctx context.Context, workspaceID uuid.UUID) (int, error) {
	now := e.now()
	var due []models.ContractorGrant
	if err := e.db.WithContext(ctx).
		Where("workspace_id = ? AND state = ? AND expires_at <= ?", workspaceID, models.ContractorStateActive, now).
		Order("expires_at asc").
		Find(&due).Error; err != nil {
		return 0, err
	}

	expired := 0
	for i := range due {
		if err := ctx.Err(); err != nil {
			return expired, err
		}
		cg := due[i]

		// Flip the contractor grant to expired (stamping revoked_at) first so the
		// "remaining active" check below excludes it.
		if err := e.service.markTerminal(ctx, workspaceID, cg.ID, models.ContractorStateActive, models.ContractorStateExpired, contractorExpiryActor, "contractor.grant.expired", "time box elapsed"); err != nil {
			// A concurrent revoke/extend already moved this grant out of active;
			// ErrContractorState here is a benign race (the grant was handled
			// elsewhere), so skip it without counting rather than logging noise.
			if !errors.Is(err, ErrContractorState) {
				logger.Errorf(ctx, "lifecycle: expire contractor grant %s: %v", cg.ID, err)
			}
			continue
		}

		remaining, err := e.activeCount(ctx, workspaceID, cg.ContractorUserID)
		if err != nil {
			logger.Errorf(ctx, "lifecycle: count remaining contractor grants for %s: %v", cg.ContractorUserID, err)
			continue
		}
		if remaining == 0 {
			// Last engagement closed — offboard the external identity entirely via
			// the kill switch (its layer 1 also revokes the backing access_grant,
			// so no separate revoke is needed on this path).
			if _, err := e.jml.RunKillSwitch(ctx, workspaceID, cg.ContractorUserID, contractorExpiryActor); err != nil {
				logger.Errorf(ctx, "lifecycle: contractor kill switch for %s: %v", cg.ContractorUserID, err)
				// The contractor grant is already expired; the kill switch records
				// its own per-layer failures. Count the expiry and continue.
			}
		} else {
			// Other engagements remain live: revoke ONLY this grant's access.
			if cg.GrantID != nil {
				if err := e.provisioner.RevokeGrant(ctx, workspaceID, *cg.GrantID, contractorExpiryActor, "contractor grant expired"); err != nil {
					logger.Errorf(ctx, "lifecycle: revoke expired contractor access %s: %v", *cg.GrantID, err)
				}
			}
		}
		expired++
	}
	return expired, nil
}

// activeCount returns how many active contractor grants the contractor still has
// in the workspace.
func (e *ContractorExpiryEnforcer) activeCount(ctx context.Context, workspaceID uuid.UUID, contractorUserID string) (int, error) {
	var n int64
	if err := e.db.WithContext(ctx).
		Model(&models.ContractorGrant{}).
		Where("workspace_id = ? AND contractor_user_id = ? AND state = ?", workspaceID, contractorUserID, models.ContractorStateActive).
		Count(&n).Error; err != nil {
		return 0, err
	}
	return int(n), nil
}
