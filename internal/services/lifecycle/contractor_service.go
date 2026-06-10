package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// contractorActor labels audit rows the contractor lifecycle writes on behalf
// of an automated path (the human actor is used where one is supplied).
const contractorActor = "system:contractor"

// ContractorService owns the contractor_grants aggregate: the time-boxed,
// sponsor-approved external-access lifecycle. A contractor grant is requested
// (pending_approval), then either approved — which provisions a real,
// time-boxed access_grant at the connector and binds it back to the contractor
// row — or rejected. Approved grants auto-expire (and offboard via the JML kill
// switch) through ContractorExpiryEnforcer, or can be revoked / extended by a
// sponsor before then.
//
// Mandatory expiry is the core invariant: every contractor grant carries a
// future ExpiresAt, so external access can never become standing access by
// omission — the defining failure mode for contractor accounts.
type ContractorService struct {
	db          *gorm.DB
	provisioner *AccessProvisioningService
	now         func() time.Time
}

// NewContractorService wires the service. provisioner is required (approval
// provisions a real grant at the connector).
func NewContractorService(db *gorm.DB, provisioner *AccessProvisioningService) *ContractorService {
	return &ContractorService{db: db, provisioner: provisioner, now: time.Now}
}

// SetClock overrides the time source (tests).
func (s *ContractorService) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// CreateContractorGrantInput is the request to open a time-boxed contractor
// grant. ExpiresAt is mandatory and must be in the future.
type CreateContractorGrantInput struct {
	WorkspaceID      uuid.UUID
	ContractorUserID string
	DisplayName      string
	ConnectorID      uuid.UUID
	ResourceRef      string
	Role             string
	SponsorID        string
	RequestedBy      string
	Justification    string
	ExpiresAt        time.Time
}

// CreateGrant records a pending_approval contractor grant. It provisions
// nothing: access is materialized only on approval. The connector must exist in
// the workspace and ExpiresAt must be in the future.
func (s *ContractorService) CreateGrant(ctx context.Context, in CreateContractorGrantInput) (*models.ContractorGrant, error) {
	if in.WorkspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	contractor := strings.TrimSpace(in.ContractorUserID)
	if contractor == "" {
		return nil, fmt.Errorf("%w: contractor_user_id is required", ErrValidation)
	}
	if in.ConnectorID == uuid.Nil {
		return nil, fmt.Errorf("%w: connector_id is required", ErrValidation)
	}
	resource := strings.TrimSpace(in.ResourceRef)
	if resource == "" {
		return nil, fmt.Errorf("%w: resource_ref is required", ErrValidation)
	}
	sponsor := strings.TrimSpace(in.SponsorID)
	if sponsor == "" {
		return nil, fmt.Errorf("%w: sponsor_id is required (a contractor grant must be sponsored)", ErrValidation)
	}
	now := s.now()
	if !in.ExpiresAt.After(now) {
		return nil, fmt.Errorf("%w: expires_at must be in the future (contractor access is time-boxed)", ErrValidation)
	}
	if err := s.assertConnector(ctx, in.WorkspaceID, in.ConnectorID); err != nil {
		return nil, err
	}

	grant := &models.ContractorGrant{
		WorkspaceID:      in.WorkspaceID,
		ContractorUserID: contractor,
		DisplayName:      strings.TrimSpace(in.DisplayName),
		ConnectorID:      in.ConnectorID,
		ResourceRef:      resource,
		Role:             strings.TrimSpace(in.Role),
		SponsorID:        sponsor,
		RequestedBy:      strings.TrimSpace(in.RequestedBy),
		Justification:    strings.TrimSpace(in.Justification),
		State:            models.ContractorStatePendingApproval,
		ExpiresAt:        in.ExpiresAt.UTC(),
	}
	grant.ID = uuid.New()
	grant.CreatedAt = now
	grant.UpdatedAt = now

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(grant).Error; err != nil {
			return fmt.Errorf("lifecycle: insert contractor grant: %w", err)
		}
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: in.WorkspaceID,
			Actor:       firstNonEmpty(grant.RequestedBy, contractorActor),
			Action:      "contractor.grant.requested",
			TargetRef:   grant.ID.String(),
			Metadata: auditMeta(map[string]any{
				"contractor_user_id": contractor,
				"sponsor_id":         sponsor,
				"resource_ref":       resource,
				"role":               grant.Role,
				"expires_at":         grant.ExpiresAt,
			}),
		})
	})
	if err != nil {
		return nil, err
	}
	return grant, nil
}

// ApproveGrant approves a pending contractor grant: it provisions a real,
// time-boxed access_grant at the connector and, in one transaction, materializes
// the grant row, binds it to the contractor record, and flips the contractor
// grant to active. The provider call happens before the transaction (no network
// I/O under a DB lock); the DB writes are atomic so an approved contractor grant
// always has a matching live access_grant.
func (s *ContractorService) ApproveGrant(ctx context.Context, workspaceID, contractorGrantID uuid.UUID, approver string) (*models.ContractorGrant, error) {
	approver = strings.TrimSpace(approver)
	if approver == "" {
		return nil, fmt.Errorf("%w: an approver is required (sponsor-approved)", ErrValidation)
	}
	cg, err := s.GetGrant(ctx, workspaceID, contractorGrantID)
	if err != nil {
		return nil, err
	}
	if cg.State != models.ContractorStatePendingApproval {
		return nil, fmt.Errorf("%w: only a pending contractor grant can be approved (state=%s)", ErrContractorState, cg.State)
	}
	now := s.now()
	if !cg.ExpiresAt.After(now) {
		// A grant whose box already closed before approval must not be
		// provisioned — reject it as expired rather than minting dead access.
		return nil, fmt.Errorf("%w: contractor grant has already expired and cannot be approved", ErrContractorState)
	}

	// Provision the time-boxed access at the connector OUTSIDE the transaction.
	if err := s.provisioner.ProvisionAtProvider(ctx, workspaceID, cg.ConnectorID, access.AccessGrant{
		UserExternalID:     cg.ContractorUserID,
		ResourceExternalID: cg.ResourceRef,
		Role:               cg.Role,
	}); err != nil {
		return nil, err
	}

	expiresAt := cg.ExpiresAt
	grantRow := &models.AccessGrant{
		WorkspaceID:   workspaceID,
		ConnectorID:   cg.ConnectorID,
		IAMCoreUserID: cg.ContractorUserID,
		ResourceRef:   cg.ResourceRef,
		Role:          cg.Role,
		State:         GrantStateActive,
		GrantedAt:     now,
		ExpiresAt:     &expiresAt,
	}
	grantRow.ID = uuid.New()
	grantRow.CreatedAt = now
	grantRow.UpdatedAt = now

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Re-load under a row lock and re-check the state so two concurrent
		// approvals cannot both insert a grant (the provider call is idempotent,
		// the row insert is not).
		var locked models.ContractorGrant
		if err := forUpdate(tx.WithContext(ctx)).
			Where("workspace_id = ? AND id = ?", workspaceID, contractorGrantID).
			Take(&locked).Error; err != nil {
			return fmt.Errorf("lifecycle: lock contractor grant: %w", err)
		}
		if locked.State != models.ContractorStatePendingApproval {
			return fmt.Errorf("%w: contractor grant is no longer pending (state=%s)", ErrContractorState, locked.State)
		}
		if err := tx.Create(grantRow).Error; err != nil {
			return fmt.Errorf("lifecycle: insert contractor access_grant: %w", err)
		}
		if err := tx.Model(&models.ContractorGrant{}).
			Where("workspace_id = ? AND id = ?", workspaceID, contractorGrantID).
			Updates(map[string]any{
				"state":       models.ContractorStateActive,
				"approved_by": approver,
				"approved_at": now,
				"grant_id":    grantRow.ID,
				"updated_at":  now,
			}).Error; err != nil {
			return fmt.Errorf("lifecycle: activate contractor grant: %w", err)
		}
		if err := appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: workspaceID,
			Actor:       approver,
			Action:      "access_grant.created",
			TargetRef:   grantRow.ID.String(),
		}); err != nil {
			return err
		}
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: workspaceID,
			Actor:       approver,
			Action:      "contractor.grant.approved",
			TargetRef:   contractorGrantID.String(),
			Metadata: auditMeta(map[string]any{
				"contractor_user_id": cg.ContractorUserID,
				"grant_id":           grantRow.ID.String(),
				"expires_at":         expiresAt,
			}),
		})
	})
	if err != nil {
		return nil, err
	}
	return s.GetGrant(ctx, workspaceID, contractorGrantID)
}

// RejectGrant rejects a pending contractor grant. No access was provisioned, so
// this only flips state and records the decision.
func (s *ContractorService) RejectGrant(ctx context.Context, workspaceID, contractorGrantID uuid.UUID, approver, reason string) (*models.ContractorGrant, error) {
	approver = strings.TrimSpace(approver)
	if approver == "" {
		return nil, fmt.Errorf("%w: an approver is required to reject", ErrValidation)
	}
	cg, err := s.GetGrant(ctx, workspaceID, contractorGrantID)
	if err != nil {
		return nil, err
	}
	if cg.State != models.ContractorStatePendingApproval {
		return nil, fmt.Errorf("%w: only a pending contractor grant can be rejected (state=%s)", ErrContractorState, cg.State)
	}
	now := s.now()
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.ContractorGrant{}).
			Where("workspace_id = ? AND id = ? AND state = ?", workspaceID, contractorGrantID, models.ContractorStatePendingApproval).
			Updates(map[string]any{"state": models.ContractorStateRejected, "updated_at": now}).Error; err != nil {
			return fmt.Errorf("lifecycle: reject contractor grant: %w", err)
		}
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: workspaceID,
			Actor:       approver,
			Action:      "contractor.grant.rejected",
			TargetRef:   contractorGrantID.String(),
			Metadata:    auditMeta(map[string]any{"reason": strings.TrimSpace(reason)}),
		})
	})
	if err != nil {
		return nil, err
	}
	return s.GetGrant(ctx, workspaceID, contractorGrantID)
}

// RevokeGrant revokes an active contractor grant early, deprovisioning its
// access_grant precisely (just this grant, not the contractor's whole identity —
// a sponsor revoking one engagement should not tear down unrelated access). The
// automatic, time-box-expiry path additionally runs the JML kill switch to
// offboard the external identity once it has no remaining access; see
// ContractorExpiryEnforcer.
func (s *ContractorService) RevokeGrant(ctx context.Context, workspaceID, contractorGrantID uuid.UUID, actor, reason string) (*models.ContractorGrant, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return nil, fmt.Errorf("%w: an actor is required to revoke", ErrValidation)
	}
	cg, err := s.GetGrant(ctx, workspaceID, contractorGrantID)
	if err != nil {
		return nil, err
	}
	if cg.State != models.ContractorStateActive {
		return nil, fmt.Errorf("%w: only an active contractor grant can be revoked (state=%s)", ErrContractorState, cg.State)
	}
	if err := s.deprovisionGrant(ctx, workspaceID, cg, actor, firstNonEmpty(strings.TrimSpace(reason), "contractor grant revoked")); err != nil {
		return nil, err
	}
	if err := s.markTerminal(ctx, workspaceID, contractorGrantID, models.ContractorStateRevoked, actor, "contractor.grant.revoked", reason); err != nil {
		return nil, err
	}
	return s.GetGrant(ctx, workspaceID, contractorGrantID)
}

// ExtendExpiry pushes an active contractor grant's time box out to newExpiresAt,
// recording a sponsor-approved extension and syncing the backing access_grant's
// expiry. newExpiresAt must be after both now and the current expiry (an
// extension only ever lengthens the box; shortening is a revoke).
func (s *ContractorService) ExtendExpiry(ctx context.Context, workspaceID, contractorGrantID uuid.UUID, approver string, newExpiresAt time.Time, reason string) (*models.ContractorGrant, error) {
	approver = strings.TrimSpace(approver)
	if approver == "" {
		return nil, fmt.Errorf("%w: an approver is required to extend", ErrValidation)
	}
	cg, err := s.GetGrant(ctx, workspaceID, contractorGrantID)
	if err != nil {
		return nil, err
	}
	if cg.State != models.ContractorStateActive {
		return nil, fmt.Errorf("%w: only an active contractor grant can be extended (state=%s)", ErrContractorState, cg.State)
	}
	now := s.now()
	newExpiresAt = newExpiresAt.UTC()
	if !newExpiresAt.After(now) {
		return nil, fmt.Errorf("%w: new expiry must be in the future", ErrValidation)
	}
	if !newExpiresAt.After(cg.ExpiresAt) {
		return nil, fmt.Errorf("%w: new expiry must be later than the current expiry (use revoke to shorten)", ErrValidation)
	}
	prev := cg.ExpiresAt
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var locked models.ContractorGrant
		if err := forUpdate(tx.WithContext(ctx)).
			Where("workspace_id = ? AND id = ?", workspaceID, contractorGrantID).
			Take(&locked).Error; err != nil {
			return fmt.Errorf("lifecycle: lock contractor grant: %w", err)
		}
		if locked.State != models.ContractorStateActive {
			return fmt.Errorf("%w: contractor grant is no longer active (state=%s)", ErrContractorState, locked.State)
		}
		ext := &models.ContractorGrantExtension{
			WorkspaceID:       workspaceID,
			ContractorGrantID: contractorGrantID,
			PreviousExpiresAt: prev,
			NewExpiresAt:      newExpiresAt,
			ApprovedBy:        approver,
			Reason:            strings.TrimSpace(reason),
		}
		ext.ID = uuid.New()
		ext.CreatedAt = now
		ext.UpdatedAt = now
		if err := tx.Create(ext).Error; err != nil {
			return fmt.Errorf("lifecycle: insert contractor extension: %w", err)
		}
		if err := tx.Model(&models.ContractorGrant{}).
			Where("workspace_id = ? AND id = ?", workspaceID, contractorGrantID).
			Updates(map[string]any{"expires_at": newExpiresAt, "updated_at": now}).Error; err != nil {
			return fmt.Errorf("lifecycle: extend contractor grant: %w", err)
		}
		// Keep the backing access_grant's expiry in lock-step so the grant-expiry
		// sweep honors the extended box.
		if locked.GrantID != nil {
			if err := tx.Model(&models.AccessGrant{}).
				Where("workspace_id = ? AND id = ?", workspaceID, *locked.GrantID).
				Updates(map[string]any{"expires_at": newExpiresAt, "updated_at": now}).Error; err != nil {
				return fmt.Errorf("lifecycle: sync access_grant expiry: %w", err)
			}
		}
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: workspaceID,
			Actor:       approver,
			Action:      "contractor.grant.extended",
			TargetRef:   contractorGrantID.String(),
			Metadata: auditMeta(map[string]any{
				"previous_expires_at": prev,
				"new_expires_at":      newExpiresAt,
				"reason":              strings.TrimSpace(reason),
			}),
		})
	})
	if err != nil {
		return nil, err
	}
	return s.GetGrant(ctx, workspaceID, contractorGrantID)
}

// GetGrant loads one contractor grant scoped to the workspace.
func (s *ContractorService) GetGrant(ctx context.Context, workspaceID, contractorGrantID uuid.UUID) (*models.ContractorGrant, error) {
	var cg models.ContractorGrant
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, contractorGrantID).
		Take(&cg).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrContractorGrantNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lifecycle: load contractor grant: %w", err)
	}
	return &cg, nil
}

// ListGrants returns the workspace's contractor grants, newest first.
func (s *ContractorService) ListGrants(ctx context.Context, workspaceID uuid.UUID) ([]models.ContractorGrant, error) {
	var out []models.ContractorGrant
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("created_at desc").
		Find(&out).Error; err != nil {
		return nil, fmt.Errorf("lifecycle: list contractor grants: %w", err)
	}
	return out, nil
}

// deprovisionGrant revokes the contractor grant's backing access_grant (if any),
// idempotently. A contractor grant with no bound access_grant (should not happen
// for an active grant) is a no-op.
func (s *ContractorService) deprovisionGrant(ctx context.Context, workspaceID uuid.UUID, cg *models.ContractorGrant, actor, reason string) error {
	if cg.GrantID == nil {
		return nil
	}
	if err := s.provisioner.RevokeGrant(ctx, workspaceID, *cg.GrantID, actor, reason); err != nil {
		if errors.Is(err, ErrGrantNotFound) {
			return nil // already gone — idempotent
		}
		return err
	}
	return nil
}

// markTerminal flips a contractor grant to a terminal state and records the
// disposition, stamping revoked_at.
func (s *ContractorService) markTerminal(ctx context.Context, workspaceID, contractorGrantID uuid.UUID, state, actor, action, reason string) error {
	now := s.now()
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.ContractorGrant{}).
			Where("workspace_id = ? AND id = ?", workspaceID, contractorGrantID).
			Updates(map[string]any{"state": state, "revoked_at": now, "updated_at": now}).Error; err != nil {
			return fmt.Errorf("lifecycle: mark contractor grant %s: %w", state, err)
		}
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      action,
			TargetRef:   contractorGrantID.String(),
			Metadata:    auditMeta(map[string]any{"reason": strings.TrimSpace(reason)}),
		})
	})
}

// assertConnector verifies the connector exists in the workspace.
func (s *ContractorService) assertConnector(ctx context.Context, workspaceID, connectorID uuid.UUID) error {
	var count int64
	if err := s.db.WithContext(ctx).
		Model(&models.AccessConnector{}).
		Where("workspace_id = ? AND id = ?", workspaceID, connectorID).
		Count(&count).Error; err != nil {
		return fmt.Errorf("lifecycle: verify connector: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("%w: connector %s not found in workspace", ErrConnectorNotConfigured, connectorID)
	}
	return nil
}

// auditMeta marshals v to datatypes.JSON, returning nil on the (practically
// impossible) marshal error so an audit metadata blob never blocks the action.
func auditMeta(v map[string]any) datatypes.JSON {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return datatypes.JSON(b)
}

// firstNonEmpty returns a if non-empty, else b.
func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
