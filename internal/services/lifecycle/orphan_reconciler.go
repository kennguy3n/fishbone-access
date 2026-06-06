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

// Orphan-account dispositions.
const (
	OrphanDispositionPending = "pending"
	OrphanDispositionIgnore  = "ignore"
	OrphanDispositionDisable = "disable"
)

// OrphanReconciler detects upstream provider accounts that have no matching
// live ShieldNet grant ("orphans") and lets an operator dispose of them. A scan
// enumerates the connector's identities and flags any whose external id has no
// active grant in the workspace.
type OrphanReconciler struct {
	db       *gorm.DB
	resolver ConnectorResolver
	now      func() time.Time
}

// NewOrphanReconciler wires the reconciler.
func NewOrphanReconciler(db *gorm.DB, resolver ConnectorResolver) *OrphanReconciler {
	return &OrphanReconciler{db: db, resolver: resolver, now: time.Now}
}

// SetClock overrides the time source (tests).
func (s *OrphanReconciler) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// OrphanCandidate is one detected orphan account (pre-persistence view).
type OrphanCandidate struct {
	ConnectorID    uuid.UUID `json:"connector_id"`
	ExternalUserID string    `json:"external_user_id"`
	DisplayName    string    `json:"display_name"`
}

// ScanResult summarizes a reconciliation scan.
type ScanResult struct {
	ConnectorID    uuid.UUID         `json:"connector_id"`
	DryRun         bool              `json:"dry_run"`
	UpstreamCount  int               `json:"upstream_count"`
	OrphanCount    int               `json:"orphan_count"`
	Orphans        []OrphanCandidate `json:"orphans"`
	PersistedCount int               `json:"persisted_count"`
}

// Scan enumerates a connector's upstream identities and flags those with no
// active grant in the workspace. In dryRun mode it returns the candidates
// without persisting. Otherwise it upserts an AccessOrphanAccount row (pending
// disposition) for each newly-seen orphan, skipping ones already recorded.
func (s *OrphanReconciler) Scan(ctx context.Context, workspaceID, connectorID uuid.UUID, dryRun bool) (ScanResult, error) {
	if workspaceID == uuid.Nil || connectorID == uuid.Nil {
		return ScanResult{}, fmt.Errorf("%w: workspace_id and connector_id are required", ErrValidation)
	}
	resolved, err := s.resolver.Resolve(ctx, workspaceID, connectorID)
	if err != nil {
		// Preserve Resolve's classification (sentinel → 422, raw DB error → 500).
		return ScanResult{}, err
	}

	// Build the set of external user ids that DO have a live grant.
	var grants []models.AccessGrant
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND connector_id = ? AND state = ? AND revoked_at IS NULL", workspaceID, connectorID, GrantStateActive).
		Find(&grants).Error; err != nil {
		return ScanResult{}, fmt.Errorf("lifecycle: load grants for scan: %w", err)
	}
	granted := make(map[string]struct{}, len(grants))
	for i := range grants {
		granted[grants[i].IAMCoreUserID] = struct{}{}
	}

	result := ScanResult{ConnectorID: connectorID, DryRun: dryRun}
	var upstream []*access.Identity
	if err := resolved.Impl.SyncIdentities(ctx, resolved.Config, resolved.Secrets, "", func(batch []*access.Identity, _ string) error {
		upstream = append(upstream, batch...)
		return nil
	}); err != nil {
		return ScanResult{}, fmt.Errorf("lifecycle: enumerate upstream identities: %w", err)
	}

	for _, id := range upstream {
		if id == nil || id.Type != access.IdentityTypeUser {
			continue
		}
		result.UpstreamCount++
		if _, ok := granted[id.ExternalID]; ok {
			continue
		}
		result.Orphans = append(result.Orphans, OrphanCandidate{
			ConnectorID:    connectorID,
			ExternalUserID: id.ExternalID,
			DisplayName:    id.DisplayName,
		})
	}
	result.OrphanCount = len(result.Orphans)

	if dryRun {
		return result, nil
	}

	now := s.now()
	for _, cand := range result.Orphans {
		var existing models.AccessOrphanAccount
		err := s.db.WithContext(ctx).
			Where("workspace_id = ? AND connector_id = ? AND external_user_id = ?", workspaceID, connectorID, cand.ExternalUserID).
			Take(&existing).Error
		if err == nil {
			continue // already recorded; leave operator disposition intact
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return result, fmt.Errorf("lifecycle: lookup orphan: %w", err)
		}
		row := &models.AccessOrphanAccount{
			WorkspaceID:    workspaceID,
			ConnectorID:    connectorID,
			ExternalUserID: cand.ExternalUserID,
			DisplayName:    cand.DisplayName,
			Disposition:    OrphanDispositionPending,
		}
		row.CreatedAt = now
		row.UpdatedAt = now
		if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := tx.Create(row).Error; err != nil {
				return fmt.Errorf("lifecycle: insert orphan: %w", err)
			}
			return appendAudit(ctx, tx, now, auditEntry{
				WorkspaceID: workspaceID,
				Actor:       "system",
				Action:      "orphan.detected",
				TargetRef:   cand.ExternalUserID,
			})
		}); err != nil {
			return result, err
		}
		result.PersistedCount++
	}
	return result, nil
}

// ListOrphans returns the workspace's recorded orphan accounts.
func (s *OrphanReconciler) ListOrphans(ctx context.Context, workspaceID uuid.UUID) ([]models.AccessOrphanAccount, error) {
	var out []models.AccessOrphanAccount
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("created_at desc").
		Find(&out).Error; err != nil {
		return nil, fmt.Errorf("lifecycle: list orphans: %w", err)
	}
	return out, nil
}

// SetDisposition records an operator's decision for an orphan account. For a
// "disable" disposition it additionally revokes the account's upstream
// entitlements on the connector (idempotent); "ignore" simply records the
// decision so future scans do not re-surface the account.
func (s *OrphanReconciler) SetDisposition(ctx context.Context, workspaceID, orphanID uuid.UUID, disposition, actor string) error {
	switch disposition {
	case OrphanDispositionIgnore, OrphanDispositionDisable:
	default:
		return fmt.Errorf("%w: unknown orphan disposition %q", ErrValidation, disposition)
	}

	var orphan models.AccessOrphanAccount
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, orphanID).
		Take(&orphan).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrOrphanNotFound
	}
	if err != nil {
		return fmt.Errorf("lifecycle: load orphan: %w", err)
	}

	if disposition == OrphanDispositionDisable {
		resolved, err := s.resolver.Resolve(ctx, workspaceID, orphan.ConnectorID)
		if err != nil {
			// Preserve Resolve's classification (sentinel → 422, raw DB error → 500).
			return err
		}
		ents, err := resolved.Impl.ListEntitlements(ctx, resolved.Config, resolved.Secrets, orphan.ExternalUserID)
		if err != nil {
			return fmt.Errorf("lifecycle: list orphan entitlements: %w", err)
		}
		// Attempt every entitlement and aggregate failures rather than aborting on
		// the first one: a transient failure on one entitlement must not leave the
		// remaining ones live (the same maximal-revocation rule the kill switch's
		// scimDeprovision follows). The disposition is only committed below when
		// all revocations succeed, so on a returned error the operator can re-run
		// and RevokeAccess (idempotent) retries whatever is still live.
		var errs []error
		for _, ent := range ents {
			if err := resolved.Impl.RevokeAccess(ctx, resolved.Config, resolved.Secrets, access.AccessGrant{
				UserExternalID:     orphan.ExternalUserID,
				ResourceExternalID: ent.ResourceExternalID,
				Role:               ent.Role,
			}); err != nil {
				errs = append(errs, fmt.Errorf("revoke %s/%s: %w", ent.ResourceExternalID, ent.Role, err))
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("lifecycle: %d/%d orphan entitlement revocations failed: %w", len(errs), len(ents), errors.Join(errs...))
		}
	}

	now := s.now()
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.AccessOrphanAccount{}).
			Where("workspace_id = ? AND id = ?", workspaceID, orphanID).
			Updates(map[string]any{"disposition": disposition, "updated_at": now}).Error; err != nil {
			return fmt.Errorf("lifecycle: update orphan disposition: %w", err)
		}
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      "orphan.disposition." + disposition,
			TargetRef:   orphan.ExternalUserID,
		})
	})
}
