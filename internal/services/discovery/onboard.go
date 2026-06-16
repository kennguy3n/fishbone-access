package discovery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// OnboardAssetInput is the operator-supplied onboarding form for promoting a
// DiscoveredAsset into a managed PAMTarget. Sensible defaults are pre-filled
// from the asset (name/protocol/address/agent) but every field is overridable.
type OnboardAssetInput struct {
	// Name is the PAM target name; defaults to the asset name/address.
	Name string
	// Protocol/Address override the asset's inferred values when set.
	Protocol string
	Address  string
	// Username + Secret are the upstream credential the target authenticates
	// with; sealed by the vault, never persisted in plaintext.
	Username string
	Secret   pam.Secret
	// AgentID binds the new target to an outbound agent (defaults to the agent
	// that discovered the asset). Nil leaves the target direct-dial.
	AgentID *uuid.UUID
	// RequireMFA gates secret-reveal/connect behind step-up MFA.
	RequireMFA bool
	// LeaseTTL caps connect-token lifetime; zero uses the broker default.
	LeaseTTL time.Duration
	// Actor is the iam-core subject performing the onboard (audited).
	Actor string
}

// OnboardAsset promotes a discovered asset into a managed PAM target. It creates
// the target through the real vault (sealing the credential, appending the
// target-create audit event atomically), optionally binds it to the discovering
// agent, then marks the asset managed with its new target_id. It NEVER grants
// standing access — access still flows through the request/lease path. Re-onboarding
// an already-managed asset is a conflict.
func (e *Engine) OnboardAsset(ctx context.Context, workspaceID, assetID uuid.UUID, in OnboardAssetInput) (*models.PAMTarget, error) {
	if workspaceID == uuid.Nil || assetID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id and asset_id are required", ErrValidation)
	}
	asset, err := e.GetAsset(ctx, workspaceID, assetID)
	if err != nil {
		return nil, err
	}
	if asset.Status == models.DiscoveryStatusManaged && asset.TargetID != nil {
		return nil, fmt.Errorf("%w: asset is already onboarded", ErrConflict)
	}

	protocol := firstNonEmpty(in.Protocol, asset.Protocol)
	if protocol == "" {
		protocol = defaultProtocolForKind(kindForProtocol(asset.Protocol))
	}
	address := firstNonEmpty(in.Address, asset.Address)
	name := firstNonEmpty(in.Name, asset.Name, address)
	agentID := in.AgentID
	if agentID == nil {
		agentID = asset.AgentID
	}
	requireMFA := in.RequireMFA

	target, err := e.vault.CreateTarget(ctx, pam.CreateTargetInput{
		WorkspaceID: workspaceID,
		Name:        name,
		Protocol:    protocol,
		Address:     address,
		Username:    in.Username,
		RequireMFA:  &requireMFA,
		LeaseTTL:    in.LeaseTTL,
		Secret:      in.Secret,
		Actor:       in.Actor,
	})
	if err != nil {
		return nil, e.mapVaultErr(err)
	}

	if agentID != nil && e.binder != nil {
		if bindErr := e.binder.BindTarget(ctx, workspaceID, *agentID, target.ID, in.Actor); bindErr != nil {
			// The target exists and is usable direct-dial; surface the bind
			// failure rather than silently dropping the agent association.
			return target, fmt.Errorf("discovery: bind onboarded target to agent: %w", bindErr)
		}
	}

	if err := e.markAssetManaged(ctx, workspaceID, asset.ID, target.ID, in.Actor, models.DiscoveryTriggerManual); err != nil {
		return target, err
	}
	return target, nil
}

// markAssetManaged links an asset to its new target and flips it managed, then
// appends the discovery.onboard audit event in the same transaction so the
// inventory state change and its audit row commit atomically.
func (e *Engine) markAssetManaged(ctx context.Context, workspaceID, assetID, targetID uuid.UUID, actor, trigger string) error {
	now := e.now()
	return e.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.DiscoveredAsset{}).
			Where("workspace_id = ? AND id = ?", workspaceID, assetID).
			Updates(map[string]any{
				"status":         models.DiscoveryStatusManaged,
				"target_id":      targetID,
				"policy_matched": false,
				"last_seen_at":   now,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      "discovery.onboard",
			TargetRef:   targetID.String(),
			Metadata: mustAuditMeta(map[string]any{
				"asset_id": assetID.String(),
				"trigger":  trigger,
			}),
		})
	})
}

// DispositionAccount sets an operator disposition on a discovered account
// (ignore / un-ignore). Ignoring hides it from the candidate list and survives
// re-scans; the change is audited.
func (e *Engine) DispositionAccount(ctx context.Context, workspaceID, accountID uuid.UUID, status, actor string) error {
	if workspaceID == uuid.Nil || accountID == uuid.Nil {
		return fmt.Errorf("%w: workspace_id and account_id are required", ErrValidation)
	}
	if status != models.DiscoveryStatusIgnored && status != models.DiscoveryStatusUnmanaged && status != models.DiscoveryStatusOrphan {
		return fmt.Errorf("%w: unsupported account disposition %q", ErrValidation, status)
	}
	now := e.now()
	return e.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.DiscoveredAccount{}).
			Where("workspace_id = ? AND id = ?", workspaceID, accountID).
			Update("status", status)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      "discovery.account_disposition",
			TargetRef:   accountID.String(),
			Metadata:    mustAuditMeta(map[string]any{"status": status}),
		})
	})
}

// IgnoreAsset hides an unmanaged asset from the candidate list (sticky across
// re-scans), audited. Managed assets cannot be ignored.
func (e *Engine) IgnoreAsset(ctx context.Context, workspaceID, assetID uuid.UUID, actor string) error {
	if workspaceID == uuid.Nil || assetID == uuid.Nil {
		return fmt.Errorf("%w: workspace_id and asset_id are required", ErrValidation)
	}
	now := e.now()
	return e.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var asset models.DiscoveredAsset
		if err := tx.Where("workspace_id = ? AND id = ?", workspaceID, assetID).Take(&asset).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if asset.Status == models.DiscoveryStatusManaged {
			return fmt.Errorf("%w: a managed asset cannot be ignored", ErrConflict)
		}
		if err := tx.Model(&models.DiscoveredAsset{}).
			Where("id = ?", asset.ID).
			Updates(map[string]any{"status": models.DiscoveryStatusIgnored, "policy_matched": false}).Error; err != nil {
			return err
		}
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      "discovery.asset_ignore",
			TargetRef:   assetID.String(),
		})
	})
}

func (e *Engine) mapVaultErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pam.ErrValidation):
		return fmt.Errorf("%w: %s", ErrValidation, strings.TrimPrefix(err.Error(), "pam: "))
	case errors.Is(err, pam.ErrTargetExists):
		return fmt.Errorf("%w: a target with that name already exists", ErrConflict)
	default:
		return fmt.Errorf("discovery: create target: %w", err)
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
