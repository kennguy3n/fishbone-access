package discovery

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// evalAssetBatchSize bounds how many unmanaged assets a single policy-evaluation
// page loads into memory, keeping the sweep's footprint constant regardless of
// inventory size (important at 5k-tenant scale where sweeps run unattended).
const evalAssetBatchSize = 500

// ScheduledSweepResult summarises one workspace's scheduled sweep.
type ScheduledSweepResult struct {
	ConnectorsScanned int
	AssetsNew         int
	PolicyMatched     int
	Onboarded         int
}

// RunScheduledSweep is the workflow-engine entry point for one ACTIVE workspace
// (the caller gates on the tenant hibernation gate, so dormant tenants are never
// swept). It re-enumerates every connector that exposes a native inventory, then
// evaluates the auto-onboarding policy over the workspace's unmanaged assets.
// It is a no-op (returns zero, nil) when the workspace has no enabled policy, so
// the workflow engine can call it for every active tenant cheaply.
func (e *Engine) RunScheduledSweep(ctx context.Context, workspaceID uuid.UUID) (ScheduledSweepResult, error) {
	var res ScheduledSweepResult
	policy, err := e.loadPolicy(ctx, workspaceID)
	if err != nil {
		return res, err
	}
	if policy == nil || !policy.Enabled {
		return res, nil
	}

	// Refresh connector inventory so the policy evaluates against current
	// assets. Connector errors are best-effort: one misconfigured connector
	// must not abort the sweep for the rest.
	if e.resolver != nil {
		connectors, lErr := e.listConnectorIDs(ctx, workspaceID)
		if lErr != nil {
			return res, lErr
		}
		for _, cid := range connectors {
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			out, scanErr := e.ConnectorInventory(ctx, workspaceID, cid, "system:scheduled-sweep", models.DiscoveryTriggerScheduled)
			if scanErr != nil {
				// Unsupported connectors (no inventory API) are expected and skipped.
				continue
			}
			res.ConnectorsScanned++
			res.AssetsNew += out.AssetsNew
		}
	}

	matched, onboarded, evalErr := e.evaluatePolicy(ctx, workspaceID, policy)
	res.PolicyMatched = matched
	res.Onboarded = onboarded
	return res, evalErr
}

// listConnectorIDs returns the workspace's non-pending connector ids (the same
// filter the lifecycle orphan sweep uses, so a deactivated connector is still
// inventoried but a never-configured one is skipped).
func (e *Engine) listConnectorIDs(ctx context.Context, workspaceID uuid.UUID) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	if err := e.db.WithContext(ctx).Model(&models.AccessConnector{}).
		Where("workspace_id = ? AND status <> ?", workspaceID, "pending").
		Pluck("id", &ids).Error; err != nil {
		return nil, fmt.Errorf("discovery: list connectors: %w", err)
	}
	return ids, nil
}

// evaluatePolicy matches the workspace's unmanaged assets against the policy
// rules. Every match is flagged PolicyMatched (surfaced as "recommended"); when
// the policy is in CREATE mode and an onboarding credential is sealed, a managed
// PAM target is auto-created (require-lease boundary preserved — no standing
// access). Returns (matched, onboarded) counts.
func (e *Engine) evaluatePolicy(ctx context.Context, workspaceID uuid.UUID, policy *models.AutoOnboardingPolicy) (matched, onboarded int, err error) {
	rules, err := decodeRules(policy.Rules)
	if err != nil {
		return 0, 0, err
	}
	if len(rules) == 0 {
		return 0, 0, nil
	}

	createMode := policy.CreateTargets && policy.CredentialEnvelope != ""
	var credential pam.Secret
	if createMode {
		credential, err = e.openPolicyCredential(ctx, policy)
		if err != nil {
			return 0, 0, err
		}
	}

	// Keyset-paginate the workspace's unmanaged assets so memory stays bounded
	// regardless of how large the inventory grows (a single workspace can
	// accumulate thousands of unmanaged candidates). Iterating by ascending id
	// moves the cursor strictly forward: onboarded assets leave the
	// status=unmanaged set entirely, and flag-only matches stay behind the
	// cursor, so neither is re-processed and the loop always terminates.
	var lastID uuid.UUID
	for {
		if ctx.Err() != nil {
			return matched, onboarded, ctx.Err()
		}
		q := e.db.WithContext(ctx).
			Where("workspace_id = ? AND status = ?", workspaceID, models.DiscoveryStatusUnmanaged)
		if lastID != uuid.Nil {
			q = q.Where("id > ?", lastID)
		}
		var batch []models.DiscoveredAsset
		if err := q.Order("id").Limit(evalAssetBatchSize).Find(&batch).Error; err != nil {
			return matched, onboarded, fmt.Errorf("discovery: load unmanaged assets: %w", err)
		}
		if len(batch) == 0 {
			return matched, onboarded, nil
		}
		for i := range batch {
			if ctx.Err() != nil {
				return matched, onboarded, ctx.Err()
			}
			asset := batch[i]
			lastID = asset.ID
			rule, ok := firstMatchingRule(&asset, rules)
			if !ok {
				continue
			}
			matched++
			if !createMode {
				if err := e.flagPolicyMatched(ctx, workspaceID, asset.ID); err != nil {
					return matched, onboarded, err
				}
				continue
			}
			agentID := rule.AgentID
			if agentID == nil {
				agentID = policy.DefaultAgentID
			}
			if agentID == nil {
				agentID = asset.AgentID
			}
			_, onbErr := e.OnboardAsset(ctx, workspaceID, asset.ID, OnboardAssetInput{
				Username:   credential.Username,
				Secret:     credential,
				AgentID:    agentID,
				RequireMFA: true,
				Actor:      "system:auto-onboard",
			})
			if onbErr != nil && !errors.Is(onbErr, ErrAgentBindFailed) {
				// A single onboarding failure (e.g. duplicate name) must not abort
				// the whole sweep; flag the asset so it still surfaces as recommended.
				if flagErr := e.flagPolicyMatched(ctx, workspaceID, asset.ID); flagErr != nil {
					return matched, onboarded, flagErr
				}
				continue
			}
			// A bind failure (ErrAgentBindFailed) still created the target and
			// linked the asset — it IS onboarded (direct-dial), so count it like
			// a success rather than undercounting the sweep result.
			onboarded++
		}
		if len(batch) < evalAssetBatchSize {
			return matched, onboarded, nil
		}
	}
}

func (e *Engine) flagPolicyMatched(ctx context.Context, workspaceID, assetID uuid.UUID) error {
	if err := e.db.WithContext(ctx).Model(&models.DiscoveredAsset{}).
		Where("workspace_id = ? AND id = ? AND status = ?", workspaceID, assetID, models.DiscoveryStatusUnmanaged).
		Update("policy_matched", true).Error; err != nil {
		return fmt.Errorf("discovery: flag policy match: %w", err)
	}
	return nil
}

func firstMatchingRule(asset *models.DiscoveredAsset, rules []AutoOnboardRule) (AutoOnboardRule, bool) {
	for _, r := range rules {
		if matchRule(asset, r) {
			return r, true
		}
	}
	return AutoOnboardRule{}, false
}
