package discovery

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
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
	// Healed counts assets recovered from the stranded managed/target_id=NULL
	// state this sweep (re-linked to their created target or released back to
	// unmanaged). Normally zero.
	Healed int
	// ActiveSweepProbed / ActiveSweepReachable summarise the scheduled active
	// network sweep (zero when it is disabled or no agent dialer is wired). Its
	// freshly-discovered assets are also folded into AssetsNew.
	ActiveSweepProbed    int
	ActiveSweepReachable int
}

// RunScheduledSweep is the workflow-engine entry point for one ACTIVE workspace
// (the caller gates on the tenant hibernation gate, so dormant tenants are never
// swept). It first recovers any assets stranded by a failed onboard, then (only
// when an enabled policy exists) re-enumerates every connector that exposes a
// native inventory and evaluates the auto-onboarding policy over the workspace's
// unmanaged assets. With no enabled policy it does just the cheap heal probe and
// returns, so the workflow engine can call it for every active tenant cheaply.
func (e *Engine) RunScheduledSweep(ctx context.Context, workspaceID uuid.UUID) (ScheduledSweepResult, error) {
	var res ScheduledSweepResult

	// Recover any assets stranded by a prior failed onboard (managed/target_id=
	// NULL) first, independent of the auto-onboarding policy: a MANUAL onboard
	// can strand an asset too, and such a workspace may have no policy at all.
	// This runs inside the hibernation-gated sweep, so dormant tenants are never
	// touched, and is near-free when nothing is stranded (one index-only probe).
	healed, healErr := e.reconcileStuckOnboards(ctx, workspaceID)
	if healErr != nil {
		return res, healErr
	}
	res.Healed = healed

	policy, err := e.loadPolicy(ctx, workspaceID)
	if err != nil {
		return res, err
	}
	if policy == nil {
		return res, nil
	}

	// Run the scheduled ACTIVE network sweep first — it is gated on its OWN flag
	// (active_sweep_enabled), independent of the onboarding policy's Enabled, so
	// a workspace can run active discovery without auto-onboarding. It is
	// best-effort: a sweep failure (e.g. the named agent is momentarily offline)
	// must not abort the onboarding pass, exactly like a single connector's
	// inventory error below.
	e.runActiveSweep(ctx, workspaceID, policy, &res)

	if !policy.Enabled {
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
				Trigger:    models.DiscoveryTriggerScheduled,
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

// runActiveSweep runs the workspace's scheduled active network sweep when it is
// enabled, an agent dialer is wired (only the case where the workflow engine
// has the cross-replica forward plane configured), and a sweep agent is named.
// It probes the configured targets THROUGH that agent and folds the results
// into res. Any error is logged and swallowed: active discovery is an additive,
// best-effort enrichment of the scheduled sweep, never a reason to fail it.
func (e *Engine) runActiveSweep(ctx context.Context, workspaceID uuid.UUID, policy *models.AutoOnboardingPolicy, res *ScheduledSweepResult) {
	if !policy.ActiveSweepEnabled || e.dialer == nil || policy.ActiveSweepAgentID == nil {
		return
	}
	targets, err := decodeActiveSweepTargets(policy.ActiveSweepTargets)
	if err != nil {
		logger.Errorf(ctx, "discovery: active sweep: workspace %s: decode targets: %v", workspaceID, err)
		return
	}
	out, err := e.AgentSweep(ctx, workspaceID, AgentSweepRequest{
		AgentID: *policy.ActiveSweepAgentID,
		Hosts:   targets.Hosts,
		CIDRs:   targets.CIDRs,
		Ports:   targets.Ports,
		Actor:   "system:scheduled-sweep",
		Trigger: models.DiscoveryTriggerScheduled,
	})
	if err != nil {
		logger.Warnf(ctx, "discovery: active sweep: workspace %s: %v", workspaceID, err)
		return
	}
	res.ActiveSweepProbed = out.Probed
	res.ActiveSweepReachable = out.Reachable
	res.AssetsNew += out.AssetsNew
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
