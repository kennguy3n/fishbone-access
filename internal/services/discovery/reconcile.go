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
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// reconcileAssets upserts a batch of discovered asset specs for one workspace
// and source, idempotently keyed on (workspace, source, external_id). A re-scan
// advances last_seen_at and refreshes mutable facts in place; it never
// duplicates and never resurrects an operator-ignored row as unmanaged. It
// returns (found, new) counts for the scan record. An asset that already maps to
// a live PAM target is classified managed; otherwise unmanaged.
func (e *Engine) reconcileAssets(ctx context.Context, workspaceID uuid.UUID, source string, specs []access.DiscoveredAssetSpec, agentID, connectorID *uuid.UUID) (found, fresh int, err error) {
	now := e.now()
	// Pre-load the managed address set once so classification is O(found),
	// not O(found * targets) — set-based, not per-row queries.
	managed, err := e.managedAddresses(ctx, workspaceID)
	if err != nil {
		return 0, 0, err
	}
	for i := range specs {
		spec := specs[i]
		if spec.ExternalID == "" {
			continue
		}
		found++
		protocol := spec.Protocol
		if protocol == "" {
			protocol = defaultProtocolForKind(spec.Kind)
		}
		status := models.DiscoveryStatusUnmanaged
		if spec.Address != "" {
			// Match on the raw address first, then on the port-normalized form
			// so a target registered without an explicit port still classifies
			// a discovered host:port as managed (and vice-versa). Lowercase the
			// raw probe to match the (now case-insensitive) managedAddresses keys.
			if _, ok := managed[strings.ToLower(strings.TrimSpace(spec.Address))]; ok {
				status = models.DiscoveryStatusManaged
			} else if _, ok := managed[normalizeEndpoint(spec.Address, protocol)]; ok {
				status = models.DiscoveryStatusManaged
			}
		}
		created, upErr := e.upsertAsset(ctx, workspaceID, source, spec, protocol, status, agentID, connectorID, now)
		if upErr != nil {
			return found, fresh, upErr
		}
		if created {
			fresh++
		}
	}
	return found, fresh, nil
}

// upsertAsset performs the idempotent insert-or-update for one asset and
// reports whether a new row was inserted. The conflict target matches the
// partial unique index uq_discovered_assets_identity. An operator-ignored row
// keeps its status; a managed row stays managed; otherwise we refresh status,
// address, protocol, metadata, and last_seen_at.
func (e *Engine) upsertAsset(ctx context.Context, workspaceID uuid.UUID, source string, spec access.DiscoveredAssetSpec, protocol, status string, agentID, connectorID *uuid.UUID, now time.Time) (bool, error) {
	var created bool
	err := e.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing models.DiscoveredAsset
		findErr := tx.Where("workspace_id = ? AND source = ? AND external_id = ?", workspaceID, source, spec.ExternalID).
			Take(&existing).Error
		switch {
		case findErr == nil:
			updates := map[string]any{
				"name":         spec.Name,
				"protocol":     protocol,
				"address":      spec.Address,
				"metadata":     jsonMap(spec.Metadata),
				"last_seen_at": now,
			}
			if agentID != nil {
				updates["agent_id"] = *agentID
			}
			if connectorID != nil {
				updates["connector_id"] = *connectorID
			}
			// Never downgrade a managed/ignored row back to unmanaged on a
			// re-scan; only promote unmanaged→managed when the address now maps
			// to a live target.
			if existing.Status == models.DiscoveryStatusUnmanaged && status == models.DiscoveryStatusManaged {
				updates["status"] = models.DiscoveryStatusManaged
			}
			return tx.Model(&models.DiscoveredAsset{}).
				Where("id = ?", existing.ID).Updates(updates).Error
		case isNotFound(findErr):
			row := &models.DiscoveredAsset{
				WorkspaceID: workspaceID,
				Source:      source,
				ExternalID:  spec.ExternalID,
				Name:        spec.Name,
				Protocol:    protocol,
				Address:     spec.Address,
				Status:      status,
				AgentID:     agentID,
				ConnectorID: connectorID,
				Metadata:    jsonMap(spec.Metadata),
				FirstSeenAt: now,
				LastSeenAt:  now,
			}
			if err := tx.Create(row).Error; err != nil {
				return err
			}
			created = true
			return nil
		default:
			return findErr
		}
	})
	if err != nil {
		return false, fmt.Errorf("discovery: upsert asset %q: %w", spec.ExternalID, err)
	}
	return created, nil
}

// managedAddresses returns the set of PAM target addresses already managed in
// the workspace, used to classify a discovered asset as managed when its
// endpoint matches an existing target.
func (e *Engine) managedAddresses(ctx context.Context, workspaceID uuid.UUID) (map[string]struct{}, error) {
	var rows []struct {
		Address  string
		Protocol string
	}
	if err := e.db.WithContext(ctx).Model(&models.PAMTarget{}).
		Where("workspace_id = ?", workspaceID).
		Select("address", "protocol").
		Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("discovery: load managed targets: %w", err)
	}
	// Index each target under both its raw address and its port-normalized form
	// so classification tolerates a missing/implicit port on either side.
	set := make(map[string]struct{}, len(rows)*2)
	for _, r := range rows {
		if r.Address == "" {
			continue
		}
		// Lowercase the raw key (hostnames are case-insensitive per RFC) so this
		// path classifies mixed-case addresses the same way the normalized form
		// and targetEndpointIndex already do.
		set[strings.ToLower(strings.TrimSpace(r.Address))] = struct{}{}
		if n := normalizeEndpoint(r.Address, r.Protocol); n != "" {
			set[n] = struct{}{}
		}
	}
	return set, nil
}

// healStuckBatchSize bounds how many stranded assets one sweep recovers, keeping
// the reconcile pass's memory and transaction count constant regardless of fleet
// size; any remainder is picked up by the next sweep. Stranded assets are rare
// (a local-tx failure mid-onboard), so a modest cap is ample.
const healStuckBatchSize = 200

// endpointTarget is a PAM target indexed by its endpoint for stuck-asset recovery.
type endpointTarget struct {
	id       uuid.UUID
	protocol string
}

// reconcileStuckOnboards recovers assets left in the rare managed/target_id=NULL
// state — a PAM target was created during OnboardAsset but the follow-up
// linkAssetTarget transaction failed (a local DB error, or the bind+link
// double-failure path). Such an asset is un-onboardable (the status check
// returns ErrConflict) and invisible to the policy sweep (which filters
// status='unmanaged'), so without this it would stay stuck until manual
// intervention. For each stranded asset we recover idempotently:
//   - re-link it to the target the onboard already created, identified
//     deterministically by (workspace, normalized endpoint, protocol) when
//     exactly one such target exists and is not already linked to another asset; or
//   - if no orphan target matches, release the claim back to unmanaged so the
//     asset reappears as an onboarding candidate (a retry then creates a fresh
//     target — no duplicate, because none existed).
//
// Ambiguous matches (more than one unlinked candidate target at the same
// endpoint) are deliberately left untouched so an asset is never linked to the
// wrong target/credential; they need operator attention. Returns the number of
// assets recovered (re-linked or released).
func (e *Engine) reconcileStuckOnboards(ctx context.Context, workspaceID uuid.UUID) (int, error) {
	var stuck []models.DiscoveredAsset
	if err := e.db.WithContext(ctx).
		Where("workspace_id = ? AND status = ? AND target_id IS NULL", workspaceID, models.DiscoveryStatusManaged).
		Order("id").Limit(healStuckBatchSize).Find(&stuck).Error; err != nil {
		return 0, fmt.Errorf("discovery: load stuck onboards: %w", err)
	}
	if len(stuck) == 0 {
		// Common case on a healthy sweep: the partial index makes this an
		// index-only scan that returns nothing, so we never build the target
		// index below.
		return 0, nil
	}

	candidates, linked, err := e.targetEndpointIndex(ctx, workspaceID)
	if err != nil {
		return 0, err
	}

	healed := 0
	for i := range stuck {
		if ctx.Err() != nil {
			return healed, ctx.Err()
		}
		asset := stuck[i]
		matches := uniqueUnlinkedTargets(candidates, linked, asset.Address, asset.Protocol)
		switch len(matches) {
		case 1:
			// Re-link to the already-created target (idempotent: linkAssetTarget
			// guards on target_id IS NULL). Record it linked so a second stranded
			// asset at the same endpoint can't also claim it.
			if linkErr := e.linkAssetTarget(ctx, workspaceID, asset.ID, matches[0], "system:reconcile", models.DiscoveryTriggerScheduled); linkErr != nil {
				if errors.Is(linkErr, ErrNotFound) {
					// Raced with a concurrent linker/onboarder — the asset is no
					// longer managed/NULL; leave it for the next sweep.
					continue
				}
				return healed, fmt.Errorf("discovery: relink stuck asset %s: %w", asset.ID, linkErr)
			}
			linked[matches[0]] = struct{}{}
			healed++
		case 0:
			// No target stands behind the claim; release it so it can be onboarded
			// again (release is guarded on managed/target_id=NULL, so it can never
			// clobber a concurrently-linked asset). Only count it healed when the
			// row was actually flipped, so a swallowed DB error or a concurrent
			// linker's row doesn't inflate the Healed metric — the next sweep
			// retries either way.
			if e.releaseAssetClaim(ctx, workspaceID, asset.ID) {
				healed++
			}
		default:
			// Ambiguous: multiple unlinked targets share this endpoint. Leave it
			// for an operator rather than risk linking the wrong credential.
			continue
		}
	}
	return healed, nil
}

// targetEndpointIndex returns the workspace's PAM targets indexed by endpoint
// (both raw address and port-normalized form, lowercased) plus the set of
// target ids already linked to a discovered asset, so stuck-asset recovery can
// find an orphan target without re-linking one that belongs to another asset.
func (e *Engine) targetEndpointIndex(ctx context.Context, workspaceID uuid.UUID) (map[string][]endpointTarget, map[uuid.UUID]struct{}, error) {
	var targets []struct {
		ID       uuid.UUID
		Address  string
		Protocol string
	}
	if err := e.db.WithContext(ctx).Model(&models.PAMTarget{}).
		Where("workspace_id = ?", workspaceID).
		Select("id", "address", "protocol").Scan(&targets).Error; err != nil {
		return nil, nil, fmt.Errorf("discovery: load targets for reconcile: %w", err)
	}
	idx := make(map[string][]endpointTarget, len(targets)*2)
	add := func(key string, t endpointTarget) {
		if key == "" {
			return
		}
		idx[key] = append(idx[key], t)
	}
	for _, t := range targets {
		if t.Address == "" {
			continue
		}
		et := endpointTarget{id: t.ID, protocol: strings.ToLower(strings.TrimSpace(t.Protocol))}
		add(strings.ToLower(strings.TrimSpace(t.Address)), et)
		add(normalizeEndpoint(t.Address, t.Protocol), et)
	}

	var linkedIDs []uuid.UUID
	if err := e.db.WithContext(ctx).Model(&models.DiscoveredAsset{}).
		Where("workspace_id = ? AND target_id IS NOT NULL", workspaceID).
		Pluck("target_id", &linkedIDs).Error; err != nil {
		return nil, nil, fmt.Errorf("discovery: load linked targets for reconcile: %w", err)
	}
	linked := make(map[uuid.UUID]struct{}, len(linkedIDs))
	for _, id := range linkedIDs {
		linked[id] = struct{}{}
	}
	return idx, linked, nil
}

// uniqueUnlinkedTargets returns the distinct target ids matching the asset's
// endpoint (raw or port-normalized) and protocol that are not already linked to
// another asset. Protocol must match when both sides declare one, so a stranded
// asset is never re-linked to a different service at the same host:port.
func uniqueUnlinkedTargets(idx map[string][]endpointTarget, linked map[uuid.UUID]struct{}, address, protocol string) []uuid.UUID {
	proto := strings.ToLower(strings.TrimSpace(protocol))
	seen := make(map[uuid.UUID]struct{})
	var out []uuid.UUID
	consider := func(key string) {
		if key == "" {
			return
		}
		for _, t := range idx[key] {
			if proto != "" && t.protocol != "" && t.protocol != proto {
				continue
			}
			if _, isLinked := linked[t.id]; isLinked {
				continue
			}
			if _, dup := seen[t.id]; dup {
				continue
			}
			seen[t.id] = struct{}{}
			out = append(out, t.id)
		}
	}
	consider(strings.ToLower(strings.TrimSpace(address)))
	consider(normalizeEndpoint(address, protocol))
	return out
}

// reconcileAccounts upserts a batch of enumerated DB accounts for one database
// target, idempotently keyed on (workspace, target, username). An account whose
// username matches a live grant on the target is managed; one with login
// capability but no grant is an orphan; the rest are unmanaged. Returns the
// count found.
func (e *Engine) reconcileAccounts(ctx context.Context, workspaceID, targetID uuid.UUID, accounts []EnumeratedAccount, grantedUsers map[string]struct{}) (int, error) {
	now := e.now()
	found := 0
	for i := range accounts {
		acct := accounts[i]
		if acct.Username == "" {
			continue
		}
		found++
		status := models.DiscoveryStatusUnmanaged
		if _, ok := grantedUsers[acct.Username]; ok {
			status = models.DiscoveryStatusManaged
		} else if acct.CanLogin {
			// A login-capable account with no live grant is an orphan — exactly
			// the connector-orphan notion, but for accounts living inside the DB.
			status = models.DiscoveryStatusOrphan
		}
		if err := e.upsertAccount(ctx, workspaceID, targetID, acct, status, now); err != nil {
			return found, err
		}
	}
	return found, nil
}

func (e *Engine) upsertAccount(ctx context.Context, workspaceID, targetID uuid.UUID, acct EnumeratedAccount, status string, now time.Time) error {
	err := e.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing models.DiscoveredAccount
		findErr := tx.Where("workspace_id = ? AND target_id = ? AND username = ?", workspaceID, targetID, acct.Username).
			Take(&existing).Error
		switch {
		case findErr == nil:
			updates := map[string]any{
				"can_login":    acct.CanLogin,
				"superuser":    acct.Superuser,
				"attributes":   jsonMap(acct.Attributes),
				"last_seen_at": now,
			}
			// An ignored disposition is sticky; otherwise refresh classification.
			if existing.Status != models.DiscoveryStatusIgnored {
				updates["status"] = status
			}
			return tx.Model(&models.DiscoveredAccount{}).Where("id = ?", existing.ID).Updates(updates).Error
		case isNotFound(findErr):
			return tx.Create(&models.DiscoveredAccount{
				WorkspaceID: workspaceID,
				TargetID:    targetID,
				Username:    acct.Username,
				Source:      models.DiscoverySourceDBAccounts,
				Status:      status,
				CanLogin:    acct.CanLogin,
				Superuser:   acct.Superuser,
				Attributes:  jsonMap(acct.Attributes),
				FirstSeenAt: now,
				LastSeenAt:  now,
			}).Error
		default:
			return findErr
		}
	})
	if err != nil {
		return fmt.Errorf("discovery: upsert account %q: %w", acct.Username, err)
	}
	return nil
}

// startScan inserts a running DiscoveryScan row and returns it so the caller can
// finalise it with finishScan.
func (e *Engine) startScan(ctx context.Context, workspaceID uuid.UUID, source, trigger, actor string, params map[string]any) (*models.DiscoveryScan, error) {
	scan := &models.DiscoveryScan{
		WorkspaceID: workspaceID,
		Source:      source,
		Trigger:     trigger,
		Status:      models.DiscoveryScanRunning,
		Actor:       actor,
		StartedAt:   e.now(),
		Params:      mustAuditMeta(params),
	}
	if err := e.db.WithContext(ctx).Create(scan).Error; err != nil {
		return nil, fmt.Errorf("discovery: start scan: %w", err)
	}
	return scan, nil
}

// finishScan stamps a scan's terminal status, counts, and finish time. A
// scanErr produces a failed status carrying the (secret-free) error string.
func (e *Engine) finishScan(ctx context.Context, scan *models.DiscoveryScan, scanErr error) {
	now := e.now()
	updates := map[string]any{
		"assets_found":    scan.AssetsFound,
		"assets_new":      scan.AssetsNew,
		"accounts_found":  scan.AccountsFound,
		"onboarded_count": scan.OnboardedCount,
		"finished_at":     now,
	}
	if scanErr != nil {
		updates["status"] = models.DiscoveryScanFailed
		updates["error"] = scanErr.Error()
	} else {
		updates["status"] = models.DiscoveryScanCompleted
	}
	// Best-effort: a scan-record finalisation failure must not mask the scan's
	// own result, so the error is swallowed (the row stays "running" and is
	// reaped by the next sweep's freshness logic).
	_ = e.db.WithContext(ctx).Model(&models.DiscoveryScan{}).
		Where("id = ?", scan.ID).Updates(updates).Error
}

func isNotFound(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound)
}
