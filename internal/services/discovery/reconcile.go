package discovery

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
			// a discovered host:port as managed (and vice-versa).
			if _, ok := managed[spec.Address]; ok {
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
		set[r.Address] = struct{}{}
		if n := normalizeEndpoint(r.Address, r.Protocol); n != "" {
			set[n] = struct{}{}
		}
	}
	return set, nil
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
