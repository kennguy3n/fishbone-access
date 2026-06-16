package discovery

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// ConnectorInventory enumerates a cloud connector's native asset inventory and
// reconciles it into the discovered-asset surface. It resolves the connector
// (decrypting its config/secrets via the shared resolver), type-asserts the
// optional access.AssetDiscoverer capability, and runs DiscoverAssets with the
// connector's existing credentials. A connector whose provider has no inventory
// API simply does not implement the capability and yields ErrUnsupported — the
// engine never fabricates an inventory.
func (e *Engine) ConnectorInventory(ctx context.Context, workspaceID, connectorID uuid.UUID, actor, trigger string) (SweepResult, error) {
	if workspaceID == uuid.Nil || connectorID == uuid.Nil {
		return SweepResult{}, fmt.Errorf("%w: workspace_id and connector_id are required", ErrValidation)
	}
	if e.resolver == nil {
		return SweepResult{}, fmt.Errorf("%w: connector resolver not configured", ErrUnsupported)
	}
	resolved, err := e.resolver.Resolve(ctx, workspaceID, connectorID)
	if err != nil {
		// Preserve the resolver's classification (unknown connector → validation).
		return SweepResult{}, err
	}
	discoverer, ok := resolved.Impl.(access.AssetDiscoverer)
	if !ok {
		return SweepResult{}, fmt.Errorf("%w: connector %q (%s) has no asset-inventory capability",
			ErrUnsupported, connectorID, resolved.Provider)
	}

	if trigger == "" {
		trigger = models.DiscoveryTriggerManual
	}
	scan, err := e.startScan(ctx, workspaceID, models.DiscoverySourceConnector, trigger, actor, map[string]any{
		"connector_id": connectorID.String(),
		"provider":     resolved.Provider,
	})
	if err != nil {
		return SweepResult{}, err
	}

	result := SweepResult{ScanID: scan.ID}
	specs, discErr := discoverer.DiscoverAssets(ctx, resolved.Config, resolved.Secrets)
	if discErr != nil {
		e.finishScan(ctx, scan, discErr)
		return result, fmt.Errorf("discovery: connector %q inventory: %w", resolved.Provider, discErr)
	}

	found, fresh, recErr := e.reconcileAssets(ctx, workspaceID, models.DiscoverySourceConnector, specs, nil, &connectorID)
	result.AssetsFound = found
	result.AssetsNew = fresh
	scan.AssetsFound = found
	scan.AssetsNew = fresh
	e.finishScan(ctx, scan, recErr)
	if recErr != nil {
		return result, recErr
	}
	if err := e.appendAudit(ctx, workspaceID, actor, "discovery.connector_inventory", connectorID.String(), map[string]any{
		"provider":   resolved.Provider,
		"assets_new": fresh,
		"scan_id":    scan.ID.String(),
	}); err != nil {
		return result, err
	}
	return result, nil
}
