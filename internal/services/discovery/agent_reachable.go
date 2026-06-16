package discovery

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// ImportAgentReachable ingests the reachable-target specs an outbound agent
// self-reported at registration (models.AgentReachableTarget) into the
// discovered-asset surface. Unlike the active sweep it performs no network I/O
// and needs no relay — it reads what the agent already advertised — so it is the
// agent-discovery source the API/console always has available even though the
// relay's live tunnels terminate only in the gateway. A reported pattern that
// is a concrete host:port becomes a DiscoveredAsset with an inferred protocol; a
// bare host or CIDR is recorded as a host asset with no port (the admin supplies
// the protocol at onboard time).
func (e *Engine) ImportAgentReachable(ctx context.Context, workspaceID, agentID uuid.UUID, actor string) (SweepResult, error) {
	if workspaceID == uuid.Nil {
		return SweepResult{}, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if agentID == uuid.Nil {
		return SweepResult{}, fmt.Errorf("%w: agent_id is required", ErrValidation)
	}
	var reach []models.AgentReachableTarget
	if err := e.db.WithContext(ctx).
		Where("workspace_id = ? AND agent_id = ?", workspaceID, agentID).
		Find(&reach).Error; err != nil {
		return SweepResult{}, fmt.Errorf("discovery: load agent reachable targets: %w", err)
	}

	scan, err := e.startScan(ctx, workspaceID, models.DiscoverySourceAgentSweep, models.DiscoveryTriggerManual, actor, map[string]any{
		"agent_id": agentID.String(),
		"mode":     "self_report_import",
		"reported": len(reach),
	})
	if err != nil {
		return SweepResult{}, err
	}

	specs := make([]access.DiscoveredAssetSpec, 0, len(reach))
	for i := range reach {
		specs = append(specs, reachableToSpec(reach[i]))
	}
	result := SweepResult{ScanID: scan.ID}
	found, fresh, recErr := e.reconcileAssets(ctx, workspaceID, models.DiscoverySourceAgentSweep, specs, &agentID, nil)
	result.AssetsFound = found
	result.AssetsNew = fresh
	scan.AssetsFound = found
	scan.AssetsNew = fresh
	e.finishScan(ctx, scan, recErr)
	if recErr != nil {
		return result, recErr
	}
	if err := e.appendAudit(ctx, workspaceID, actor, "discovery.agent_reachable_import", agentID.String(), map[string]any{
		"reported":   len(reach),
		"assets_new": fresh,
		"scan_id":    scan.ID.String(),
	}); err != nil {
		return result, err
	}
	return result, nil
}

// reachableToSpec maps one agent self-report into an asset spec. A concrete
// host:port yields an inferred protocol; a bare host/CIDR pattern yields a host
// asset with no protocol (resolved at onboard time).
func reachableToSpec(r models.AgentReachableTarget) access.DiscoveredAssetSpec {
	pattern := strings.TrimSpace(r.Pattern)
	spec := access.DiscoveredAssetSpec{
		ExternalID: "agent-reach:" + r.AgentID.String() + ":" + pattern,
		Kind:       access.AssetKindHost,
		Name:       pattern,
		Metadata: map[string]string{
			"agent_id": r.AgentID.String(),
			"pattern":  pattern,
			"kind":     r.Kind,
			"origin":   "agent_self_report",
		},
	}
	if host, portStr, err := net.SplitHostPort(pattern); err == nil {
		if port, perr := strconv.Atoi(portStr); perr == nil {
			spec.Address = pattern
			spec.Name = host
			spec.Protocol = protocolForPort(port)
		}
	}
	return spec
}
