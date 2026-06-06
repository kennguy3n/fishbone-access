package access

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/workers"
)

// ConnectorJobProcessor is the workers.Processor that executes connector jobs
// pulled from the access_jobs queue: identity syncs, access provisioning, and
// revocations. It decodes the job payload, loads the target connector scoped to
// the payload's workspace (tenant isolation), opens the sealed secrets just
// before the provider call, and dispatches to the registered AccessConnector.
type ConnectorJobProcessor struct {
	svc       *ConnectorManagementService
	syncState *SyncStateStore
}

// NewConnectorJobProcessor builds a processor over the given DB and credential
// encryptor. It constructs an internal management service (queue=nil — the
// processor consumes jobs, it does not enqueue them) to reuse the tenant-scoped
// connector loader and secret-opening logic.
func NewConnectorJobProcessor(db *gorm.DB, enc CredentialEncryptor) *ConnectorJobProcessor {
	return &ConnectorJobProcessor{
		svc:       NewConnectorManagementService(db, enc, nil),
		syncState: NewSyncStateStore(db),
	}
}

// Process implements workers.Processor.
func (p *ConnectorJobProcessor) Process(ctx context.Context, job workers.Job) error {
	if p == nil || p.svc == nil {
		return fmt.Errorf("access: ConnectorJobProcessor not initialised")
	}
	var payload jobPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return fmt.Errorf("access: decode job payload: %w", err)
	}
	workspaceID, err := uuid.Parse(payload.WorkspaceID)
	if err != nil {
		return fmt.Errorf("access: job %s: invalid workspace_id: %w", job.ID, err)
	}
	connectorID, err := uuid.Parse(payload.ConnectorID)
	if err != nil {
		return fmt.Errorf("access: job %s: invalid connector_id: %w", job.ID, err)
	}

	row, err := p.svc.loadConnector(ctx, p.svc.db, workspaceID, connectorID)
	if err != nil {
		return err
	}
	connector, err := GetAccessConnector(row.Provider)
	if err != nil {
		return fmt.Errorf("access: job %s: %w", job.ID, err)
	}
	cfg, secrets, err := p.svc.openConnector(ctx, row)
	if err != nil {
		return err
	}

	switch job.Type {
	case JobTypeSyncIdentities:
		return p.runSync(ctx, connector, row, payload, cfg, secrets)
	case JobTypeProvision:
		if payload.Grant == nil {
			return fmt.Errorf("access: job %s: provision job missing grant", job.ID)
		}
		return connector.ProvisionAccess(ctx, cfg, secrets, *payload.Grant)
	case JobTypeRevoke:
		if payload.Grant == nil {
			return fmt.Errorf("access: job %s: revoke job missing grant", job.ID)
		}
		return connector.RevokeAccess(ctx, cfg, secrets, *payload.Grant)
	default:
		return fmt.Errorf("access: job %s: unknown job type %q", job.ID, job.Type)
	}
}

// runSync drives a full identity sync, resuming from the persisted delta link
// when the provider supports incremental sync. It captures the latest
// next-checkpoint the connector emits and persists it so the next run is
// incremental, then stamps the connector's last_synced_at.
func (p *ConnectorJobProcessor) runSync(ctx context.Context, connector AccessConnector, row *models.AccessConnector, payload jobPayload, cfg, secrets map[string]interface{}) error {
	syncType := normalizeSyncType(payload.SyncType)
	checkpoint, err := p.syncState.Load(ctx, row.WorkspaceID, row.ID, syncType)
	if err != nil {
		return err
	}

	// Track the most recent non-empty checkpoint the connector hands back. For
	// delta-capable providers this is the opaque delta link to resume from next
	// time; for cursor-paginated providers it is the final page cursor.
	latestCheckpoint := checkpoint
	handler := func(_ []*Identity, nextCheckpoint string) error {
		if nextCheckpoint != "" {
			latestCheckpoint = nextCheckpoint
		}
		return nil
	}
	if err := connector.SyncIdentities(ctx, cfg, secrets, checkpoint, handler); err != nil {
		return fmt.Errorf("access: sync identities (connector=%s provider=%s): %w", row.ID, row.Provider, err)
	}

	if latestCheckpoint != checkpoint {
		if err := p.syncState.Save(ctx, row.WorkspaceID, row.ID, syncType, latestCheckpoint); err != nil {
			return err
		}
	}
	now := time.Now().UTC()
	if err := p.svc.db.WithContext(ctx).
		Model(&models.AccessConnector{}).
		Where("id = ? AND workspace_id = ?", row.ID, row.WorkspaceID).
		Update("last_synced_at", &now).Error; err != nil {
		return fmt.Errorf("access: stamp last_synced_at: %w", err)
	}
	return nil
}

// Ensure ConnectorJobProcessor satisfies the workers.Processor contract.
var _ workers.Processor = (*ConnectorJobProcessor)(nil)
