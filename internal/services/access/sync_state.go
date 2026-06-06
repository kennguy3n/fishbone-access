package access

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// DefaultSyncType is the sync_type used when a caller does not specify one. A
// connector may track multiple independent checkpoints (e.g. "identities" vs
// "groups"); the common identity sync uses this default.
const DefaultSyncType = "identities"

// SyncStateStore persists per-connector incremental-sync checkpoints in
// access_sync_state. Delta-capable providers hand back an opaque delta link or
// cursor at the end of each sync; storing it lets the next run fetch only what
// changed. Every method is scoped by workspace_id so one tenant can never read
// or overwrite another tenant's checkpoint.
type SyncStateStore struct {
	db *gorm.DB
}

// NewSyncStateStore builds a store over the given GORM handle.
func NewSyncStateStore(db *gorm.DB) *SyncStateStore {
	return &SyncStateStore{db: db}
}

// Load returns the persisted delta link for (workspace, connector, syncType),
// or an empty string when no checkpoint exists yet (a first/full sync). An
// empty syncType defaults to DefaultSyncType.
func (s *SyncStateStore) Load(ctx context.Context, workspaceID, connectorID uuid.UUID, syncType string) (string, error) {
	if s == nil || s.db == nil {
		return "", fmt.Errorf("access: SyncStateStore not initialised")
	}
	if workspaceID == uuid.Nil || connectorID == uuid.Nil {
		return "", fmt.Errorf("access: SyncStateStore.Load: workspace and connector are required")
	}
	syncType = normalizeSyncType(syncType)

	var state models.AccessSyncState
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND connector_id = ? AND sync_type = ?", workspaceID, connectorID, syncType).
		First(&state).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("access: load sync state: %w", err)
	}
	return state.DeltaLink, nil
}

// Save upserts the delta link and stamps last_synced_at for
// (workspace, connector, syncType). It runs in a transaction so a concurrent
// Save for the same checkpoint can't create a duplicate row; the worker queue's
// per-connector serialization (one in-flight job per connector) makes contention
// rare, but the transaction keeps the invariant regardless.
func (s *SyncStateStore) Save(ctx context.Context, workspaceID, connectorID uuid.UUID, syncType, deltaLink string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("access: SyncStateStore not initialised")
	}
	if workspaceID == uuid.Nil || connectorID == uuid.Nil {
		return fmt.Errorf("access: SyncStateStore.Save: workspace and connector are required")
	}
	syncType = normalizeSyncType(syncType)
	now := time.Now().UTC()

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var state models.AccessSyncState
		err := tx.Where("workspace_id = ? AND connector_id = ? AND sync_type = ?", workspaceID, connectorID, syncType).
			First(&state).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			state = models.AccessSyncState{
				Base:         models.Base{ID: uuid.New()},
				WorkspaceID:  workspaceID,
				ConnectorID:  connectorID,
				SyncType:     syncType,
				DeltaLink:    deltaLink,
				LastSyncedAt: &now,
			}
			if err := tx.Create(&state).Error; err != nil {
				return fmt.Errorf("access: create sync state: %w", err)
			}
			return nil
		case err != nil:
			return fmt.Errorf("access: load sync state for update: %w", err)
		default:
			state.DeltaLink = deltaLink
			state.LastSyncedAt = &now
			if err := tx.Save(&state).Error; err != nil {
				return fmt.Errorf("access: update sync state: %w", err)
			}
			return nil
		}
	})
}

// Clear removes the checkpoint for (workspace, connector, syncType), forcing the
// next sync to start from scratch (full enumeration). Used when a delta link is
// rejected as stale/expired by the provider. Deleting a non-existent checkpoint
// is a no-op.
func (s *SyncStateStore) Clear(ctx context.Context, workspaceID, connectorID uuid.UUID, syncType string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("access: SyncStateStore not initialised")
	}
	if workspaceID == uuid.Nil || connectorID == uuid.Nil {
		return fmt.Errorf("access: SyncStateStore.Clear: workspace and connector are required")
	}
	syncType = normalizeSyncType(syncType)
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND connector_id = ? AND sync_type = ?", workspaceID, connectorID, syncType).
		Delete(&models.AccessSyncState{}).Error
	if err != nil {
		return fmt.Errorf("access: clear sync state: %w", err)
	}
	return nil
}

func normalizeSyncType(syncType string) string {
	if syncType == "" {
		return DefaultSyncType
	}
	return syncType
}
