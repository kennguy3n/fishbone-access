package access

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

// newTestDB spins up an in-memory SQLite database with the full schema applied,
// for service-layer tests that need a real *gorm.DB.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	return db
}

func TestSyncStateStoreLoadEmpty(t *testing.T) {
	store := NewSyncStateStore(newTestDB(t))
	link, err := store.Load(context.Background(), uuid.New(), uuid.New(), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if link != "" {
		t.Errorf("Load on empty store = %q, want empty", link)
	}
}

func TestSyncStateStoreSaveAndLoad(t *testing.T) {
	store := NewSyncStateStore(newTestDB(t))
	ctx := context.Background()
	ws, conn := uuid.New(), uuid.New()

	if err := store.Save(ctx, ws, conn, "", "delta-token-1"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	link, err := store.Load(ctx, ws, conn, "identities")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if link != "delta-token-1" {
		t.Errorf("Load = %q, want delta-token-1", link)
	}

	// Saving again updates in place (no duplicate row).
	if err := store.Save(ctx, ws, conn, "identities", "delta-token-2"); err != nil {
		t.Fatalf("Save 2: %v", err)
	}
	link, err = store.Load(ctx, ws, conn, "")
	if err != nil {
		t.Fatalf("Load 2: %v", err)
	}
	if link != "delta-token-2" {
		t.Errorf("Load after update = %q, want delta-token-2", link)
	}

	var count int64
	if err := store.db.Model(&models.AccessSyncState{}).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("row count = %d, want 1 (upsert, not insert)", count)
	}
}

func TestSyncStateStoreTenantIsolation(t *testing.T) {
	store := NewSyncStateStore(newTestDB(t))
	ctx := context.Background()
	conn := uuid.New()
	wsA, wsB := uuid.New(), uuid.New()

	if err := store.Save(ctx, wsA, conn, "", "tenant-a-token"); err != nil {
		t.Fatalf("Save A: %v", err)
	}
	// A different workspace must not see workspace A's checkpoint, even for the
	// same connector id.
	link, err := store.Load(ctx, wsB, conn, "")
	if err != nil {
		t.Fatalf("Load B: %v", err)
	}
	if link != "" {
		t.Errorf("workspace B read workspace A's checkpoint: %q", link)
	}
}

func TestSyncStateStoreSeparateSyncTypes(t *testing.T) {
	store := NewSyncStateStore(newTestDB(t))
	ctx := context.Background()
	ws, conn := uuid.New(), uuid.New()

	if err := store.Save(ctx, ws, conn, "identities", "id-token"); err != nil {
		t.Fatalf("Save identities: %v", err)
	}
	if err := store.Save(ctx, ws, conn, "groups", "grp-token"); err != nil {
		t.Fatalf("Save groups: %v", err)
	}
	if link, _ := store.Load(ctx, ws, conn, "identities"); link != "id-token" {
		t.Errorf("identities link = %q", link)
	}
	if link, _ := store.Load(ctx, ws, conn, "groups"); link != "grp-token" {
		t.Errorf("groups link = %q", link)
	}
}

func TestSyncStateStoreClear(t *testing.T) {
	store := NewSyncStateStore(newTestDB(t))
	ctx := context.Background()
	ws, conn := uuid.New(), uuid.New()

	if err := store.Save(ctx, ws, conn, "", "token"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Clear(ctx, ws, conn, ""); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if link, _ := store.Load(ctx, ws, conn, ""); link != "" {
		t.Errorf("Load after Clear = %q, want empty", link)
	}
	// Clearing a non-existent checkpoint is a no-op.
	if err := store.Clear(ctx, ws, conn, ""); err != nil {
		t.Errorf("Clear non-existent: %v", err)
	}
}

// TestSyncStateStoreClearThenResave guards the soft-delete + unique-index
// interaction: Clear soft-deletes the checkpoint (deleted_at = now), and a
// later Save must be able to create a fresh row for the same
// (workspace, connector, sync_type). This only works when the unique index is
// partial (WHERE deleted_at IS NULL); a non-partial index would still count the
// soft-deleted row and reject the new insert. Mirrors the real flow where a
// stale delta link is cleared and the next sync persists a new cursor.
func TestSyncStateStoreClearThenResave(t *testing.T) {
	store := NewSyncStateStore(newTestDB(t))
	ctx := context.Background()
	ws, conn := uuid.New(), uuid.New()

	if err := store.Save(ctx, ws, conn, "", "stale-token"); err != nil {
		t.Fatalf("Save 1: %v", err)
	}
	if err := store.Clear(ctx, ws, conn, ""); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	// Re-saving after a clear must succeed (no unique-constraint collision with
	// the soft-deleted row) and must surface the new token.
	if err := store.Save(ctx, ws, conn, "", "fresh-token"); err != nil {
		t.Fatalf("Save after Clear: %v", err)
	}
	link, err := store.Load(ctx, ws, conn, "")
	if err != nil {
		t.Fatalf("Load after re-save: %v", err)
	}
	if link != "fresh-token" {
		t.Errorf("Load after re-save = %q, want fresh-token", link)
	}

	// Exactly one live checkpoint exists (the soft-deleted one is excluded).
	var count int64
	if err := store.db.Model(&models.AccessSyncState{}).
		Where("workspace_id = ? AND connector_id = ?", ws, conn).
		Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("live checkpoint count = %d, want 1", count)
	}
}

func TestSyncStateStoreValidation(t *testing.T) {
	store := NewSyncStateStore(newTestDB(t))
	ctx := context.Background()
	if _, err := store.Load(ctx, uuid.Nil, uuid.New(), ""); err == nil {
		t.Error("Load with nil workspace should error")
	}
	if err := store.Save(ctx, uuid.New(), uuid.Nil, "", "x"); err == nil {
		t.Error("Save with nil connector should error")
	}
}
