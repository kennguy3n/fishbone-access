package database

import (
	"errors"
	"testing"

	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// TestSoftDeleteIsActive locks in the GORM v2 soft-delete behaviour that the
// models.Base.DeletedAt gorm.DeletedAt field enables. If that field ever
// regresses to *time.Time, GORM emits a hard DELETE and stops filtering deleted
// rows, and every assertion below fails — which is exactly the silent data-loss
// bug we want CI to catch before the 1B–1E handlers start querying these models.
func TestSoftDeleteIsActive(t *testing.T) {
	db, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("auto-migrate: %v", err)
	}

	ws := &models.Workspace{Name: "acme", IAMCoreTenantID: "tenant-1"}
	if err := db.Create(ws).Error; err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := db.Delete(ws).Error; err != nil {
		t.Fatalf("delete: %v", err)
	}

	// A normal query must NOT return the soft-deleted row.
	var got models.Workspace
	err = db.First(&got, "id = ?", ws.ID).Error
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound for soft-deleted row, got err=%v (id=%v)", err, got.ID)
	}

	// The row must still physically exist (soft delete, not hard delete) and be
	// visible via Unscoped, with DeletedAt populated.
	var unscoped models.Workspace
	if err := db.Unscoped().First(&unscoped, "id = ?", ws.ID).Error; err != nil {
		t.Fatalf("unscoped first: row was hard-deleted (expected soft delete): %v", err)
	}
	if !unscoped.DeletedAt.Valid {
		t.Fatal("DeletedAt not set on soft-deleted row")
	}

	// Default count must exclude the soft-deleted row.
	var count int64
	if err := db.Model(&models.Workspace{}).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 live workspaces after soft delete, got %d", count)
	}
}
