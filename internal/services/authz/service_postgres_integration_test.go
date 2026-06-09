//go:build integration

package authz

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/migrations"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

// TestLastOwnerGuardOnPostgres proves the last-owner guard's owner-count query
// runs correctly on Postgres. The guard locks the remaining owner rows FOR
// UPDATE; an earlier implementation expressed this as
// `SELECT count(*) ... FOR UPDATE`, which Postgres rejects at runtime with
// "FOR UPDATE is not allowed with aggregate functions" — turning every owner
// demotion/removal into a 500 on the production dialect. SQLite silently
// ignores FOR UPDATE, so the unit tests could not catch this; this test pins
// the behaviour on Postgres.
//
// Postgres-only: skips unless ACCESS_TEST_DATABASE_URL is set, matching the
// migration and promote-serialization integration tests.
func TestLastOwnerGuardOnPostgres(t *testing.T) {
	dsn := os.Getenv("ACCESS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ACCESS_TEST_DATABASE_URL not set; skipping Postgres last-owner-guard integration test")
	}
	ctx := context.Background()
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db handle: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	if _, err := sqlDB.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if _, err := migrations.Run(ctx, sqlDB); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	ws := &models.Workspace{Name: "tenant-lastowner", IAMCoreTenantID: "tenant-lastowner-" + uuid.NewString(), Plan: "base"}
	if err := db.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}

	svc := NewRBACService(db, 0)

	// Two owners present.
	if err := svc.UpsertMember(ctx, ws.ID, "owner-1", RoleOwner, SystemActor); err != nil {
		t.Fatalf("seed owner-1: %v", err)
	}
	if err := svc.UpsertMember(ctx, ws.ID, "owner-2", RoleOwner, SystemActor); err != nil {
		t.Fatalf("seed owner-2: %v", err)
	}

	// Demoting one owner while a co-owner remains exercises the locked
	// owner-count path and must succeed on Postgres (the old aggregate+FOR
	// UPDATE query would 500 here).
	if err := svc.UpsertMember(ctx, ws.ID, "owner-1", RoleAdmin, SystemActor); err != nil {
		t.Fatalf("demote owner-1 with co-owner present: %v", err)
	}

	// Demoting the now-sole owner must be rejected by the guard — again proving
	// the count query executed (rather than erroring) and returned zero.
	if err := svc.UpsertMember(ctx, ws.ID, "owner-2", RoleAdmin, SystemActor); !errors.Is(err, ErrLastOwnerProtected) {
		t.Fatalf("demote last owner err = %v, want ErrLastOwnerProtected", err)
	}

	// The delete path shares the same guard helper.
	if err := svc.DeleteMember(ctx, ws.ID, "owner-2", SystemActor); !errors.Is(err, ErrLastOwnerProtected) {
		t.Fatalf("delete last owner err = %v, want ErrLastOwnerProtected", err)
	}
}
