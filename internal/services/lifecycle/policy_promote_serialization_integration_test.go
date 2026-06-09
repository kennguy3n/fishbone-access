//go:build integration

package lifecycle

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/migrations"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

// TestPromoteSerializesOnWorkspaceLock proves the workspace-level promotion lock
// closes the cross-draft race, and — crucially — that the lock is taken at the
// very top of Promote's transaction, before any per-row / conflict-detection
// work.
//
// The race: two *different* drafts (a grant and a deny on the same
// subject/resource pair) are simulated while both are still drafts, so neither
// sees a conflict at simulate time. Each promotion's FOR UPDATE lock guards only
// its own row, so without a workspace-wide lock two concurrent promotions each
// re-scan a policy set where the other is still an uncommitted draft and BOTH
// could go active, silently defeating grant-vs-deny detection.
//
// Note appendAudit already takes the same per-workspace advisory lock, so *any*
// promotion blocks on a held lock eventually — that alone does not prove the
// fix. What the fix adds is taking the lock FIRST, before loadPolicyTx row-locks
// the draft. This test distinguishes the two deterministically: while an
// out-of-band transaction holds the workspace lock and a Promote is blocked, the
// draft row must still be unlocked (SELECT ... FOR UPDATE NOWAIT succeeds). On
// the unfixed code the blocked Promote would already hold the draft's row lock
// (it reaches appendAudit only after loadPolicyTx + the state update), so the
// NOWAIT probe would fail. After the lock is released the promotion completes,
// the conflicting deny is rejected with PromoteConflictError, and the active set
// holds exactly one of the pair.
//
// SQLite serializes all writers on one global lock and cannot model independent
// sessions, so this is Postgres-only and skips unless ACCESS_TEST_DATABASE_URL
// is set — the same gate the migration integration test uses.
func TestPromoteSerializesOnWorkspaceLock(t *testing.T) {
	dsn := os.Getenv("ACCESS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ACCESS_TEST_DATABASE_URL not set; skipping Postgres promote-serialization integration test")
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
	// The holder tx, the racing Promote, and the row-lock probe each need their
	// own connection.
	sqlDB.SetMaxOpenConns(5)

	// Reset to a clean schema and apply the production migrations (not GORM
	// AutoMigrate, which can't reconcile the migration-managed constraint
	// names). ACCESS_TEST_DATABASE_URL is expected to point at a throwaway
	// database, matching the migration integration test's convention.
	if _, err := sqlDB.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if _, err := migrations.Run(ctx, sqlDB); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	ws := seedWorkspace(t, db, "tenant-promote-race-"+uuid.NewString())
	svc := NewPolicyService(db)

	grantDef := mustJSON(t, PolicyDefinition{Action: "grant", Subjects: []string{"u1"}, Resources: []string{"app:db"}, Role: "admin"})
	grant, err := svc.CreatePolicy(ctx, CreatePolicyInput{WorkspaceID: ws, Name: "grant", Definition: grantDef, Actor: "admin"})
	if err != nil {
		t.Fatalf("create grant draft: %v", err)
	}
	denyDef := mustJSON(t, PolicyDefinition{Action: "deny", Subjects: []string{"u1"}, Resources: []string{"app:db"}})
	deny, err := svc.CreatePolicy(ctx, CreatePolicyInput{WorkspaceID: ws, Name: "deny", Definition: denyDef, Actor: "admin"})
	if err != nil {
		t.Fatalf("create deny draft: %v", err)
	}
	// Both simulate cleanly: each only scans ACTIVE policies, and the other is
	// still a draft, so neither reports a conflict yet.
	if _, err := svc.Simulate(ctx, ws, grant.ID); err != nil {
		t.Fatalf("simulate grant: %v", err)
	}
	if _, err := svc.Simulate(ctx, ws, deny.ID); err != nil {
		t.Fatalf("simulate deny: %v", err)
	}

	// Hold the workspace advisory lock from an out-of-band transaction so any
	// promotion that takes the same lock must wait for us.
	holder := db.Begin()
	if holder.Error != nil {
		t.Fatalf("begin holder tx: %v", holder.Error)
	}
	if err := lockWorkspace(ctx, holder, ws); err != nil {
		_ = holder.Rollback()
		t.Fatalf("acquire holder lock: %v", err)
	}

	// Promote the grant on another connection; it must block on the workspace
	// lock the holder is sitting on.
	promoted := make(chan error, 1)
	go func() {
		_, e := svc.Promote(ctx, ws, grant.ID, "admin", PromoteOptions{})
		promoted <- e
	}()

	// Give the blocked promotion time to reach its blocking point.
	select {
	case e := <-promoted:
		_ = holder.Rollback()
		t.Fatalf("promotion completed (err=%v) while the workspace lock was held; promotions are not serialized", e)
	case <-time.After(750 * time.Millisecond):
		// Still blocked, as expected.
	}

	// The fix takes the workspace lock BEFORE loadPolicyTx, so the draft row must
	// not be row-locked yet. A FOR UPDATE NOWAIT from a third connection succeeds
	// when the fix is present; on the unfixed code the blocked promotion already
	// holds the row lock (it reaches appendAudit only after loadPolicyTx), so the
	// probe would fail with lock_not_available.
	if err := probeRowUnlocked(ctx, t, sqlDB, ws, grant.ID); err != nil {
		_ = holder.Rollback()
		t.Fatalf("draft row is already locked while Promote is blocked on the workspace lock — the lock is not taken before loadPolicyTx: %v", err)
	}

	// Release the lock; the blocked promotion should now acquire it and succeed.
	if err := holder.Rollback().Error; err != nil {
		t.Fatalf("release holder lock: %v", err)
	}
	select {
	case e := <-promoted:
		if e != nil {
			t.Fatalf("promotion failed after lock release: %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("promotion did not complete after the workspace lock was released")
	}

	// The grant is now live, so promoting the conflicting deny must be rejected
	// for the grant-vs-deny conflict the re-scan now sees.
	_, err = svc.Promote(ctx, ws, deny.ID, "admin", PromoteOptions{})
	var conflictErr *PromoteConflictError
	if !errors.As(err, &conflictErr) {
		t.Fatalf("expected PromoteConflictError promoting the conflicting deny, got %v", err)
	}

	// The committed active set must hold exactly one of the conflicting pair.
	var active int64
	if err := db.Model(&models.Policy{}).
		Where("workspace_id = ? AND state = ? AND id IN ?", ws, PolicyStateActive, []uuid.UUID{grant.ID, deny.ID}).
		Count(&active).Error; err != nil {
		t.Fatalf("count active: %v", err)
	}
	if active != 1 {
		t.Fatalf("expected exactly 1 of the conflicting pair active, got %d", active)
	}
}

// probeRowUnlocked attempts a FOR UPDATE NOWAIT on the policy row from an
// independent transaction and returns an error if the row is currently locked
// (Postgres reports lock_not_available, SQLSTATE 55P03). The probe transaction
// is always rolled back, so it never itself promotes or mutates state.
func probeRowUnlocked(ctx context.Context, t *testing.T, sqlDB *sql.DB, ws, id uuid.UUID) error {
	t.Helper()
	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var got string
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM policies WHERE workspace_id = $1 AND id = $2 FOR UPDATE NOWAIT`,
		ws, id,
	).Scan(&got)
	if err != nil {
		// 55P03 = lock_not_available: the row is held by the blocked promotion.
		if strings.Contains(err.Error(), "55P03") {
			return errors.New("row is row-locked (SQLSTATE 55P03)")
		}
		return err
	}
	return nil
}
