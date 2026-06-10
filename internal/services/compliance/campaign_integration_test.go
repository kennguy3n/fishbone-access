//go:build integration

package compliance

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/migrations"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// openCampaignPG resets a throwaway Postgres schema and returns a migrated
// handle. Postgres (unlike SQLite) honours the FOR UPDATE / FOR SHARE row locks
// the late-decision serialization relies on, so this race can only be exercised
// against a real PG. Skips unless ACCESS_TEST_DATABASE_URL is set.
func openCampaignPG(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("ACCESS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ACCESS_TEST_DATABASE_URL not set; skipping Postgres campaign integration test")
	}
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db handle: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if _, err := sqlDB.ExecContext(context.Background(), `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if _, err := migrations.Run(context.Background(), sqlDB); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	return db
}

// TestCloseCampaignRejectsLateDecisionConcurrentWithClose is the regression
// guard for the late-decision TOCTOU. Before the fix, CloseCampaign read the
// staged-revoke snapshot OUTSIDE its transaction, so a SubmitDecision(revoke)
// landing between that read and the state flip would be accepted, committed,
// and then silently missed by the post-commit teardown — leaving a grant live
// behind a campaign reported "closed".
//
// The fix takes the snapshot INSIDE the close transaction under the campaign's
// FOR UPDATE lock, and makes SubmitDecision take FOR SHARE on the same campaign
// row. A decision in flight when a close runs therefore either commits before
// the close's exclusive lock (so it is in the snapshot) or blocks until the
// close commits and then sees state=closed and is rejected. This test drives
// the second path deterministically: the close holds the lock (via a test hook)
// while a concurrent decision attempts to stage a new revoke; the decision must
// be rejected with ErrCampaignClosed, never accepted-then-stranded.
func TestCloseCampaignRejectsLateDecisionConcurrentWithClose(t *testing.T) {
	db := openCampaignPG(t)
	ws := seedWorkspace(t, db, "tenant-toctou-"+uuid.NewString())
	conn := seedConnector(t, db, ws, "fake")
	g1 := seedGrant(t, db, ws, conn, "u1", "r1", "reader")
	g2 := seedGrant(t, db, ws, conn, "u2", "r2", "reader")
	ctx := context.Background()
	rev := newFakeRevoker(db)
	svc := NewCertificationService(db, rev)

	camp, _, err := svc.StartCampaign(ctx, ws, CampaignInput{Name: "c"}, "auditor")
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	items, _ := svc.ListItems(ctx, ws, camp.ID, "")
	var item1, item2 uuid.UUID
	for _, it := range items {
		switch it.GrantID {
		case g1:
			item1 = it.ItemID
		case g2:
			item2 = it.ItemID
		}
	}
	if item1 == uuid.Nil || item2 == uuid.Nil {
		t.Fatalf("expected items for both grants, got %+v", items)
	}

	// Stage a revoke on item1 BEFORE the close — this one must be applied.
	if err := svc.SubmitDecision(ctx, ws, camp.ID, item1, models.CertificationDecisionRevoke, "auditor", "stale"); err != nil {
		t.Fatalf("stage item1 revoke: %v", err)
	}

	// The hook fires inside the close transaction while it holds FOR UPDATE on
	// the campaign row. It releases goroutine B to attempt a late decision, then
	// holds the lock briefly so B's FOR SHARE is observably blocked before the
	// close commits.
	locked := make(chan struct{})
	svc.beforeSnapshotHook = func() {
		close(locked)
		time.Sleep(300 * time.Millisecond)
	}

	type decisionResult struct{ err error }
	lateCh := make(chan decisionResult, 1)
	go func() {
		<-locked
		// Attempt to stage a NEW revoke on item2 while the close is in progress.
		err := svc.SubmitDecision(ctx, ws, camp.ID, item2, models.CertificationDecisionRevoke, "auditor", "late")
		lateCh <- decisionResult{err: err}
	}()

	report, err := svc.CloseCampaign(ctx, ws, camp.ID, "auditor")
	if err != nil {
		t.Fatalf("CloseCampaign: %v", err)
	}
	late := <-lateCh

	// The late decision must be rejected because the campaign closed under it.
	if !errors.Is(late.err, ErrCampaignClosed) {
		t.Fatalf("late SubmitDecision: want ErrCampaignClosed, got %v", late.err)
	}
	// The close applied exactly the one revoke that was staged before it.
	if report.State != models.CertificationStateClosed {
		t.Fatalf("expected closed, got %s", report.State)
	}
	if report.Revoked != 1 {
		t.Fatalf("expected exactly 1 revoke applied, got %d (report %+v)", report.Revoked, report)
	}
	if rev.callCount(g1) != 1 {
		t.Fatalf("g1 (staged before close) must be revoked once, got %d", rev.callCount(g1))
	}
	if rev.callCount(g2) != 0 {
		t.Fatalf("g2 (late, rejected) must NOT be revoked, got %d", rev.callCount(g2))
	}

	// item2 must remain undecided with its grant live — the rejected decision
	// left no trace, so nothing is stranded behind the closed campaign.
	var it2 models.CertificationItem
	if err := db.Where("workspace_id = ? AND id = ?", ws, item2).Take(&it2).Error; err != nil {
		t.Fatalf("load item2: %v", err)
	}
	if it2.Decision != models.CertificationDecisionPending {
		t.Fatalf("item2 decision: want pending, got %s", it2.Decision)
	}
	if it2.RevokedAt != nil {
		t.Fatalf("item2 revoked_at must be nil, got %v", it2.RevokedAt)
	}
	var grant2 models.AccessGrant
	if err := db.Where("workspace_id = ? AND id = ?", ws, g2).Take(&grant2).Error; err != nil {
		t.Fatalf("load g2: %v", err)
	}
	if grant2.State == lifecycle.GrantStateRevoked {
		t.Fatalf("g2 must still be live, got state %s", grant2.State)
	}
}
