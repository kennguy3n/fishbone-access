package compliance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

func TestStartCampaignEnumeratesScopedGrants(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	other := seedConnector(t, db, ws, "other")
	ctx := context.Background()

	seedGrant(t, db, ws, conn, "u1", "prod/db/orders", "reader")
	seedGrant(t, db, ws, conn, "u2", "prod/db/users", "writer")
	seedGrant(t, db, ws, conn, "u3", "staging/db/x", "reader")
	seedGrant(t, db, ws, other, "u4", "prod/db/orders", "reader")

	svc := NewCertificationService(db, newFakeRevoker(db))

	// Scope by resource prefix "prod/db/" -> 3 grants (two on conn, one on other).
	camp, n, err := svc.StartCampaign(ctx, ws, CampaignInput{Name: "prod db", ScopeResource: "prod/db/"}, "auditor")
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 scoped items, got %d", n)
	}

	// Scope by role "reader" AND connector -> only the two readers on conn.
	_, n2, err := svc.StartCampaign(ctx, ws, CampaignInput{Name: "readers", ScopeRole: "reader", ScopeConnectorID: &conn}, "auditor")
	if err != nil {
		t.Fatalf("StartCampaign role+conn: %v", err)
	}
	if n2 != 2 {
		t.Fatalf("expected 2 reader items on conn, got %d", n2)
	}

	// A campaign.started evidence event exists.
	var started int64
	db.Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND action = ? AND target_ref = ?", ws, "certification.campaign.started", camp.ID.String()).
		Count(&started)
	if started != 1 {
		t.Fatalf("expected 1 started evidence event, got %d", started)
	}
}

func TestStartCampaignRejectsUnknownFrameworkAndConnector(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	ctx := context.Background()
	svc := NewCertificationService(db, newFakeRevoker(db))

	if _, _, err := svc.StartCampaign(ctx, ws, CampaignInput{Name: "x", Framework: "HIPAA"}, "a"); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for bad framework, got %v", err)
	}
	bogus := uuid.New()
	if _, _, err := svc.StartCampaign(ctx, ws, CampaignInput{Name: "x", ScopeConnectorID: &bogus}, "a"); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for unknown connector, got %v", err)
	}
}

func TestSubmitDecisionStagesRevokeUntilClose(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	gid := seedGrant(t, db, ws, conn, "u1", "r", "reader")
	ctx := context.Background()
	rev := newFakeRevoker(db)
	svc := NewCertificationService(db, rev)

	camp, _, err := svc.StartCampaign(ctx, ws, CampaignInput{Name: "c"}, "auditor")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	items, _ := svc.ListItems(ctx, ws, camp.ID, "")
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	itemID := items[0].ItemID

	if err := svc.SubmitDecision(ctx, ws, camp.ID, itemID, models.CertificationDecisionRevoke, "auditor", "stale"); err != nil {
		t.Fatalf("decision: %v", err)
	}
	// Staged: the revoker must NOT have been called yet, grant still active.
	if rev.callCount(gid) != 0 {
		t.Fatalf("revoke should be staged, but revoker was called")
	}
	var g models.AccessGrant
	db.Where("id = ?", gid).Take(&g)
	if g.State != "active" {
		t.Fatalf("grant should still be active before close, got %s", g.State)
	}

	// A decision evidence event was appended.
	var dec int64
	db.Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND action = ?", ws, "certification.item.decision.revoke").
		Count(&dec)
	if dec != 1 {
		t.Fatalf("expected 1 decision evidence event, got %d", dec)
	}

	// Preview shows exactly this revoke.
	preview, err := svc.PreviewRevocations(ctx, ws, camp.ID)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if len(preview) != 1 || preview[0].GrantID != gid {
		t.Fatalf("unexpected preview: %+v", preview)
	}
}

func TestCloseCampaignAppliesStagedRevokes(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	g1 := seedGrant(t, db, ws, conn, "u1", "r1", "reader")
	g2 := seedGrant(t, db, ws, conn, "u2", "r2", "reader")
	ctx := context.Background()
	rev := newFakeRevoker(db)
	svc := NewCertificationService(db, rev)

	camp, _, _ := svc.StartCampaign(ctx, ws, CampaignInput{Name: "c"}, "auditor")
	items, _ := svc.ListItems(ctx, ws, camp.ID, "")
	for _, it := range items {
		decision := models.CertificationDecisionCertify
		if it.GrantID == g2 {
			decision = models.CertificationDecisionRevoke
		}
		if err := svc.SubmitDecision(ctx, ws, camp.ID, it.ItemID, decision, "auditor", ""); err != nil {
			t.Fatalf("decision: %v", err)
		}
	}

	report, err := svc.CloseCampaign(ctx, ws, camp.ID, "auditor")
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	if report.State != models.CertificationStateClosed {
		t.Fatalf("expected closed, got %s", report.State)
	}
	if report.Certified != 1 || report.Revoked != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	// Only g2 revoked; g1 untouched.
	if rev.callCount(g2) != 1 {
		t.Fatalf("expected g2 revoked once, got %d", rev.callCount(g2))
	}
	if rev.callCount(g1) != 0 {
		t.Fatalf("certified grant must not be revoked, got %d calls", rev.callCount(g1))
	}

	// Re-close is idempotent and does NOT re-drive an already-applied revoke
	// (revoked_at was stamped).
	if _, err := svc.CloseCampaign(ctx, ws, camp.ID, "auditor"); err != nil {
		t.Fatalf("re-close: %v", err)
	}
	if rev.callCount(g2) != 1 {
		t.Fatalf("re-close must not re-revoke, got %d calls", rev.callCount(g2))
	}
}

// TestCloseCampaignToleratesIndependentlyRevokedGrant proves the post-commit
// apply loop converges when a staged-revoke grant was already revoked out-of-
// band (e.g. via /grants/:id/revoke or a concurrent close) between the preview
// snapshot and the apply. The idempotent revoker no-ops on the already-revoked
// grant, the close still applies the OTHER staged revoke, returns a report, and
// stamps revoked_at on both items — no error and no half-applied state.
func TestCloseCampaignToleratesIndependentlyRevokedGrant(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	g1 := seedGrant(t, db, ws, conn, "u1", "r1", "reader")
	g2 := seedGrant(t, db, ws, conn, "u2", "r2", "reader")
	ctx := context.Background()
	rev := newFakeRevoker(db)
	svc := NewCertificationService(db, rev)

	camp, _, _ := svc.StartCampaign(ctx, ws, CampaignInput{Name: "c"}, "auditor")
	items, _ := svc.ListItems(ctx, ws, camp.ID, "")
	for _, it := range items { // stage BOTH grants for revoke
		if err := svc.SubmitDecision(ctx, ws, camp.ID, it.ItemID, models.CertificationDecisionRevoke, "auditor", ""); err != nil {
			t.Fatalf("decision: %v", err)
		}
	}

	// Independently revoke g1 out-of-band BEFORE close (simulates a direct
	// /grants/:id/revoke or a concurrent campaign close landing first).
	if err := db.WithContext(ctx).Model(&models.AccessGrant{}).
		Where("workspace_id = ? AND id = ?", ws, g1).
		Updates(map[string]any{"state": lifecycle.GrantStateRevoked, "revoked_at": time.Now().UTC()}).Error; err != nil {
		t.Fatalf("independent revoke: %v", err)
	}

	report, err := svc.CloseCampaign(ctx, ws, camp.ID, "auditor")
	if err != nil {
		t.Fatalf("close must converge despite an independently-revoked grant, got: %v", err)
	}
	if report.State != models.CertificationStateClosed {
		t.Fatalf("expected closed, got %s", report.State)
	}
	if report.Revoked != 2 {
		t.Fatalf("both items decided revoke, got %+v", report)
	}
	// g1 was attempted once (idempotent no-op); g2 actually torn down once.
	if rev.callCount(g1) != 1 || rev.callCount(g2) != 1 {
		t.Fatalf("expected each grant attempted once, got g1=%d g2=%d", rev.callCount(g1), rev.callCount(g2))
	}
	// Both revoke items must be stamped revoked_at (loop did not abort on g1).
	var unstamped int64
	if err := db.WithContext(ctx).Model(&models.CertificationItem{}).
		Where("workspace_id = ? AND campaign_id = ? AND decision = ? AND revoked_at IS NULL",
			ws, camp.ID, models.CertificationDecisionRevoke).
		Count(&unstamped).Error; err != nil {
		t.Fatalf("count unstamped: %v", err)
	}
	if unstamped != 0 {
		t.Fatalf("all revoke items must be stamped revoked_at after close, %d left unstamped", unstamped)
	}
}

// TestCloseCampaignCompletesTeardownAfterRequestCancel proves the post-commit
// revoke loop is detached from the request context: once the campaign is
// committed closed, cancelling the caller's context mid-loop must NOT abandon the
// remaining staged revokes. The revoker cancels the parent ctx during the first
// teardown; with the request ctx threaded straight through, the second revoke
// (and the revoked_at stamp) would observe the cancellation and abort, leaving a
// live grant behind a closed campaign. With context.WithoutCancel the loop runs
// to completion regardless.
func TestCloseCampaignCompletesTeardownAfterRequestCancel(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	g1 := seedGrant(t, db, ws, conn, "u1", "r1", "reader")
	g2 := seedGrant(t, db, ws, conn, "u2", "r2", "reader")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rev := newFakeRevoker(db)
	svc := NewCertificationService(db, rev)

	camp, _, _ := svc.StartCampaign(ctx, ws, CampaignInput{Name: "c"}, "auditor")
	items, _ := svc.ListItems(ctx, ws, camp.ID, "")
	for _, it := range items { // stage BOTH grants for revoke
		if err := svc.SubmitDecision(ctx, ws, camp.ID, it.ItemID, models.CertificationDecisionRevoke, "auditor", ""); err != nil {
			t.Fatalf("decision: %v", err)
		}
	}

	// Cancel the request context the moment the first teardown begins. If the
	// loop used the request ctx, everything after this point would fail.
	var once bool
	rev.beforeCall = func(uuid.UUID) {
		if !once {
			once = true
			cancel()
		}
	}

	report, err := svc.CloseCampaign(ctx, ws, camp.ID, "auditor")
	if err != nil {
		t.Fatalf("close must complete teardown despite request cancel, got: %v", err)
	}
	if report.State != models.CertificationStateClosed {
		t.Fatalf("expected closed, got %s", report.State)
	}
	// Both staged revokes must have been applied — the cancel did not strand the
	// second one.
	if rev.callCount(g1) != 1 || rev.callCount(g2) != 1 {
		t.Fatalf("both grants must be torn down despite cancel, got g1=%d g2=%d", rev.callCount(g1), rev.callCount(g2))
	}
	var unstamped int64
	if err := db.WithContext(context.Background()).Model(&models.CertificationItem{}).
		Where("workspace_id = ? AND campaign_id = ? AND decision = ? AND revoked_at IS NULL",
			ws, camp.ID, models.CertificationDecisionRevoke).
		Count(&unstamped).Error; err != nil {
		t.Fatalf("count unstamped: %v", err)
	}
	if unstamped != 0 {
		t.Fatalf("all revoke items must be stamped revoked_at after close, %d left unstamped", unstamped)
	}
}

// hangingRevoker blocks on the context until it is cancelled (or its deadline
// fires), then returns the context error — standing in for a connector that
// stops responding mid-teardown.
type hangingRevoker struct{ calls int }

func (h *hangingRevoker) RevokeGrant(ctx context.Context, _, _ uuid.UUID, _, _ string) error {
	h.calls++
	<-ctx.Done()
	return ctx.Err()
}

// TestCloseCampaignBoundsHungRevoke proves the post-commit teardown is bounded:
// because the loop runs request-detached (no ambient deadline), a connector that
// never returns must not hang the goroutine forever. With a per-revocation
// timeout the close aborts deterministically, leaving the item un-stamped so a
// convergent re-close (with a healthy revoker) finishes the teardown. Without
// the bound this test would block until the test binary's own timeout.
func TestCloseCampaignBoundsHungRevoke(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	g1 := seedGrant(t, db, ws, conn, "u1", "r1", "reader")
	ctx := context.Background()

	hung := &hangingRevoker{}
	svc := NewCertificationService(db, hung)
	svc.revokeTimeout = 50 * time.Millisecond // shrink so the test is fast

	camp, _, _ := svc.StartCampaign(ctx, ws, CampaignInput{Name: "c"}, "auditor")
	items, _ := svc.ListItems(ctx, ws, camp.ID, "")
	if err := svc.SubmitDecision(ctx, ws, camp.ID, items[0].ItemID, models.CertificationDecisionRevoke, "auditor", ""); err != nil {
		t.Fatalf("decision: %v", err)
	}

	_, err := svc.CloseCampaign(ctx, ws, camp.ID, "auditor")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close with hung revoker must abort with a deadline, got %v", err)
	}
	if hung.calls != 1 {
		t.Fatalf("expected the hung revoke to be attempted once, got %d", hung.calls)
	}

	// The campaign committed closed, but the hung revoke aborted before the
	// revoked_at stamp, so the item is still pending teardown.
	var unstamped int64
	if err := db.WithContext(ctx).Model(&models.CertificationItem{}).
		Where("workspace_id = ? AND campaign_id = ? AND decision = ? AND revoked_at IS NULL",
			ws, camp.ID, models.CertificationDecisionRevoke).
		Count(&unstamped).Error; err != nil {
		t.Fatalf("count unstamped: %v", err)
	}
	if unstamped != 1 {
		t.Fatalf("hung revoke must leave the item un-stamped for re-close, got %d unstamped", unstamped)
	}

	// A convergent re-close with a healthy revoker finishes the teardown.
	healthy := newFakeRevoker(db)
	if _, err := NewCertificationService(db, healthy).CloseCampaign(ctx, ws, camp.ID, "auditor"); err != nil {
		t.Fatalf("re-close must converge, got %v", err)
	}
	if healthy.callCount(g1) != 1 {
		t.Fatalf("re-close must apply the outstanding revoke once, got %d", healthy.callCount(g1))
	}
	if err := db.WithContext(ctx).Model(&models.CertificationItem{}).
		Where("workspace_id = ? AND campaign_id = ? AND decision = ? AND revoked_at IS NULL",
			ws, camp.ID, models.CertificationDecisionRevoke).
		Count(&unstamped).Error; err != nil {
		t.Fatalf("re-count unstamped: %v", err)
	}
	if unstamped != 0 {
		t.Fatalf("re-close must stamp the revoked item, %d left unstamped", unstamped)
	}
}

func TestCloseWithoutRevokerFailsClosed(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	seedGrant(t, db, ws, conn, "u1", "r1", "reader")
	ctx := context.Background()
	svc := NewCertificationService(db, nil) // no revoker

	camp, _, _ := svc.StartCampaign(ctx, ws, CampaignInput{Name: "c"}, "auditor")
	items, _ := svc.ListItems(ctx, ws, camp.ID, "")
	if err := svc.SubmitDecision(ctx, ws, camp.ID, items[0].ItemID, models.CertificationDecisionRevoke, "auditor", "stale"); err != nil {
		t.Fatalf("decision: %v", err)
	}
	if _, err := svc.CloseCampaign(ctx, ws, camp.ID, "auditor"); !errors.Is(err, ErrNoRevoker) {
		t.Fatalf("expected ErrNoRevoker, got %v", err)
	}
	// Campaign must remain running (not falsely closed).
	report, _ := svc.Report(ctx, ws, camp.ID)
	if report.State != models.CertificationStateRunning {
		t.Fatalf("campaign must stay running when close fails closed, got %s", report.State)
	}
}

func TestDecisionTerminalGuardAndIdempotency(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	seedGrant(t, db, ws, conn, "u1", "r1", "reader")
	ctx := context.Background()
	svc := NewCertificationService(db, newFakeRevoker(db))

	camp, _, _ := svc.StartCampaign(ctx, ws, CampaignInput{Name: "c"}, "auditor")
	items, _ := svc.ListItems(ctx, ws, camp.ID, "")
	id := items[0].ItemID

	if err := svc.SubmitDecision(ctx, ws, camp.ID, id, models.CertificationDecisionCertify, "a", "ok"); err != nil {
		t.Fatalf("certify: %v", err)
	}
	// Same decision again is idempotent (no new evidence row).
	if err := svc.SubmitDecision(ctx, ws, camp.ID, id, models.CertificationDecisionCertify, "a", "ok"); err != nil {
		t.Fatalf("idempotent re-certify: %v", err)
	}
	// Flipping to a different terminal decision is rejected.
	if err := svc.SubmitDecision(ctx, ws, camp.ID, id, models.CertificationDecisionRevoke, "a", "no"); !errors.Is(err, ErrItemDecided) {
		t.Fatalf("expected ErrItemDecided, got %v", err)
	}
	var dec int64
	db.Model(&models.AuditEvent{}).Where("workspace_id = ? AND action = ?", ws, "certification.item.decision.certify").Count(&dec)
	if dec != 1 {
		t.Fatalf("expected exactly 1 certify evidence event, got %d", dec)
	}
}

func TestDecisionOnClosedCampaignRejected(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	seedGrant(t, db, ws, conn, "u1", "r1", "reader")
	ctx := context.Background()
	svc := NewCertificationService(db, newFakeRevoker(db))

	camp, _, _ := svc.StartCampaign(ctx, ws, CampaignInput{Name: "c"}, "auditor")
	items, _ := svc.ListItems(ctx, ws, camp.ID, "")
	if _, err := svc.CloseCampaign(ctx, ws, camp.ID, "auditor"); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := svc.SubmitDecision(ctx, ws, camp.ID, items[0].ItemID, models.CertificationDecisionCertify, "a", ""); !errors.Is(err, ErrCampaignClosed) {
		t.Fatalf("expected ErrCampaignClosed, got %v", err)
	}
}

func TestEnforceOverdue(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	seedGrant(t, db, ws, conn, "u1", "r1", "reader")
	ctx := context.Background()
	svc := NewCertificationService(db, newFakeRevoker(db))

	past := time.Now().Add(-time.Hour)
	camp, _, err := svc.StartCampaign(ctx, ws, CampaignInput{Name: "c", DueAt: &past}, "auditor")
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	marked, err := svc.EnforceOverdue(ctx, ws)
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if marked != 1 {
		t.Fatalf("expected 1 overdue, got %d", marked)
	}
	// Idempotent: a second sweep marks nothing new.
	marked2, _ := svc.EnforceOverdue(ctx, ws)
	if marked2 != 0 {
		t.Fatalf("expected 0 on second sweep, got %d", marked2)
	}
	// Exactly one overdue evidence event.
	var ov int64
	db.Model(&models.AuditEvent{}).Where("workspace_id = ? AND action = ?", ws, "certification.campaign.overdue").Count(&ov)
	if ov != 1 {
		t.Fatalf("expected 1 overdue evidence event, got %d", ov)
	}
	// Report derives overdue=true.
	report, _ := svc.Report(ctx, ws, camp.ID)
	if !report.Overdue {
		t.Fatalf("expected report.Overdue true")
	}

	// Once all items decided, it is no longer overdue even past due.
	items, _ := svc.ListItems(ctx, ws, camp.ID, "")
	_ = svc.SubmitDecision(ctx, ws, camp.ID, items[0].ItemID, models.CertificationDecisionCertify, "a", "")
	report2, _ := svc.Report(ctx, ws, camp.ID)
	if report2.Overdue {
		t.Fatalf("fully-decided campaign must not be overdue")
	}
}

// TestEscalatedItemsAreNotTerminallyDecided locks the rule that escalation is an
// intermediate state, not a terminal decision: an all-escalated campaign must
// NOT report all-decided, MUST still be overdue past its due date, and MUST be
// stamped overdue by the sweep. Resolving the escalation to a terminal decision
// then clears both.
func TestEscalatedItemsAreNotTerminallyDecided(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	seedGrant(t, db, ws, conn, "u1", "r1", "reader")
	ctx := context.Background()
	svc := NewCertificationService(db, newFakeRevoker(db))

	past := time.Now().Add(-time.Hour)
	camp, _, err := svc.StartCampaign(ctx, ws, CampaignInput{Name: "c", DueAt: &past}, "auditor")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	items, _ := svc.ListItems(ctx, ws, camp.ID, "")
	if err := svc.SubmitDecision(ctx, ws, camp.ID, items[0].ItemID, models.CertificationDecisionEscalate, "a", "needs manager"); err != nil {
		t.Fatalf("escalate: %v", err)
	}

	report, _ := svc.Report(ctx, ws, camp.ID)
	if report.Escalated != 1 || report.Pending != 0 {
		t.Fatalf("expected 1 escalated / 0 pending, got %+v", report)
	}
	if report.AllDecided {
		t.Fatalf("all-escalated campaign must NOT be all-decided")
	}
	if !report.Overdue {
		t.Fatalf("past-due campaign with an escalated (non-terminal) item must be overdue")
	}

	// The sweep must stamp it overdue too (escalated counts as open).
	marked, err := svc.EnforceOverdue(ctx, ws)
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if marked != 1 {
		t.Fatalf("expected sweep to mark 1 all-escalated campaign overdue, got %d", marked)
	}

	// Resolving the escalation to a terminal decision clears both signals.
	if err := svc.SubmitDecision(ctx, ws, camp.ID, items[0].ItemID, models.CertificationDecisionCertify, "a", "approved"); err != nil {
		t.Fatalf("certify after escalate: %v", err)
	}
	report2, _ := svc.Report(ctx, ws, camp.ID)
	if !report2.AllDecided {
		t.Fatalf("expected all-decided after terminal decision, got %+v", report2)
	}
	if report2.Overdue {
		t.Fatalf("terminally-decided campaign must not be overdue")
	}
}

func TestCampaignCrossTenantIsolation(t *testing.T) {
	db := newTestDB(t)
	wsA := seedWorkspace(t, db, "tenant-a")
	wsB := seedWorkspace(t, db, "tenant-b")
	conn := seedConnector(t, db, wsA, "fake")
	seedGrant(t, db, wsA, conn, "u1", "r1", "reader")
	ctx := context.Background()
	svc := NewCertificationService(db, newFakeRevoker(db))

	camp, _, _ := svc.StartCampaign(ctx, wsA, CampaignInput{Name: "c"}, "auditor")

	// Tenant B cannot see or act on tenant A's campaign.
	if _, err := svc.Report(ctx, wsB, camp.ID); !errors.Is(err, ErrCampaignNotFound) {
		t.Fatalf("expected ErrCampaignNotFound cross-tenant, got %v", err)
	}
	if _, err := svc.ListItems(ctx, wsB, camp.ID, ""); !errors.Is(err, ErrCampaignNotFound) {
		t.Fatalf("expected ErrCampaignNotFound cross-tenant items, got %v", err)
	}
	if err := svc.SubmitDecision(ctx, wsB, camp.ID, uuid.New(), models.CertificationDecisionCertify, "b", ""); !errors.Is(err, ErrCampaignNotFound) {
		t.Fatalf("expected ErrCampaignNotFound cross-tenant decision, got %v", err)
	}
}
