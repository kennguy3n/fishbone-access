package compliance

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// chainHead returns the (seq, hash) of the current head of a workspace chain,
// the trusted baseline a caller persists after a full verify and replays into
// VerifyChainSince on the next load.
func chainHead(t *testing.T, db *gorm.DB, ws uuid.UUID) (int64, string) {
	t.Helper()
	var head models.AuditEvent
	if err := db.Where("workspace_id = ?", ws).Order("chain_seq desc").Limit(1).
		Take(&head).Error; err != nil {
		t.Fatalf("read chain head: %v", err)
	}
	return head.ChainSeq, head.ChainHash
}

func TestStreamClassifiesAndFilters(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	ctx := context.Background()

	appendEvent(t, db, ws, "access_grant.created", "g1")
	appendEvent(t, db, ws, "policy.promoted", "p1")
	appendEvent(t, db, ws, "weird.unmapped.action", "x1") // -> KindOther
	appendEvent(t, db, ws, "access_grant.revoked", "g1")

	svc := NewEvidenceService(db)

	all, err := svc.Stream(ctx, ws, EvidenceFilter{})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("expected 4 records, got %d", len(all))
	}
	// Chain order (oldest first).
	if all[0].Action != "access_grant.created" || all[3].Action != "access_grant.revoked" {
		t.Fatalf("unexpected chain order: %+v", all)
	}
	if all[0].Kind != KindAccessGranted || all[1].Kind != KindPolicyPromoted {
		t.Fatalf("classification wrong: %s %s", all[0].Kind, all[1].Kind)
	}
	if all[2].Kind != KindOther {
		t.Fatalf("expected unmapped action -> KindOther, got %s", all[2].Kind)
	}

	// ControlledOnly drops the KindOther row.
	ctrl, err := svc.Stream(ctx, ws, EvidenceFilter{ControlledOnly: true})
	if err != nil {
		t.Fatalf("Stream controlled: %v", err)
	}
	if len(ctrl) != 3 {
		t.Fatalf("expected 3 controlled records, got %d", len(ctrl))
	}

	// Kind filter.
	onlyGrants, err := svc.Stream(ctx, ws, EvidenceFilter{Kinds: []EvidenceKind{KindAccessGranted, KindAccessRevoked}})
	if err != nil {
		t.Fatalf("Stream kinds: %v", err)
	}
	if len(onlyGrants) != 2 {
		t.Fatalf("expected 2 grant records, got %d", len(onlyGrants))
	}

	// Limit caps the result.
	limited, err := svc.Stream(ctx, ws, EvidenceFilter{Limit: 2})
	if err != nil {
		t.Fatalf("Stream limit: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("expected 2 limited records, got %d", len(limited))
	}
	// Ascending limit returns the OLDEST N (the start of the chain).
	if limited[0].Action != "access_grant.created" {
		t.Fatalf("ascending limit should start at oldest, got %s", limited[0].Action)
	}

	// Newest=true flips to descending chain order so a bounded read returns the
	// most-recent N events (the dashboard timeline contract), newest first.
	newest, err := svc.Stream(ctx, ws, EvidenceFilter{Limit: 2, Newest: true})
	if err != nil {
		t.Fatalf("Stream newest: %v", err)
	}
	if len(newest) != 2 {
		t.Fatalf("expected 2 newest records, got %d", len(newest))
	}
	if newest[0].Action != "access_grant.revoked" || newest[1].Action != "weird.unmapped.action" {
		t.Fatalf("newest-first limit should return the latest events, got %s,%s", newest[0].Action, newest[1].Action)
	}
	if newest[0].ChainSeq <= newest[1].ChainSeq {
		t.Fatalf("newest order must be descending by chain_seq, got %d then %d", newest[0].ChainSeq, newest[1].ChainSeq)
	}
}

func TestVerifyChainValidThenTamperDetected(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		appendEvent(t, db, ws, "policy.promoted", "p")
	}

	svc := NewEvidenceService(db)
	v, err := svc.VerifyChain(ctx, ws)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !v.OK || v.Status != chainStatusValid || v.Length != 5 {
		t.Fatalf("expected valid chain of 5, got %+v", v)
	}

	// Tamper: edit a hashed field (action) on the 3rd row WITHOUT recomputing
	// its chain_hash. The row still links by prev_hash, so only the recompute
	// check can catch it.
	var third models.AuditEvent
	if err := db.Where("workspace_id = ? AND chain_seq = ?", ws, int64(3)).Take(&third).Error; err != nil {
		t.Fatalf("load 3rd row: %v", err)
	}
	if err := db.Model(&models.AuditEvent{}).Where("id = ?", third.ID).
		Update("action", "policy.archived").Error; err != nil {
		t.Fatalf("tamper: %v", err)
	}

	v2, err := svc.VerifyChain(ctx, ws)
	if err != nil {
		t.Fatalf("VerifyChain after tamper: %v", err)
	}
	if v2.OK || v2.Status != chainStatusTampered {
		t.Fatalf("expected tampered, got %+v", v2)
	}
	if v2.BrokenAtSeq != 3 {
		t.Fatalf("expected break at seq 3, got %d", v2.BrokenAtSeq)
	}
}

func TestVerifyChainEmpty(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v, err := NewEvidenceService(db).VerifyChain(context.Background(), ws)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if v.OK || v.Status != chainStatusEmpty {
		t.Fatalf("expected empty, got %+v", v)
	}
}

func TestVerifyChainDetectsDeletedRow(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	for i := 0; i < 4; i++ {
		appendEvent(t, db, ws, "policy.promoted", "p")
	}
	// Hard-delete the 2nd row, creating a chain_seq gap (2 missing). Use Unscoped
	// so it is truly gone, not soft-deleted.
	if err := db.Unscoped().Where("workspace_id = ? AND chain_seq = ?", ws, int64(2)).
		Delete(&models.AuditEvent{}).Error; err != nil {
		t.Fatalf("delete row: %v", err)
	}
	v, err := NewEvidenceService(db).VerifyChain(context.Background(), ws)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if v.OK || v.Status != chainStatusTampered {
		t.Fatalf("expected tampered after deletion, got %+v", v)
	}
}

// TestVerifyChainDetectsSoftDeletedRow locks in the deliberate scope divergence
// between the appender and the verifier. The appender reads the chain head with
// Unscoped() so a soft-deleted row can never be silently skipped and forked off
// (see lifecycle.appendAudit). The verifier intentionally does NOT use
// Unscoped(): a soft-deleted audit row is an anomaly (audit events are immutable
// and must never be deleted), and the SCOPED read surfaces the resulting
// chain_seq gap as "tampered". Using Unscoped() in the verifier would instead
// re-link over the soft-deleted row and report "valid", BLINDING the tamper
// check to deletion — the weaker posture. This test guarantees the stronger one.
func TestVerifyChainDetectsSoftDeletedRow(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	for i := 0; i < 4; i++ {
		appendEvent(t, db, ws, "policy.promoted", "p")
	}
	// SOFT-delete the 2nd row (scoped Delete sets deleted_at; the row physically
	// remains). The scoped verifier must still surface the chain_seq gap.
	if err := db.Where("workspace_id = ? AND chain_seq = ?", ws, int64(2)).
		Delete(&models.AuditEvent{}).Error; err != nil {
		t.Fatalf("soft delete row: %v", err)
	}
	v, err := NewEvidenceService(db).VerifyChain(context.Background(), ws)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if v.OK || v.Status != chainStatusTampered {
		t.Fatalf("expected tampered after soft-deletion, got %+v", v)
	}
}

func TestCoverageByFramework(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	ctx := context.Background()

	// Evidence that should credit several SOC 2 controls.
	appendEvent(t, db, ws, "policy.promoted", "p1")      // CC6.1
	appendEvent(t, db, ws, "access_grant.created", "g1") // CC6.1, CC6.2
	appendEvent(t, db, ws, "access_grant.revoked", "g1") // CC6.3
	appendEvent(t, db, ws, "weird.action", "x")          // KindOther — credits nothing

	svc := NewEvidenceService(db)
	cov, err := svc.Coverage(ctx, ws, FrameworkSOC2, nil, nil)
	if err != nil {
		t.Fatalf("Coverage: %v", err)
	}
	if cov.Framework != FrameworkSOC2 {
		t.Fatalf("wrong framework: %s", cov.Framework)
	}
	if cov.ControlsCovered == 0 || cov.ControlsCovered > cov.ControlsTotal {
		t.Fatalf("unexpected coverage tally: %+v", cov)
	}
	// EvidenceTotal counts only controlled kinds (the weird.action is excluded).
	if cov.EvidenceTotal != 3 {
		t.Fatalf("expected 3 controlled evidence records, got %d", cov.EvidenceTotal)
	}

	// Find CC6.1 and assert it is covered with the right kinds.
	var cc61 *ControlCoverage
	for i := range cov.Controls {
		if cov.Controls[i].ID == "CC6.1" {
			cc61 = &cov.Controls[i]
		}
	}
	if cc61 == nil || !cc61.Covered {
		t.Fatalf("expected CC6.1 covered, got %+v", cc61)
	}
}

func TestCoverageUnknownFramework(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	_, err := NewEvidenceService(db).Coverage(context.Background(), ws, Framework("HIPAA"), nil, nil)
	if err == nil {
		t.Fatal("expected error for unknown framework")
	}
}

func TestEvidenceCrossTenantIsolation(t *testing.T) {
	db := newTestDB(t)
	wsA := seedWorkspace(t, db, "tenant-a")
	wsB := seedWorkspace(t, db, "tenant-b")
	ctx := context.Background()

	appendEvent(t, db, wsA, "policy.promoted", "pa")
	appendEvent(t, db, wsA, "access_grant.created", "ga")
	appendEvent(t, db, wsB, "policy.promoted", "pb")

	svc := NewEvidenceService(db)
	a, _ := svc.Stream(ctx, wsA, EvidenceFilter{})
	b, _ := svc.Stream(ctx, wsB, EvidenceFilter{})
	if len(a) != 2 || len(b) != 1 {
		t.Fatalf("cross-tenant leak: a=%d b=%d", len(a), len(b))
	}
	// Each workspace's chain verifies independently.
	if v, _ := svc.VerifyChain(ctx, wsA); !v.OK {
		t.Fatalf("ws A chain should be valid: %+v", v)
	}
	if v, _ := svc.VerifyChain(ctx, wsB); !v.OK {
		t.Fatalf("ws B chain should be valid: %+v", v)
	}
}

// TestVerifyChainSinceIncrementalConsistent is the headline case: a caller
// holds a trusted baseline from an earlier full verify, the chain grows, and
// the incremental verify scans only the new rows and reports the new head.
func TestVerifyChainSinceIncrementalConsistent(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	ctx := context.Background()
	svc := NewEvidenceService(db)

	for i := 0; i < 5; i++ {
		appendEvent(t, db, ws, "policy.promoted", "p")
	}
	full, err := svc.VerifyChain(ctx, ws)
	if err != nil || !full.OK || full.Length != 5 {
		t.Fatalf("baseline full verify: %+v err=%v", full, err)
	}
	anchorSeq, anchorHash := chainHead(t, db, ws)

	// Chain grows by two rows after the baseline.
	appendEvent(t, db, ws, "access_grant.created", "g")
	appendEvent(t, db, ws, "access_grant.created", "g")

	cons, err := svc.VerifyChainSince(ctx, ws, anchorSeq, anchorHash)
	if err != nil {
		t.Fatalf("VerifyChainSince: %v", err)
	}
	if !cons.OK || cons.Status != chainStatusConsistent {
		t.Fatalf("expected consistent, got %+v", cons)
	}
	if cons.Verified != 2 {
		t.Fatalf("expected 2 new rows verified, got %d", cons.Verified)
	}
	wantSeq, wantHash := chainHead(t, db, ws)
	if cons.HeadSeq != wantSeq || cons.HeadHash != wantHash {
		t.Fatalf("head mismatch: got (%d,%s) want (%d,%s)", cons.HeadSeq, cons.HeadHash, wantSeq, wantHash)
	}

	// Replaying the now-current head must be a no-op consistent verify.
	again, err := svc.VerifyChainSince(ctx, ws, cons.HeadSeq, cons.HeadHash)
	if err != nil {
		t.Fatalf("VerifyChainSince (no new rows): %v", err)
	}
	if !again.OK || again.Verified != 0 || again.HeadSeq != wantSeq {
		t.Fatalf("expected consistent no-op, got %+v", again)
	}
}

// TestVerifyChainSinceDetectsSuffixTamper proves the incremental scan is as
// strict as a full scan over the rows it covers: editing a row after the anchor
// without recomputing its hash is caught.
func TestVerifyChainSinceDetectsSuffixTamper(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	ctx := context.Background()
	svc := NewEvidenceService(db)

	for i := 0; i < 3; i++ {
		appendEvent(t, db, ws, "policy.promoted", "p")
	}
	anchorSeq, anchorHash := chainHead(t, db, ws)
	for i := 0; i < 3; i++ {
		appendEvent(t, db, ws, "access_grant.created", "g")
	}

	// Tamper a hashed field on a row in the SUFFIX (seq 5) without recomputing.
	if err := db.Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND chain_seq = ?", ws, int64(5)).
		Update("action", "access_grant.revoked").Error; err != nil {
		t.Fatalf("tamper: %v", err)
	}

	cons, err := svc.VerifyChainSince(ctx, ws, anchorSeq, anchorHash)
	if err != nil {
		t.Fatalf("VerifyChainSince: %v", err)
	}
	if cons.OK || cons.Status != chainStatusTampered {
		t.Fatalf("expected tampered, got %+v", cons)
	}
	if cons.BrokenAtSeq != 5 {
		t.Fatalf("expected break at seq 5, got %d", cons.BrokenAtSeq)
	}
}

// TestVerifyChainSinceWrongAnchorHash proves a baseline whose hash does not
// match the real chain head cannot pass: the first suffix row's prev_hash will
// not link to the asserted anchor.
func TestVerifyChainSinceWrongAnchorHash(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	ctx := context.Background()
	svc := NewEvidenceService(db)

	for i := 0; i < 4; i++ {
		appendEvent(t, db, ws, "policy.promoted", "p")
	}
	anchorSeq, _ := chainHead(t, db, ws)
	appendEvent(t, db, ws, "access_grant.created", "g")

	cons, err := svc.VerifyChainSince(ctx, ws, anchorSeq, "deadbeefnotarealhash")
	if err != nil {
		t.Fatalf("VerifyChainSince: %v", err)
	}
	if cons.OK || cons.Status != chainStatusTampered {
		t.Fatalf("expected tampered on bad anchor link, got %+v", cons)
	}
}

// TestVerifyChainSinceStaleAnchor proves an anchor seq ahead of the chain head
// is reported as a stale anchor rather than masquerading as "consistent, 0 new
// rows".
func TestVerifyChainSinceStaleAnchor(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	ctx := context.Background()
	svc := NewEvidenceService(db)

	for i := 0; i < 3; i++ {
		appendEvent(t, db, ws, "policy.promoted", "p")
	}
	cons, err := svc.VerifyChainSince(ctx, ws, 99, "anyhash")
	if err != nil {
		t.Fatalf("VerifyChainSince: %v", err)
	}
	if cons.OK || cons.Status != chainStatusStaleAnchor {
		t.Fatalf("expected stale_anchor, got %+v", cons)
	}
	if cons.HeadSeq != 3 {
		t.Fatalf("expected reported head 3, got %d", cons.HeadSeq)
	}
}

// TestVerifyChainSinceValidation rejects a non-zero anchor seq with no hash:
// there is nothing for the first suffix row to link onto.
func TestVerifyChainSinceValidation(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	if _, err := NewEvidenceService(db).VerifyChainSince(context.Background(), ws, 3, ""); err == nil {
		t.Fatal("expected validation error for from_seq>0 with empty from_hash")
	}
}
