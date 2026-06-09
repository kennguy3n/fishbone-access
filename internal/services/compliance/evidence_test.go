package compliance

import (
	"context"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

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

func TestCoverageByFramework(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	ctx := context.Background()

	// Evidence that should credit several SOC 2 controls.
	appendEvent(t, db, ws, "policy.promoted", "p1")   // CC6.1
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

