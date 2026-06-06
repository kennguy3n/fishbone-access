package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// approveAndConnector creates a request with a connector and approves it,
// returning the request id ready to provision.
func approveAndConnector(t *testing.T, reqSvc *AccessRequestService, ws, connID uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	r, err := reqSvc.CreateRequest(ctx, CreateAccessRequestInput{
		WorkspaceID: ws, RequesterID: "u", TargetUserID: "ext-u", ConnectorID: &connID,
		ResourceRef: "app:db", Role: "reader",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := reqSvc.ApproveRequest(ctx, ws, r.ID, "mgr", "ok"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	return r.ID
}

func TestProvisionSuccessCreatesGrantAndActivates(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{}
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(3, func(int) time.Duration { return 0 })
	ctx := context.Background()

	reqID := approveAndConnector(t, reqSvc, ws, connID)
	grant, err := prov.Provision(ctx, ws, reqID, "system")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if grant.State != GrantStateActive {
		t.Fatalf("expected active grant, got %s", grant.State)
	}
	got, _ := reqSvc.GetRequest(ctx, ws, reqID)
	if got.State != StateActive {
		t.Fatalf("expected request active, got %s", got.State)
	}
	if fc.provisionCnt != 1 {
		t.Fatalf("expected 1 provision call, got %d", fc.provisionCnt)
	}

	// History should include provisioning, provisioned, active.
	hist, _ := reqSvc.History(ctx, ws, reqID)
	var sawProvisioning, sawProvisioned, sawActive bool
	for _, h := range hist {
		switch RequestState(h.ToState) {
		case StateProvisioning:
			sawProvisioning = true
		case StateProvisioned:
			sawProvisioned = true
		case StateActive:
			sawActive = true
		}
	}
	if !sawProvisioning || !sawProvisioned || !sawActive {
		t.Fatalf("missing lifecycle history rows: %+v", hist)
	}
}

func TestProvisionRetriesThenSucceeds(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{failNProvision: 2} // fail twice, succeed on 3rd
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(3, func(int) time.Duration { return 0 })
	ctx := context.Background()

	reqID := approveAndConnector(t, reqSvc, ws, connID)
	if _, err := prov.Provision(ctx, ws, reqID, "system"); err != nil {
		t.Fatalf("Provision (with retries): %v", err)
	}
	if fc.provisionCnt != 3 {
		t.Fatalf("expected 3 provision attempts, got %d", fc.provisionCnt)
	}
}

func TestProvisionFailsThenRetryPath(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{failNProvision: 99} // always fail
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(2, func(int) time.Duration { return 0 })
	ctx := context.Background()

	reqID := approveAndConnector(t, reqSvc, ws, connID)
	if _, err := prov.Provision(ctx, ws, reqID, "system"); err == nil {
		t.Fatal("expected provision failure")
	}
	got, _ := reqSvc.GetRequest(ctx, ws, reqID)
	if got.State != StateProvisionFailed {
		t.Fatalf("expected provision_failed, got %s", got.State)
	}

	// Retry path: now make it succeed.
	fc.failNProvision = 0
	if _, err := prov.Provision(ctx, ws, reqID, "system"); err != nil {
		t.Fatalf("retry Provision: %v", err)
	}
	got, _ = reqSvc.GetRequest(ctx, ws, reqID)
	if got.State != StateActive {
		t.Fatalf("expected active after retry, got %s", got.State)
	}
}

// TestProvisionIsIdempotentWhenGrantAlreadyExists proves the crash/retry guard:
// if a live grant already exists for a request (e.g. a prior attempt that
// committed, or a concurrent provision), a subsequent Provision reuses it
// instead of inserting a duplicate access_grants row.
func TestProvisionIsIdempotentWhenGrantAlreadyExists(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{}
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })
	ctx := context.Background()

	reqID := approveAndConnector(t, reqSvc, ws, connID)
	first, err := prov.Provision(ctx, ws, reqID, "system")
	if err != nil {
		t.Fatalf("first Provision: %v", err)
	}

	// Simulate crash-recovery: force the request back to provisioning while the
	// grant from the first attempt is still live. A second Provision must NOT
	// create a second grant.
	if err := db.Model(&models.AccessRequest{}).
		Where("workspace_id = ? AND id = ?", ws, reqID).
		Update("state", string(StateProvisioning)).Error; err != nil {
		t.Fatalf("force provisioning: %v", err)
	}

	second, err := prov.Provision(ctx, ws, reqID, "system")
	if err != nil {
		t.Fatalf("second Provision: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("expected reused grant %s, got new grant %s", first.ID, second.ID)
	}
	var count int64
	if err := db.Model(&models.AccessGrant{}).
		Where("workspace_id = ? AND request_id = ?", ws, reqID).
		Count(&count).Error; err != nil {
		t.Fatalf("count grants: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 grant for request, got %d (duplicate grant created)", count)
	}
}

func TestRevokeGrantIdempotent(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{}
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })
	ctx := context.Background()

	reqID := approveAndConnector(t, reqSvc, ws, connID)
	grant, _ := prov.Provision(ctx, ws, reqID, "system")

	if err := prov.RevokeGrant(ctx, ws, grant.ID, "admin", "no longer needed"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	// Second revoke is a no-op (idempotent) — no extra connector call.
	if err := prov.RevokeGrant(ctx, ws, grant.ID, "admin", "again"); err != nil {
		t.Fatalf("RevokeGrant idempotent: %v", err)
	}
	if fc.revokeCnt != 1 {
		t.Fatalf("expected exactly 1 revoke connector call, got %d", fc.revokeCnt)
	}
	got, _ := reqSvc.GetRequest(ctx, ws, reqID)
	if got.State != StateRevoked {
		t.Fatalf("expected request revoked, got %s", got.State)
	}
}

func TestPolicyDraftSimulatePromoteIdempotent(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	svc := NewPolicyService(db)
	ctx := context.Background()

	def := mustJSON(t, PolicyDefinition{Action: "grant", Subjects: []string{"u1", "u2"}, Resources: []string{"app:db"}, Role: "reader"})
	pol, err := svc.CreatePolicy(ctx, CreatePolicyInput{WorkspaceID: ws, Name: "p1", Definition: def, Actor: "admin"})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if pol.State != PolicyStateDraft {
		t.Fatalf("expected draft, got %s", pol.State)
	}

	sim, err := svc.Simulate(ctx, ws, pol.ID)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if sim.Impact.NewGrantPairs != 2 {
		t.Fatalf("expected 2 new grant pairs, got %d", sim.Impact.NewGrantPairs)
	}
	// Draft impact cached.
	reloaded, _ := svc.GetPolicy(ctx, ws, pol.ID)
	if len(reloaded.DraftImpact) == 0 {
		t.Fatal("expected DraftImpact cached after simulate")
	}

	p2, err := svc.Promote(ctx, ws, pol.ID, "admin")
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if p2.State != PolicyStateActive || p2.PromotedAt == nil {
		t.Fatalf("expected active+promoted, got %s %v", p2.State, p2.PromotedAt)
	}
	firstPromoted := *p2.PromotedAt

	// Idempotent: promoting again returns unchanged (same PromotedAt).
	p3, err := svc.Promote(ctx, ws, pol.ID, "admin")
	if err != nil {
		t.Fatalf("Promote idempotent: %v", err)
	}
	if !p3.PromotedAt.Equal(firstPromoted) {
		t.Fatalf("idempotent promote restamped PromotedAt: %v != %v", p3.PromotedAt, firstPromoted)
	}
}

// TestUpdateDraftOnNonDraftReturnsNotEditable proves editing a promoted policy
// returns the dedicated ErrPolicyNotEditable sentinel (not ErrPolicyNotPromotable),
// so the client gets an accurate "not editable" message rather than a confusing
// "cannot be promoted" one.
func TestUpdateDraftOnNonDraftReturnsNotEditable(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	svc := NewPolicyService(db)
	ctx := context.Background()

	def := mustJSON(t, PolicyDefinition{Action: "grant", Subjects: []string{"u1"}, Resources: []string{"app:db"}, Role: "reader"})
	pol, err := svc.CreatePolicy(ctx, CreatePolicyInput{WorkspaceID: ws, Name: "p1", Definition: def, Actor: "admin"})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if _, err := svc.Promote(ctx, ws, pol.ID, "admin"); err != nil {
		t.Fatalf("Promote: %v", err)
	}

	_, err = svc.UpdateDraft(ctx, ws, pol.ID, "p1", def, "admin")
	if !errors.Is(err, ErrPolicyNotEditable) {
		t.Fatalf("expected ErrPolicyNotEditable editing a promoted policy, got %v", err)
	}
	if errors.Is(err, ErrPolicyNotPromotable) {
		t.Fatalf("editing error must not be the promotion sentinel: %v", err)
	}
}

func TestPolicyDraftNeverTouchesDataPlane(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	svc := NewPolicyService(db)
	ctx := context.Background()

	def := mustJSON(t, PolicyDefinition{Action: "grant", Subjects: []string{"u1"}, Resources: []string{"app:db"}, Role: "reader"})
	pol, _ := svc.CreatePolicy(ctx, CreatePolicyInput{WorkspaceID: ws, Name: "p1", Definition: def, Actor: "admin"})
	if _, err := svc.Simulate(ctx, ws, pol.ID); err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	// No grants should exist from a draft+simulate.
	var grants int64
	db.Model(&models.AccessGrant{}).Where("workspace_id = ?", ws).Count(&grants)
	if grants != 0 {
		t.Fatalf("draft/simulate created %d grants — must touch nothing", grants)
	}
}

func TestConflictDetectorGrantVsDeny(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	svc := NewPolicyService(db)
	ctx := context.Background()

	// Active deny policy on (u1, app:db).
	denyDef := mustJSON(t, PolicyDefinition{Action: "deny", Subjects: []string{"u1"}, Resources: []string{"app:db"}})
	deny, _ := svc.CreatePolicy(ctx, CreatePolicyInput{WorkspaceID: ws, Name: "deny", Definition: denyDef, Actor: "admin"})
	if _, err := svc.Promote(ctx, ws, deny.ID, "admin"); err != nil {
		t.Fatalf("promote deny: %v", err)
	}

	// New grant draft over the same pair.
	grantDef := mustJSON(t, PolicyDefinition{Action: "grant", Subjects: []string{"u1"}, Resources: []string{"app:db"}, Role: "admin"})
	grant, _ := svc.CreatePolicy(ctx, CreatePolicyInput{WorkspaceID: ws, Name: "grant", Definition: grantDef, Actor: "admin"})

	sim, err := svc.Simulate(ctx, ws, grant.ID)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if len(sim.Conflicts) != 1 || sim.Conflicts[0].Kind != ConflictGrantVsDeny {
		t.Fatalf("expected 1 grant_vs_deny conflict, got %+v", sim.Conflicts)
	}
}

func TestImpactReportWildcardPairCountConsistent(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	r := NewImpactResolver(db)
	ctx := context.Background()

	// A wildcard resource cannot be enumerated into concrete pairs. PairCount
	// must therefore exclude it (counting only concrete resources) so the
	// invariant PairCount == NewGrantPairs + RedundantPairs still holds, and
	// WildcardResource must flag that a "*" was present.
	def := PolicyDefinition{Action: PolicyActionGrant, Subjects: []string{"u1", "u2"}, Resources: []string{"app:db", "*"}, Role: "reader"}
	rep, err := r.ResolveImpact(ctx, ws, def)
	if err != nil {
		t.Fatalf("ResolveImpact: %v", err)
	}
	if !rep.WildcardResource {
		t.Fatal("expected WildcardResource=true when resources include \"*\"")
	}
	// 2 subjects × 1 concrete resource ("app:db"); "*" excluded.
	if rep.PairCount != 2 {
		t.Fatalf("expected pair_count 2 (wildcard excluded), got %d", rep.PairCount)
	}
	if rep.PairCount != rep.NewGrantPairs+rep.RedundantPairs {
		t.Fatalf("pair_count %d != new %d + redundant %d", rep.PairCount, rep.NewGrantPairs, rep.RedundantPairs)
	}
}

func TestReviewCampaignCertifyAndRevoke(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{}
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })
	review := NewReviewService(db, prov)
	ctx := context.Background()

	// Two active grants.
	g1 := mustProvision(t, reqSvc, prov, ws, connID, "ext-1")
	g2 := mustProvision(t, reqSvc, prov, ws, connID, "ext-2")

	rev, n, err := review.StartCampaign(ctx, ws, "Q1 review", "auditor")
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 review items, got %d", n)
	}

	items, _ := review.ListItems(ctx, ws, rev.ID)
	var itemForG1, itemForG2 uuid.UUID
	for _, it := range items {
		switch it.GrantID {
		case g1.ID:
			itemForG1 = it.ID
		case g2.ID:
			itemForG2 = it.ID
		}
	}

	if err := review.SubmitDecision(ctx, ws, rev.ID, itemForG1, ReviewDecisionCertify, "auditor", "ok"); err != nil {
		t.Fatalf("certify: %v", err)
	}
	if err := review.SubmitDecision(ctx, ws, rev.ID, itemForG2, ReviewDecisionRevoke, "auditor", "stale"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// g2 should now be revoked.
	var g2reload models.AccessGrant
	db.Where("id = ?", g2.ID).Take(&g2reload)
	if g2reload.State != GrantStateRevoked {
		t.Fatalf("expected g2 revoked by review, got %s", g2reload.State)
	}

	report, err := review.CompleteCampaign(ctx, ws, rev.ID, "auditor")
	if err != nil {
		t.Fatalf("CompleteCampaign: %v", err)
	}
	if report.Certified != 1 || report.Revoked != 1 || report.State != ReviewStateCompleted {
		t.Fatalf("unexpected report: %+v", report)
	}
}

// TestReviewItemTerminalDecisionCannotBeOverwritten proves a finalized
// certify/revoke decision cannot be flipped (which would mark a torn-down grant
// as certified, or vice versa), while an escalated item can still be resolved.
func TestReviewItemTerminalDecisionCannotBeOverwritten(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{}
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })
	review := NewReviewService(db, prov)
	ctx := context.Background()

	g1 := mustProvision(t, reqSvc, prov, ws, connID, "ext-1")
	g2 := mustProvision(t, reqSvc, prov, ws, connID, "ext-2")
	rev, _, err := review.StartCampaign(ctx, ws, "Q1", "auditor")
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	items, _ := review.ListItems(ctx, ws, rev.ID)
	var revokeItem, escalateItem uuid.UUID
	for _, it := range items {
		switch it.GrantID {
		case g1.ID:
			revokeItem = it.ID
		case g2.ID:
			escalateItem = it.ID
		}
	}

	// Revoke is terminal: a follow-up certify must be rejected, and the grant
	// must stay revoked.
	if err := review.SubmitDecision(ctx, ws, rev.ID, revokeItem, ReviewDecisionRevoke, "auditor", "stale"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := review.SubmitDecision(ctx, ws, rev.ID, revokeItem, ReviewDecisionCertify, "auditor", "oops"); !errors.Is(err, ErrReviewItemDecided) {
		t.Fatalf("expected ErrReviewItemDecided overwriting a revoke, got %v", err)
	}
	var g1reload models.AccessGrant
	db.Where("id = ?", g1.ID).Take(&g1reload)
	if g1reload.State != GrantStateRevoked {
		t.Fatalf("revoked grant must stay revoked, got %s", g1reload.State)
	}

	// Escalate is NOT terminal: it can be resolved to a final decision.
	if err := review.SubmitDecision(ctx, ws, rev.ID, escalateItem, ReviewDecisionEscalate, "auditor", "needs mgr"); err != nil {
		t.Fatalf("escalate: %v", err)
	}
	if err := review.SubmitDecision(ctx, ws, rev.ID, escalateItem, ReviewDecisionCertify, "manager", "approved"); err != nil {
		t.Fatalf("resolving an escalation must be allowed, got %v", err)
	}
}

// TestSubmitDecisionConcurrentDecisionsStayConsistent fires many concurrent
// decisions (a revoke racing several certifies) at the same review item and
// asserts the committed decision and the grant state never disagree: the
// terminal-decision guard now runs inside the FOR-UPDATE transaction, so the
// first decision to commit wins and every differing decision is rejected —
// a revoked grant can never end up marked "certified" (the TOCTOU the guard is
// meant to prevent).
func TestSubmitDecisionConcurrentDecisionsStayConsistent(t *testing.T) {
	db := newTestDB(t)
	// A shared in-memory SQLite database is per-connection, so pin the pool to a
	// single connection: every goroutine then sees the same schema/data and
	// writes serialize on SQLite's global write lock (the no-op stand-in for the
	// Postgres FOR UPDATE row lock this test is really about).
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{}
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })
	review := NewReviewService(db, prov)
	ctx := context.Background()

	g := mustProvision(t, reqSvc, prov, ws, connID, "ext-race")
	rev, _, err := review.StartCampaign(ctx, ws, "Q1", "auditor")
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	items, _ := review.ListItems(ctx, ws, rev.ID)
	if len(items) != 1 {
		t.Fatalf("expected 1 review item, got %d", len(items))
	}
	itemID := items[0].ID

	const n = 8
	decisions := make([]string, n)
	for i := range decisions {
		if i == 0 {
			decisions[i] = ReviewDecisionRevoke
		} else {
			decisions[i] = ReviewDecisionCertify
		}
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, d := range decisions {
		wg.Add(1)
		go func(decision string) {
			defer wg.Done()
			<-start
			// Errors (ErrReviewItemDecided for losers) are expected; we only
			// assert on the final persisted state below.
			_ = review.SubmitDecision(ctx, ws, rev.ID, itemID, decision, "auditor", "race")
		}(d)
	}
	close(start)
	wg.Wait()

	var finalItem models.AccessReviewItem
	if err := db.Where("id = ?", itemID).Take(&finalItem).Error; err != nil {
		t.Fatalf("reload item: %v", err)
	}
	var finalGrant models.AccessGrant
	if err := db.Where("id = ?", g.ID).Take(&finalGrant).Error; err != nil {
		t.Fatalf("reload grant: %v", err)
	}
	// Invariant: the recorded decision and the grant state must agree.
	revokedDecision := finalItem.Decision == ReviewDecisionRevoke
	revokedGrant := finalGrant.State == GrantStateRevoked
	if revokedDecision != revokedGrant {
		t.Fatalf("inconsistent: item.Decision=%q grant.State=%q", finalItem.Decision, finalGrant.State)
	}
	if finalItem.Decision != ReviewDecisionRevoke && finalItem.Decision != ReviewDecisionCertify {
		t.Fatalf("final decision must be terminal, got %q", finalItem.Decision)
	}
}

// TestHistoryUnknownRequestReturnsNotFound proves History distinguishes "no
// such request" from "a real request with an empty trail": an unknown (or
// cross-tenant) request id must surface ErrRequestNotFound, not a 200 with an
// empty history.
func TestHistoryUnknownRequestReturnsNotFound(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	reqSvc := NewAccessRequestService(db)
	ctx := context.Background()

	if _, err := reqSvc.History(ctx, ws, uuid.New()); !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("expected ErrRequestNotFound for unknown request, got %v", err)
	}

	// A real request still returns its (non-empty) trail without error.
	connID := seedConnector(t, db, ws, "fake")
	reqID := approveAndConnector(t, reqSvc, ws, connID)
	hist, err := reqSvc.History(ctx, ws, reqID)
	if err != nil {
		t.Fatalf("History on a real request: %v", err)
	}
	if len(hist) == 0 {
		t.Fatalf("expected a non-empty history for a real request")
	}
}

// TestListItemsUnknownReviewReturnsNotFound proves ListItems 404s on an unknown
// (or cross-tenant) review id rather than returning an empty list with 200.
func TestListItemsUnknownReviewReturnsNotFound(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	review := NewReviewService(db, nil)
	ctx := context.Background()

	if _, err := review.ListItems(ctx, ws, uuid.New()); !errors.Is(err, ErrReviewNotFound) {
		t.Fatalf("expected ErrReviewNotFound for unknown review, got %v", err)
	}

	// A cross-tenant review id is invisible: tenant-b cannot read tenant-a's
	// review items (404, never a leak).
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	prov := NewAccessProvisioningService(db, reqSvc, &fakeConnector{})
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })
	reviewA := NewReviewService(db, prov)
	mustProvision(t, reqSvc, prov, ws, connID, "ext-1")
	rev, _, err := reviewA.StartCampaign(ctx, ws, "Q1", "auditor")
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	wsB := seedWorkspace(t, db, "tenant-b")
	if _, err := review.ListItems(ctx, wsB, rev.ID); !errors.Is(err, ErrReviewNotFound) {
		t.Fatalf("expected ErrReviewNotFound for cross-tenant review, got %v", err)
	}
}

// TestCompleteCampaignIsIdempotent proves completing an already-completed
// campaign is a no-op: it returns the same report without error and does NOT
// append a second "access_review.completed" audit event (the FOR-UPDATE guard
// inside the transaction makes the second call observe the completed state).
func TestCompleteCampaignIsIdempotent(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	prov := NewAccessProvisioningService(db, reqSvc, &fakeConnector{})
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })
	review := NewReviewService(db, prov)
	ctx := context.Background()

	mustProvision(t, reqSvc, prov, ws, connID, "ext-1")
	rev, _, err := review.StartCampaign(ctx, ws, "Q1", "auditor")
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}

	first, err := review.CompleteCampaign(ctx, ws, rev.ID, "auditor")
	if err != nil {
		t.Fatalf("CompleteCampaign #1: %v", err)
	}
	second, err := review.CompleteCampaign(ctx, ws, rev.ID, "auditor")
	if err != nil {
		t.Fatalf("CompleteCampaign #2 (idempotent): %v", err)
	}
	if first.State != ReviewStateCompleted || second.State != ReviewStateCompleted {
		t.Fatalf("both reports must be completed: %+v / %+v", first, second)
	}

	var completedEvents int64
	if err := db.Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND action = ? AND target_ref = ?", ws, "access_review.completed", rev.ID.String()).
		Count(&completedEvents).Error; err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	if completedEvents != 1 {
		t.Fatalf("expected exactly 1 completion audit event, got %d", completedEvents)
	}
}

func TestLeaverKillSwitchAllLayers(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{}
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })
	disabler := &fakeDisabler{}
	jml := NewJMLService(db, reqSvc, NewWorkflowService(reqSvc), prov, fc, disabler)
	ctx := context.Background()

	// User ext-leaver has a grant and a team membership.
	g := mustProvision(t, reqSvc, prov, ws, connID, "ext-leaver")
	tm := &models.TeamMember{WorkspaceID: ws, TeamID: uuid.New(), IAMCoreUserID: "ext-leaver", Role: "member"}
	if err := db.Create(tm).Error; err != nil {
		t.Fatalf("seed team member: %v", err)
	}

	res, err := jml.HandleLeaver(ctx, ws, SCIMEvent{Method: "DELETE", UserExternalID: "ext-leaver"})
	if err != nil {
		t.Fatalf("HandleLeaver: %v", err)
	}
	if res.Errored {
		t.Fatalf("expected no layer failures, got %+v", res.Layers)
	}
	if len(res.Layers) != 6 {
		t.Fatalf("expected 6 layers, got %d: %+v", len(res.Layers), res.Layers)
	}

	// Grant revoked.
	var greload models.AccessGrant
	db.Where("id = ?", g.ID).Take(&greload)
	if greload.State != GrantStateRevoked {
		t.Fatalf("expected grant revoked, got %s", greload.State)
	}
	// Team membership removed.
	var tmCount int64
	db.Model(&models.TeamMember{}).Where("workspace_id = ? AND iam_core_user_id = ?", ws, "ext-leaver").Count(&tmCount)
	if tmCount != 0 {
		t.Fatalf("expected team memberships removed, got %d", tmCount)
	}
	// iam-core disable called.
	if disabler.blocked["ext-leaver"] != 1 {
		t.Fatalf("expected BlockUser called once, got %d", disabler.blocked["ext-leaver"])
	}
	// Session revoke layer ran on the connector.
	if fc.revokeSessCnt != 1 {
		t.Fatalf("expected 1 RevokeSessions, got %d", fc.revokeSessCnt)
	}

	// Idempotent re-run.
	res2, err := jml.HandleLeaver(ctx, ws, SCIMEvent{Method: "DELETE", UserExternalID: "ext-leaver"})
	if err != nil {
		t.Fatalf("HandleLeaver re-run: %v", err)
	}
	if res2.Errored {
		t.Fatalf("re-run had failures: %+v", res2.Layers)
	}
}

func TestKillSwitchContinuesAfterLayerFailure(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{revokeErr: &fakeErr{"revoke boom"}} // layer-1 grant revoke fails
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })
	disabler := &fakeDisabler{}
	jml := NewJMLService(db, reqSvc, nil, prov, fc, disabler)
	ctx := context.Background()

	mustProvision(t, reqSvc, prov, ws, connID, "ext-leaver")

	res, err := jml.HandleLeaver(ctx, ws, SCIMEvent{Method: "DELETE", UserExternalID: "ext-leaver"})
	if err == nil {
		t.Fatal("expected an error because a layer failed")
	}
	if !res.Errored {
		t.Fatal("expected Errored=true")
	}
	// Even though layer 1 failed, the iam-core disable layer must still run.
	if disabler.blocked["ext-leaver"] != 1 {
		t.Fatalf("expected BlockUser still called after earlier failure, got %d", disabler.blocked["ext-leaver"])
	}
	if len(res.Layers) != 6 {
		t.Fatalf("expected all 6 layers attempted, got %d", len(res.Layers))
	}
}

// TestKillSwitchConnectorResolveFailureReportsFailedNotSkipped proves a leaver
// sweep whose connectors all fail to resolve (e.g. rotated DEK) reports the
// session-revoke and scim-deprovision layers as "failed" and errors the kill
// switch — instead of misclassifying an unswept connector as "skipped" and
// returning success.
func TestKillSwitchConnectorResolveFailureReportsFailedNotSkipped(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{resolveErr: &fakeErr{"resolve boom: rotated DEK"}}
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })
	disabler := &fakeDisabler{}
	jml := NewJMLService(db, reqSvc, nil, prov, fc, disabler)
	ctx := context.Background()

	// No grant for this user, so the grant-revoke layer is a clean no-op and we
	// isolate the connector-sweep behavior.
	res, err := jml.HandleLeaver(ctx, ws, SCIMEvent{Method: "DELETE", UserExternalID: "ext-leaver"})
	if err == nil {
		t.Fatal("expected error: connector sweep failed to resolve every connector")
	}
	if !res.Errored {
		t.Fatalf("expected Errored=true, got %+v", res.Layers)
	}
	byLayer := map[string]string{}
	for _, l := range res.Layers {
		byLayer[l.Layer] = l.Status
	}
	if byLayer[LayerSessionRevoke] != LayerStatusFailed {
		t.Fatalf("session_revoke = %q, want failed (must not be skipped)", byLayer[LayerSessionRevoke])
	}
	if byLayer[LayerSCIMDeprov] != LayerStatusFailed {
		t.Fatalf("scim_deprovision = %q, want failed (must not be skipped)", byLayer[LayerSCIMDeprov])
	}
}

// TestHandleEventSurfacesLeaverResultOnFailure proves HandleEvent returns the
// six-layer kill-switch breakdown alongside the error for the leaver lane, so a
// partial kill-switch failure is not reduced to an opaque error with the
// per-layer detail discarded.
func TestHandleEventSurfacesLeaverResultOnFailure(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{revokeErr: &fakeErr{"revoke boom"}} // layer-1 grant revoke fails
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })
	jml := NewJMLService(db, reqSvc, nil, prov, fc, &fakeDisabler{})
	ctx := context.Background()

	mustProvision(t, reqSvc, prov, ws, connID, "ext-leaver")

	lane, leaver, err := jml.HandleEvent(ctx, ws, SCIMEvent{Method: "DELETE", UserExternalID: "ext-leaver"})
	if err == nil {
		t.Fatal("expected error from partial kill-switch failure")
	}
	if lane != JMLLeaver {
		t.Fatalf("lane = %q, want leaver", lane)
	}
	if leaver == nil {
		t.Fatal("HandleEvent dropped the LeaverResult; operator loses per-layer detail")
	}
	if !leaver.Errored || len(leaver.Layers) != 6 {
		t.Fatalf("expected errored result with 6 layers, got %+v", leaver)
	}

	// The joiner/mover lanes carry no kill-switch result.
	_, joinerRes, err := jml.HandleEvent(ctx, ws, SCIMEvent{Method: "POST", UserExternalID: "ext-joiner"})
	if err != nil {
		t.Fatalf("joiner HandleEvent: %v", err)
	}
	if joinerRes != nil {
		t.Fatalf("joiner lane must not return a LeaverResult, got %+v", joinerRes)
	}
}

func TestClassifyChange(t *testing.T) {
	f := false
	tr := true
	cases := []struct {
		e    SCIMEvent
		want string
	}{
		{SCIMEvent{Method: "POST"}, JMLJoiner},
		{SCIMEvent{Method: "DELETE"}, JMLLeaver},
		{SCIMEvent{Method: "PATCH", Active: &f}, JMLLeaver},
		{SCIMEvent{Method: "PATCH", Active: &tr}, JMLJoiner},
		{SCIMEvent{Method: "PATCH", GroupsChanged: true}, JMLMover},
		{SCIMEvent{Method: "PUT"}, JMLMover},
	}
	for _, tc := range cases {
		if got := ClassifyChange(tc.e); got != tc.want {
			t.Errorf("ClassifyChange(%+v)=%s want %s", tc.e, got, tc.want)
		}
	}
}

func TestOrphanReconcilerDryRunAndDisposition(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{
		identities: []*access.Identity{
			{ExternalID: "ext-granted", Type: access.IdentityTypeUser},
			{ExternalID: "ext-orphan", Type: access.IdentityTypeUser},
		},
	}
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })
	rec := NewOrphanReconciler(db, fc)
	ctx := context.Background()

	// ext-granted has a live grant; ext-orphan does not.
	mustProvision(t, reqSvc, prov, ws, connID, "ext-granted")

	// Dry run persists nothing.
	dry, err := rec.Scan(ctx, ws, connID, true)
	if err != nil {
		t.Fatalf("dry Scan: %v", err)
	}
	if dry.OrphanCount != 1 || dry.Orphans[0].ExternalUserID != "ext-orphan" {
		t.Fatalf("expected 1 orphan ext-orphan, got %+v", dry.Orphans)
	}
	var persisted int64
	db.Model(&models.AccessOrphanAccount{}).Where("workspace_id = ?", ws).Count(&persisted)
	if persisted != 0 {
		t.Fatalf("dry run persisted %d rows", persisted)
	}

	// Real run persists.
	real, err := rec.Scan(ctx, ws, connID, false)
	if err != nil {
		t.Fatalf("real Scan: %v", err)
	}
	if real.PersistedCount != 1 {
		t.Fatalf("expected 1 persisted orphan, got %d", real.PersistedCount)
	}

	orphans, _ := rec.ListOrphans(ctx, ws)
	if len(orphans) != 1 {
		t.Fatalf("expected 1 orphan row, got %d", len(orphans))
	}
	if err := rec.SetDisposition(ctx, ws, orphans[0].ID, OrphanDispositionIgnore, "admin"); err != nil {
		t.Fatalf("SetDisposition: %v", err)
	}
	reloaded, _ := rec.ListOrphans(ctx, ws)
	if reloaded[0].Disposition != OrphanDispositionIgnore {
		t.Fatalf("expected ignore disposition, got %s", reloaded[0].Disposition)
	}

	// A disposition on an unknown orphan id must report the orphan-specific
	// not-found sentinel (not ErrGrantNotFound), so the REST layer returns an
	// accurate 404 message.
	if err := rec.SetDisposition(ctx, ws, uuid.New(), OrphanDispositionIgnore, "admin"); !errors.Is(err, ErrOrphanNotFound) {
		t.Fatalf("expected ErrOrphanNotFound for missing orphan, got %v", err)
	}
}

func TestExpiryEnforcer(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{}
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })
	ctx := context.Background()

	g := mustProvision(t, reqSvc, prov, ws, connID, "ext-u")
	// Force the grant to be expired in the past.
	past := time.Now().Add(-1 * time.Hour)
	db.Model(&models.AccessGrant{}).Where("id = ?", g.ID).Update("expires_at", past)

	enf := NewExpiryEnforcer(db, prov)
	res, err := enf.EnforceExpired(ctx, ws)
	if err != nil {
		t.Fatalf("EnforceExpired: %v", err)
	}
	if res.Expired != 1 {
		t.Fatalf("expected 1 expired, got %+v", res)
	}
	var greload models.AccessGrant
	db.Where("id = ?", g.ID).Take(&greload)
	if greload.State != GrantStateExpired {
		t.Fatalf("expected grant expired, got %s", greload.State)
	}
}

func TestSSOEnforcementChecker(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	fc := &fakeConnector{ssoEnforced: true}
	chk := NewSSOEnforcementChecker(db, fc)
	ctx := context.Background()

	status, err := chk.Check(ctx, ws, connID)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !status.Supported || !status.Enforced {
		t.Fatalf("expected supported+enforced, got %+v", status)
	}
}

// --- helpers ---

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// mustProvision creates+approves+provisions a grant for user and returns it.
func mustProvision(t *testing.T, reqSvc *AccessRequestService, prov *AccessProvisioningService, ws, connID uuid.UUID, user string) *models.AccessGrant {
	t.Helper()
	ctx := context.Background()
	r, err := reqSvc.CreateRequest(ctx, CreateAccessRequestInput{
		WorkspaceID: ws, RequesterID: "u", TargetUserID: user, ConnectorID: &connID,
		ResourceRef: "app:db", Role: "reader",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := reqSvc.ApproveRequest(ctx, ws, r.ID, "mgr", "ok"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	g, err := prov.Provision(ctx, ws, r.ID, "system")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	return g
}

// fakeDisabler records BlockUser calls.
type fakeDisabler struct {
	blocked map[string]int
}

func (d *fakeDisabler) BlockUser(_ context.Context, userID string) error {
	if d.blocked == nil {
		d.blocked = map[string]int{}
	}
	d.blocked[userID]++
	return nil
}

func TestSchedulerExpirySweepAcrossWorkspaces(t *testing.T) {
	db := newTestDB(t)
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{}
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })
	ctx := context.Background()

	// Two workspaces each with an overdue grant.
	wsA := seedWorkspace(t, db, "tenant-a")
	wsB := seedWorkspace(t, db, "tenant-b")
	connA := seedConnector(t, db, wsA, "fake")
	connB := seedConnector(t, db, wsB, "fake")
	gA := mustProvision(t, reqSvc, prov, wsA, connA, "ext-a")
	gB := mustProvision(t, reqSvc, prov, wsB, connB, "ext-b")
	past := time.Now().Add(-time.Hour)
	db.Model(&models.AccessGrant{}).Where("id IN ?", []uuid.UUID{gA.ID, gB.ID}).Update("expires_at", past)

	sched := NewScheduler(db, NewExpiryEnforcer(db, prov), nil, SchedulerConfig{})
	n, err := sched.RunExpirySweep(ctx)
	if err != nil {
		t.Fatalf("RunExpirySweep: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 grants expired across workspaces, got %d", n)
	}
}

func TestSchedulerOrphanSweep(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	seedConnector(t, db, ws, "fake") // scheduler discovers it from the DB
	fc := &fakeConnector{identities: []*access.Identity{{ExternalID: "ext-orphan", Type: access.IdentityTypeUser}}}
	rec := NewOrphanReconciler(db, fc)
	ctx := context.Background()

	sched := NewScheduler(db, NewExpiryEnforcer(db, &noopExpirer{}), rec, SchedulerConfig{})
	n, err := sched.RunOrphanSweep(ctx)
	if err != nil {
		t.Fatalf("RunOrphanSweep: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 orphan recorded, got %d", n)
	}
}

// TestSchedulerOrphanSweepSkipsPendingConnectors proves the sweep ignores a
// connector that has never been configured (status "pending"): it has no synced
// identities, so scanning it would only produce recurring resolve-error noise.
func TestSchedulerOrphanSweepSkipsPendingConnectors(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	pending := &models.AccessConnector{WorkspaceID: ws, Provider: "fake", Status: "pending"}
	if err := db.Create(pending).Error; err != nil {
		t.Fatalf("seed pending connector: %v", err)
	}
	fc := &fakeConnector{identities: []*access.Identity{{ExternalID: "ext-orphan", Type: access.IdentityTypeUser}}}
	sched := NewScheduler(db, NewExpiryEnforcer(db, &noopExpirer{}), NewOrphanReconciler(db, fc), SchedulerConfig{})

	n, err := sched.RunOrphanSweep(context.Background())
	if err != nil {
		t.Fatalf("RunOrphanSweep: %v", err)
	}
	if n != 0 {
		t.Fatalf("pending connector must be skipped, got %d orphan(s) recorded", n)
	}
}

type noopExpirer struct{}

func (noopExpirer) ExpireGrant(context.Context, uuid.UUID, uuid.UUID, string) error {
	return nil
}

// TestScimDeprovisionRevokesAllEntitlementsDespiteFailure proves the
// security-critical SCIM deprovision step does not abort on the first failed
// revocation: when one entitlement fails, the remaining ones are still revoked
// (maximal revocation), and the call still returns an error so the kill-switch
// layer is marked failed and a retry is driven.
func TestScimDeprovisionRevokesAllEntitlementsDespiteFailure(t *testing.T) {
	db := newTestDB(t)
	jml := NewJMLService(db, nil, nil, nil, nil, nil)
	fc := &fakeConnector{
		entitlements: []access.Entitlement{
			{ResourceExternalID: "res-a", Role: "reader"},
			{ResourceExternalID: "res-b", Role: "writer"},
			{ResourceExternalID: "res-c", Role: "admin"},
		},
		revokeFailFor: map[string]bool{"res-b": true},
	}
	resolved := &ResolvedConnector{Provider: "fake", Impl: fc}

	err := jml.scimDeprovision(context.Background(), resolved, "ext-leaver")
	if err == nil {
		t.Fatal("expected an error because res-b revocation failed")
	}

	// Every entitlement must have been attempted, not just up to the failure.
	want := map[string]bool{"res-a": true, "res-b": true, "res-c": true}
	got := map[string]bool{}
	for _, r := range fc.revokedResources {
		got[r] = true
	}
	for r := range want {
		if !got[r] {
			t.Fatalf("entitlement %s was not attempted; revoked=%v", r, fc.revokedResources)
		}
	}
	if len(fc.revokedResources) != 3 {
		t.Fatalf("expected exactly 3 revoke attempts, got %d (%v)", len(fc.revokedResources), fc.revokedResources)
	}
}

// TestAuditChainStaysLinearAcrossMultiEventTransactions proves the hash chain
// is not forked by the multi-event Provision transaction. Provision appends
// three audit events in one transaction (two state transitions + grant
// created), and a later RevokeGrant appends more in a separate transaction. The
// chain head is selected by chain_seq, not created_at, so the grant-created
// event (whose created_at can be earlier than the transition events') is still
// the true tail that the next append links to. A fixed clock forces every row
// to share one created_at, which is exactly the condition that broke the old
// (created_at, id) ordering.
func TestAuditChainStaysLinearAcrossMultiEventTransactions(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{}
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })

	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	reqSvc.SetClock(func() time.Time { return fixed })
	prov.SetClock(func() time.Time { return fixed })

	ctx := context.Background()
	g := mustProvision(t, reqSvc, prov, ws, connID, "ext-chain")
	if err := prov.RevokeGrant(ctx, ws, g.ID, "auditor", "test revoke"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	var events []models.AuditEvent
	if err := db.WithContext(ctx).
		Where("workspace_id = ?", ws).
		Order("chain_seq asc").
		Find(&events).Error; err != nil {
		t.Fatalf("load audit events: %v", err)
	}
	if len(events) < 2 {
		t.Fatalf("expected several audit events, got %d", len(events))
	}

	seenPrev := map[string]uuid.UUID{}
	prevHash := ""
	for i := range events {
		ev := events[i]
		if ev.ChainSeq != int64(i+1) {
			t.Fatalf("chain_seq not contiguous: event %d has seq %d", i, ev.ChainSeq)
		}
		if ev.PrevHash != prevHash {
			t.Fatalf("chain broken at seq %d: prev_hash %q != expected %q", ev.ChainSeq, ev.PrevHash, prevHash)
		}
		if ev.PrevHash != "" {
			if other, dup := seenPrev[ev.PrevHash]; dup {
				t.Fatalf("chain forked: events %s and %s both chain off prev_hash %q", other, ev.ID, ev.PrevHash)
			}
			seenPrev[ev.PrevHash] = ev.ID
		}
		prevHash = ev.ChainHash
	}
}
