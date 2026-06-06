package lifecycle

import (
	"context"
	"encoding/json"
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

type noopExpirer struct{}

func (noopExpirer) ExpireGrant(context.Context, uuid.UUID, uuid.UUID, string) error {
	return nil
}
