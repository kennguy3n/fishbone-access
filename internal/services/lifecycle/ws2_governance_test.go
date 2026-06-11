package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// seedActiveGrant inserts a live access_grant directly (bypassing the request
// flow) so SoD/anomaly tests can stand up a subject's effective entitlements
// without driving the whole provisioning machinery.
func seedActiveGrant(t *testing.T, db *gorm.DB, ws, connID uuid.UUID, user, resource, role string) {
	t.Helper()
	g := &models.AccessGrant{
		WorkspaceID:   ws,
		ConnectorID:   connID,
		IAMCoreUserID: user,
		ResourceRef:   resource,
		Role:          role,
		State:         GrantStateActive,
		GrantedAt:     time.Now(),
	}
	if err := db.Create(g).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}
}

// seedSodRule inserts a SoD rule via the service so validation/defaults apply.
func seedSodRule(t *testing.T, db *gorm.DB, ws uuid.UUID, name, severity, resA, roleA, resB, roleB string) *models.SodRule {
	t.Helper()
	rule, err := NewSodService(db).CreateRule(context.Background(), CreateSodRuleInput{
		WorkspaceID: ws, Name: name, Severity: severity,
		ResourceA: resA, RoleA: roleA, ResourceB: resB, RoleB: roleB, Actor: "admin",
	})
	if err != nil {
		t.Fatalf("seed sod rule: %v", err)
	}
	return rule
}

// --- SoD engine ---

// TestSodWhatIfFlagsIntroducedToxicCombination pins the core SoD what-if: a
// candidate grant that gives a subject the second half of a toxic pair is
// flagged as introduced, while a subject who gains nothing toxic is not.
func TestSodWhatIfFlagsIntroducedToxicCombination(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	ctx := context.Background()

	// u1 already can create vendors; u2 holds nothing.
	seedActiveGrant(t, db, ws, conn, "u1", "app:vendor", "create")
	seedSodRule(t, db, ws, "vendor-vs-payment", models.SodSeverityHigh, "app:vendor", "create", "app:payment", "approve")

	eng := NewSodEngine(db)
	// Candidate: grant approve-payment to both u1 and u2.
	def := PolicyDefinition{Action: PolicyActionGrant, Subjects: []string{"u1", "u2"}, Resources: []string{"app:payment"}, Role: "approve"}
	vs, err := eng.EvaluatePolicyTx(ctx, db, ws, def)
	if err != nil {
		t.Fatalf("EvaluatePolicyTx: %v", err)
	}
	if len(vs) != 1 {
		t.Fatalf("expected exactly 1 introduced violation (u1 only), got %d: %+v", len(vs), vs)
	}
	if vs[0].Subject != "u1" || !vs[0].Introduced {
		t.Fatalf("expected introduced violation for u1, got %+v", vs[0])
	}
}

// TestSodWhatIfNoFalsePositiveOnPreExisting pins the precise-introduced fix: a
// subject who ALREADY holds both sides of a rule must not have a fresh grant
// (that only adds more of one side) reported as introducing the combination —
// otherwise an unrelated change would be wrongly blocked.
func TestSodWhatIfNoFalsePositiveOnPreExisting(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	ctx := context.Background()

	// u1 already holds BOTH sides — a standing violation.
	seedActiveGrant(t, db, ws, conn, "u1", "app:vendor", "create")
	seedActiveGrant(t, db, ws, conn, "u1", "app:payment", "approve")
	// Wildcard-role rule so an extra vendor grant still matches selector A.
	seedSodRule(t, db, ws, "vendor-vs-payment", models.SodSeverityHigh, "app:vendor", "*", "app:payment", "*")

	eng := NewSodEngine(db)
	// Candidate adds another vendor entitlement (selector A) to u1.
	def := PolicyDefinition{Action: PolicyActionGrant, Subjects: []string{"u1"}, Resources: []string{"app:vendor"}, Role: "write"}
	vs, err := eng.EvaluatePolicyTx(ctx, db, ws, def)
	if err != nil {
		t.Fatalf("EvaluatePolicyTx: %v", err)
	}
	if len(vs) != 0 {
		t.Fatalf("a pre-existing toxic combination must not be reported as introduced, got %+v", vs)
	}
}

// TestSodStandingDetectionDeterministic pins the standing detector: it finds
// the live toxic combination, marks it not-introduced, and is stable.
func TestSodStandingDetectionDeterministic(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	ctx := context.Background()

	seedActiveGrant(t, db, ws, conn, "u1", "app:vendor", "create")
	seedActiveGrant(t, db, ws, conn, "u1", "app:payment", "approve")
	seedActiveGrant(t, db, ws, conn, "u2", "app:vendor", "create") // only one side
	seedSodRule(t, db, ws, "vendor-vs-payment", models.SodSeverityHigh, "app:vendor", "create", "app:payment", "approve")

	vs, err := NewSodEngine(db).DetectStandingViolations(ctx, ws)
	if err != nil {
		t.Fatalf("DetectStandingViolations: %v", err)
	}
	if len(vs) != 1 || vs[0].Subject != "u1" || vs[0].Introduced {
		t.Fatalf("expected one standing (not-introduced) violation for u1, got %+v", vs)
	}
}

// --- richer simulation guardrails ---

// TestPromoteBlockedByHighSeveritySod proves a Draft→Active promotion that
// would introduce a high-severity toxic combination is blocked with the typed
// SoD error, and that an audited force override clears the block.
func TestPromoteBlockedByHighSeveritySod(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	svc := NewPolicyService(db)
	ctx := context.Background()

	seedActiveGrant(t, db, ws, conn, "u1", "app:vendor", "create")
	seedSodRule(t, db, ws, "vendor-vs-payment", models.SodSeverityHigh, "app:vendor", "create", "app:payment", "approve")

	def := mustJSON(t, PolicyDefinition{Action: "grant", Subjects: []string{"u1"}, Resources: []string{"app:payment"}, Role: "approve"})
	pol, err := svc.CreatePolicy(ctx, CreatePolicyInput{WorkspaceID: ws, Name: "p", Definition: def, Actor: "admin"})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	sim, err := svc.Simulate(ctx, ws, pol.ID)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if !sim.Impact.Catastrophic || len(sim.Impact.SoDViolations) != 1 {
		t.Fatalf("expected catastrophic simulation with 1 SoD violation, got catastrophic=%v violations=%+v", sim.Impact.Catastrophic, sim.Impact.SoDViolations)
	}

	_, err = svc.Promote(ctx, ws, pol.ID, "admin", PromoteOptions{})
	if !errors.Is(err, ErrPolicyHasSodViolations) {
		t.Fatalf("expected promotion blocked by SoD, got %v", err)
	}
	var se *PromoteSodError
	if !errors.As(err, &se) || len(se.Violations) != 1 {
		t.Fatalf("expected typed PromoteSodError carrying 1 violation, got %v", err)
	}

	// Force override with a reason promotes.
	p2, err := svc.Promote(ctx, ws, pol.ID, "admin", PromoteOptions{Force: true, Reason: "risk accepted by CISO"})
	if err != nil {
		t.Fatalf("forced Promote: %v", err)
	}
	if p2.State != PolicyStateActive {
		t.Fatalf("expected active after forced promote, got %s", p2.State)
	}
}

// TestPromoteNotBlockedByLowSeveritySod proves a low-severity toxic combination
// is surfaced in simulation but does not hard-block promotion.
func TestPromoteNotBlockedByLowSeveritySod(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	svc := NewPolicyService(db)
	ctx := context.Background()

	seedActiveGrant(t, db, ws, conn, "u1", "app:vendor", "create")
	seedSodRule(t, db, ws, "soft-rule", models.SodSeverityLow, "app:vendor", "create", "app:payment", "approve")

	def := mustJSON(t, PolicyDefinition{Action: "grant", Subjects: []string{"u1"}, Resources: []string{"app:payment"}, Role: "approve"})
	pol, _ := svc.CreatePolicy(ctx, CreatePolicyInput{WorkspaceID: ws, Name: "p", Definition: def, Actor: "admin"})
	sim, err := svc.Simulate(ctx, ws, pol.ID)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if len(sim.Impact.SoDViolations) != 1 {
		t.Fatalf("expected the low-severity violation surfaced, got %+v", sim.Impact.SoDViolations)
	}
	if _, err := svc.Promote(ctx, ws, pol.ID, "admin", PromoteOptions{}); err != nil {
		t.Fatalf("low-severity SoD must not block promotion, got %v", err)
	}
}

// TestSimulateDefinitionCatastrophicWildcard proves the ad-hoc bulk what-if
// flags an unbounded wildcard grant as catastrophic and never mutates anything.
func TestSimulateDefinitionCatastrophicWildcard(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	svc := NewPolicyService(db)
	ctx := context.Background()

	def := PolicyDefinition{Action: PolicyActionGrant, Subjects: []string{"u1"}, Resources: []string{"*"}, Role: "admin"}
	sim, err := svc.SimulateDefinition(ctx, ws, def)
	if err != nil {
		t.Fatalf("SimulateDefinition: %v", err)
	}
	if !sim.Impact.Catastrophic || !sim.Impact.WildcardResource {
		t.Fatalf("expected catastrophic wildcard verdict, got %+v", sim.Impact)
	}
	var grants, policies int64
	db.Model(&models.AccessGrant{}).Where("workspace_id = ?", ws).Count(&grants)
	db.Model(&models.Policy{}).Where("workspace_id = ?", ws).Count(&policies)
	if grants != 0 || policies != 0 {
		t.Fatalf("ad-hoc what-if must not persist anything, got grants=%d policies=%d", grants, policies)
	}
}

// --- anomaly → CC7.3 evidence ---

// TestAnomalyDetectorEmitsDispositionedEvidence proves the scheduled detector
// turns a standing toxic combination into the CC7.3 evidence pair
// (orphan.detected + orphan.disposition.*) through the audit chain, records a
// flagged anomaly, and is idempotent across sweeps.
func TestAnomalyDetectorEmitsDispositionedEvidence(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	ctx := context.Background()

	seedActiveGrant(t, db, ws, conn, "u1", "app:vendor", "create")
	seedActiveGrant(t, db, ws, conn, "u1", "app:payment", "approve")
	seedSodRule(t, db, ws, "vendor-vs-payment", models.SodSeverityHigh, "app:vendor", "create", "app:payment", "approve")

	det := NewAnomalyDetector(db)
	n, err := det.DetectAndRecord(ctx, ws)
	if err != nil {
		t.Fatalf("DetectAndRecord: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 new anomaly recorded, got %d", n)
	}

	// One flagged anomaly worklist row.
	var anomalies []models.AccessAnomaly
	db.Where("workspace_id = ?", ws).Find(&anomalies)
	if len(anomalies) != 1 || anomalies[0].Disposition != models.AnomalyDispositionFlagged {
		t.Fatalf("expected 1 flagged anomaly, got %+v", anomalies)
	}

	// CC7.3 evidence pair on the audit chain.
	assertAuditCount(t, db, ws, "orphan.detected", 1)
	assertAuditCount(t, db, ws, "orphan.disposition.flagged", 1)

	// Idempotent: a second sweep over unchanged grants records nothing new.
	n2, err := det.DetectAndRecord(ctx, ws)
	if err != nil {
		t.Fatalf("DetectAndRecord re-run: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("expected idempotent re-run to record 0, got %d", n2)
	}
	assertAuditCount(t, db, ws, "orphan.detected", 1)
	assertAuditCount(t, db, ws, "orphan.disposition.flagged", 1)
}

func assertAuditCount(t *testing.T, db *gorm.DB, ws uuid.UUID, action string, want int64) {
	t.Helper()
	var got int64
	db.Model(&models.AuditEvent{}).Where("workspace_id = ? AND action = ?", ws, action).Count(&got)
	if got != want {
		t.Fatalf("expected %d %q audit rows, got %d", want, action, got)
	}
}

// --- contractor lifecycle ---

type contractorStack struct {
	db       *gorm.DB
	svc      *ContractorService
	enforcer *ContractorExpiryEnforcer
	fc       *fakeConnector
	disabler *fakeDisabler
	clock    func() time.Time
}

func newContractorStack(t *testing.T, db *gorm.DB, now time.Time) *contractorStack {
	t.Helper()
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{}
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })
	disabler := &fakeDisabler{}
	jml := NewJMLService(db, reqSvc, NewWorkflowService(reqSvc), prov, fc, disabler)
	clock := func() time.Time { return now }
	svc := NewContractorService(db, prov)
	svc.SetClock(clock)
	enforcer := NewContractorExpiryEnforcer(db, svc, prov, jml)
	enforcer.SetClock(clock)
	return &contractorStack{db: db, svc: svc, enforcer: enforcer, fc: fc, disabler: disabler, clock: clock}
}

func (s *contractorStack) create(t *testing.T, ws, conn uuid.UUID, user string, expires time.Time) *models.ContractorGrant {
	t.Helper()
	cg, err := s.svc.CreateGrant(context.Background(), CreateContractorGrantInput{
		WorkspaceID: ws, ContractorUserID: user, ConnectorID: conn,
		ResourceRef: "app:db", Role: "reader", SponsorID: "sponsor-1",
		RequestedBy: "requester", ExpiresAt: expires,
	})
	if err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	return cg
}

func TestContractorCreateRequiresFutureExpiry(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	now := time.Now()
	st := newContractorStack(t, db, now)

	_, err := st.svc.CreateGrant(context.Background(), CreateContractorGrantInput{
		WorkspaceID: ws, ContractorUserID: "ext-1", ConnectorID: conn,
		ResourceRef: "app:db", SponsorID: "sponsor-1", ExpiresAt: now.Add(-time.Hour),
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for past expiry, got %v", err)
	}
}

func TestContractorApproveMaterializesTimeBoxedGrant(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	now := time.Now()
	st := newContractorStack(t, db, now)
	ctx := context.Background()

	expires := now.Add(48 * time.Hour)
	cg := st.create(t, ws, conn, "ext-1", expires)

	got, err := st.svc.ApproveGrant(ctx, ws, cg.ID, "sponsor-1")
	if err != nil {
		t.Fatalf("ApproveGrant: %v", err)
	}
	if got.State != models.ContractorStateActive || got.GrantID == nil {
		t.Fatalf("expected active contractor grant bound to an access_grant, got state=%s grant_id=%v", got.State, got.GrantID)
	}
	if st.fc.provisionCnt != 1 {
		t.Fatalf("expected exactly one provider provision, got %d", st.fc.provisionCnt)
	}
	var g models.AccessGrant
	if err := db.Where("id = ?", *got.GrantID).Take(&g).Error; err != nil {
		t.Fatalf("load access_grant: %v", err)
	}
	if g.State != GrantStateActive || g.ExpiresAt == nil || !g.ExpiresAt.Equal(expires.UTC()) {
		t.Fatalf("expected active access_grant time-boxed to %v, got state=%s expires=%v", expires.UTC(), g.State, g.ExpiresAt)
	}
}

func TestContractorApproveExpiredIsRejected(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	now := time.Now()
	st := newContractorStack(t, db, now)
	ctx := context.Background()

	cg := st.create(t, ws, conn, "ext-1", now.Add(time.Hour))
	// Clock jumps past the box before approval.
	st.svc.SetClock(func() time.Time { return now.Add(2 * time.Hour) })

	if _, err := st.svc.ApproveGrant(ctx, ws, cg.ID, "sponsor-1"); !errors.Is(err, ErrContractorState) {
		t.Fatalf("expected ErrContractorState approving an expired grant, got %v", err)
	}
	if st.fc.provisionCnt != 0 {
		t.Fatalf("an expired grant must not provision access, got %d provisions", st.fc.provisionCnt)
	}
}

func TestContractorRejectAndRevoke(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	now := time.Now()
	st := newContractorStack(t, db, now)
	ctx := context.Background()

	// Reject a pending grant — nothing provisioned.
	pending := st.create(t, ws, conn, "ext-reject", now.Add(time.Hour))
	rej, err := st.svc.RejectGrant(ctx, ws, pending.ID, "sponsor-1", "not needed")
	if err != nil {
		t.Fatalf("RejectGrant: %v", err)
	}
	if rej.State != models.ContractorStateRejected {
		t.Fatalf("expected rejected, got %s", rej.State)
	}

	// Approve then revoke another — backing access torn down precisely.
	active := st.create(t, ws, conn, "ext-revoke", now.Add(time.Hour))
	if _, err := st.svc.ApproveGrant(ctx, ws, active.ID, "sponsor-1"); err != nil {
		t.Fatalf("ApproveGrant: %v", err)
	}
	rev, err := st.svc.RevokeGrant(ctx, ws, active.ID, "sponsor-1", "engagement ended")
	if err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if rev.State != models.ContractorStateRevoked || rev.RevokedAt == nil {
		t.Fatalf("expected revoked+stamped, got state=%s revoked_at=%v", rev.State, rev.RevokedAt)
	}
	if st.fc.revokeCnt != 1 {
		t.Fatalf("expected exactly one provider revoke, got %d", st.fc.revokeCnt)
	}
	var g models.AccessGrant
	db.Where("id = ?", *rev.GrantID).Take(&g)
	if g.State != GrantStateRevoked {
		t.Fatalf("expected backing access_grant revoked, got %s", g.State)
	}
	// A sponsor revoking one engagement must NOT offboard the whole identity.
	if st.disabler.blocked["ext-revoke"] != 0 {
		t.Fatalf("precise revoke must not disable the identity, got %d", st.disabler.blocked["ext-revoke"])
	}
}

func TestContractorExtendLengthensBoxAndSyncsGrant(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	now := time.Now()
	st := newContractorStack(t, db, now)
	ctx := context.Background()

	cg := st.create(t, ws, conn, "ext-1", now.Add(time.Hour))
	approved, err := st.svc.ApproveGrant(ctx, ws, cg.ID, "sponsor-1")
	if err != nil {
		t.Fatalf("ApproveGrant: %v", err)
	}

	// Shortening is rejected; lengthening succeeds.
	if _, err := st.svc.ExtendExpiry(ctx, ws, cg.ID, "sponsor-1", now.Add(30*time.Minute), "nope"); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation shortening the box, got %v", err)
	}
	newExpiry := now.Add(72 * time.Hour)
	ext, err := st.svc.ExtendExpiry(ctx, ws, cg.ID, "sponsor-1", newExpiry, "renewed SOW")
	if err != nil {
		t.Fatalf("ExtendExpiry: %v", err)
	}
	if !ext.ExpiresAt.Equal(newExpiry.UTC()) {
		t.Fatalf("expected contractor expiry %v, got %v", newExpiry.UTC(), ext.ExpiresAt)
	}
	// Backing access_grant expiry advanced in lock-step.
	var g models.AccessGrant
	db.Where("id = ?", *approved.GrantID).Take(&g)
	if g.ExpiresAt == nil || !g.ExpiresAt.Equal(newExpiry.UTC()) {
		t.Fatalf("expected access_grant expiry synced to %v, got %v", newExpiry.UTC(), g.ExpiresAt)
	}
	// Extension history row recorded.
	var exts int64
	db.Model(&models.ContractorGrantExtension{}).Where("contractor_grant_id = ?", cg.ID).Count(&exts)
	if exts != 1 {
		t.Fatalf("expected 1 extension record, got %d", exts)
	}
}

// TestContractorExpiryOffboardsViaKillSwitch proves the time box auto-enforces:
// once a contractor's only grant lapses, the enforcer expires it and runs the
// JML kill switch to deprovision the external identity everywhere.
func TestContractorExpiryOffboardsViaKillSwitch(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	now := time.Now()
	st := newContractorStack(t, db, now)
	ctx := context.Background()

	cg := st.create(t, ws, conn, "ext-1", now.Add(time.Hour))
	approved, err := st.svc.ApproveGrant(ctx, ws, cg.ID, "sponsor-1")
	if err != nil {
		t.Fatalf("ApproveGrant: %v", err)
	}

	// Advance past the box and sweep.
	st.svc.SetClock(func() time.Time { return now.Add(2 * time.Hour) })
	st.enforcer.SetClock(func() time.Time { return now.Add(2 * time.Hour) })
	expired, err := st.enforcer.EnforceExpired(ctx, ws)
	if err != nil {
		t.Fatalf("EnforceExpired: %v", err)
	}
	if expired != 1 {
		t.Fatalf("expected 1 grant expired, got %d", expired)
	}

	reload, _ := st.svc.GetGrant(ctx, ws, cg.ID)
	if reload.State != models.ContractorStateExpired || reload.RevokedAt == nil {
		t.Fatalf("expected expired+stamped contractor grant, got state=%s revoked_at=%v", reload.State, reload.RevokedAt)
	}
	// Kill switch ran: identity disabled, connector sessions revoked, grant gone.
	if st.disabler.blocked["ext-1"] != 1 {
		t.Fatalf("expected the external identity disabled once, got %d", st.disabler.blocked["ext-1"])
	}
	if st.fc.revokeSessCnt != 1 {
		t.Fatalf("expected connector sessions revoked once, got %d", st.fc.revokeSessCnt)
	}
	var g models.AccessGrant
	db.Where("id = ?", *approved.GrantID).Take(&g)
	if g.State != GrantStateRevoked {
		t.Fatalf("expected backing access_grant revoked by kill switch, got %s", g.State)
	}

	// Idempotent: a terminal grant is never re-selected.
	again, err := st.enforcer.EnforceExpired(ctx, ws)
	if err != nil {
		t.Fatalf("EnforceExpired re-run: %v", err)
	}
	if again != 0 {
		t.Fatalf("expected idempotent re-run to expire 0, got %d", again)
	}
}

// TestContractorExpiryPreciseRevokeWhenEngagementRemains proves that expiring
// one of a contractor's grants while another is still live revokes only the
// lapsed grant's access and does NOT offboard the identity.
func TestContractorExpiryPreciseRevokeWhenEngagementRemains(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	now := time.Now()
	st := newContractorStack(t, db, now)
	ctx := context.Background()

	// Same contractor, two engagements with different boxes.
	shortG := st.create(t, ws, conn, "ext-1", now.Add(time.Hour))
	longG := st.create(t, ws, conn, "ext-1", now.Add(10*time.Hour))
	shortApproved, err := st.svc.ApproveGrant(ctx, ws, shortG.ID, "sponsor-1")
	if err != nil {
		t.Fatalf("approve short: %v", err)
	}
	if _, err := st.svc.ApproveGrant(ctx, ws, longG.ID, "sponsor-1"); err != nil {
		t.Fatalf("approve long: %v", err)
	}

	// Advance past only the short box.
	st.svc.SetClock(func() time.Time { return now.Add(2 * time.Hour) })
	st.enforcer.SetClock(func() time.Time { return now.Add(2 * time.Hour) })
	expired, err := st.enforcer.EnforceExpired(ctx, ws)
	if err != nil {
		t.Fatalf("EnforceExpired: %v", err)
	}
	if expired != 1 {
		t.Fatalf("expected only the short grant expired, got %d", expired)
	}

	// The long engagement remains active; the identity is NOT offboarded.
	longReload, _ := st.svc.GetGrant(ctx, ws, longG.ID)
	if longReload.State != models.ContractorStateActive {
		t.Fatalf("expected the remaining engagement still active, got %s", longReload.State)
	}
	if st.disabler.blocked["ext-1"] != 0 {
		t.Fatalf("identity must not be offboarded while an engagement remains, got %d", st.disabler.blocked["ext-1"])
	}
	if st.fc.revokeSessCnt != 0 {
		t.Fatalf("kill switch must not run while an engagement remains, got %d session revokes", st.fc.revokeSessCnt)
	}
	// Only the short grant's access was revoked.
	var g models.AccessGrant
	db.Where("id = ?", *shortApproved.GrantID).Take(&g)
	if g.State != GrantStateRevoked {
		t.Fatalf("expected the lapsed grant's access revoked, got %s", g.State)
	}
}

// TestContractorMarkTerminalIsStateGuarded proves the shared terminal-transition
// helper writes the terminal state and its disposition exactly once. A second
// transition racing on a grant that already left fromState (e.g. a manual revoke
// arriving after the expiry sweep already expired it) matches no row, returns
// ErrContractorState, and appends NO audit event — so the expiry sweep and a
// manual revoke can never both stamp the tamper-evident chain or overwrite each
// other's terminal state.
func TestContractorMarkTerminalIsStateGuarded(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	now := time.Now()
	st := newContractorStack(t, db, now)
	ctx := context.Background()

	cg := st.create(t, ws, conn, "ext-1", now.Add(time.Hour))
	if _, err := st.svc.ApproveGrant(ctx, ws, cg.ID, "sponsor-1"); err != nil {
		t.Fatalf("ApproveGrant: %v", err)
	}

	// First terminal transition wins: active -> expired.
	if err := st.svc.markTerminal(ctx, ws, cg.ID, models.ContractorStateActive, models.ContractorStateExpired, "system", "contractor.grant.expired", "box elapsed"); err != nil {
		t.Fatalf("first markTerminal: %v", err)
	}
	assertAuditCount(t, db, ws, "contractor.grant.expired", 1)

	// The loser of the race finds the grant no longer active.
	err := st.svc.markTerminal(ctx, ws, cg.ID, models.ContractorStateActive, models.ContractorStateRevoked, "sponsor-1", "contractor.grant.revoked", "late revoke")
	if !errors.Is(err, ErrContractorState) {
		t.Fatalf("expected ErrContractorState for a stale terminal transition, got %v", err)
	}
	// State is unchanged and NO revoked disposition was written.
	reload, _ := st.svc.GetGrant(ctx, ws, cg.ID)
	if reload.State != models.ContractorStateExpired {
		t.Fatalf("expected state to remain expired, got %s", reload.State)
	}
	assertAuditCount(t, db, ws, "contractor.grant.revoked", 0)
}

// TestContractorRejectAfterApproveIsConflict proves RejectGrant never records a
// rejection for a grant that is no longer pending (e.g. a concurrent approval
// won the race): it returns ErrContractorState, appends no rejected disposition
// to the audit chain, and leaves the grant active.
func TestContractorRejectAfterApproveIsConflict(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	now := time.Now()
	st := newContractorStack(t, db, now)
	ctx := context.Background()

	cg := st.create(t, ws, conn, "ext-1", now.Add(time.Hour))
	if _, err := st.svc.ApproveGrant(ctx, ws, cg.ID, "sponsor-1"); err != nil {
		t.Fatalf("ApproveGrant: %v", err)
	}

	_, err := st.svc.RejectGrant(ctx, ws, cg.ID, "sponsor-2", "too late")
	if !errors.Is(err, ErrContractorState) {
		t.Fatalf("expected ErrContractorState rejecting an approved grant, got %v", err)
	}
	assertAuditCount(t, db, ws, "contractor.grant.rejected", 0)
	reload, _ := st.svc.GetGrant(ctx, ws, cg.ID)
	if reload.State != models.ContractorStateActive {
		t.Fatalf("expected the grant to remain active, got %s", reload.State)
	}
}
