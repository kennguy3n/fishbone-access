package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestAppendAuditWhitespaceOnlyMetadataStoresNull pins the degenerate case the
// lifecycle appender used to mishandle: whitespace-only metadata canonicalizes
// to nil, so the row must persist SQL NULL (not the raw whitespace) to stay
// byte-identical with the pgx/GORM appenders and to remain recomputable.
func TestAppendAuditWhitespaceOnlyMetadataStoresNull(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	ctx := context.Background()

	in := AuditInput{
		WorkspaceID: ws,
		Actor:       "auditor",
		Action:      "test.whitespace",
		TargetRef:   "ref-1",
		Metadata:    datatypes.JSON([]byte("   ")),
	}
	if err := AppendAudit(ctx, db, time.Now(), in); err != nil {
		t.Fatalf("append: %v", err)
	}

	var row models.AuditEvent
	if err := db.WithContext(ctx).
		Where("workspace_id = ? AND action = ?", ws, "test.whitespace").
		Take(&row).Error; err != nil {
		t.Fatalf("load row: %v", err)
	}
	if len(row.Metadata) != 0 {
		t.Fatalf("whitespace-only metadata must store NULL, got %q", string(row.Metadata))
	}
	// The stored row must recompute over the canonical (nil) metadata.
	want := ComputeChainHash(row.PrevHash, ws, row.Action, row.TargetRef, nil, row.CreatedAt)
	if row.ChainHash != want {
		t.Fatalf("row does not recompute: got %q want %q", row.ChainHash, want)
	}
}

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
	// The guard must not leave the request stranded in provisioning: it
	// reconciles the request forward to active to match the live grant it
	// returned, so the request state can never lag a materialized grant.
	got, err := reqSvc.GetRequest(ctx, ws, reqID)
	if err != nil {
		t.Fatalf("get request: %v", err)
	}
	if got.State != StateActive {
		t.Fatalf("expected request reconciled to active, got %s", got.State)
	}
}

// TestResolverErrorClassificationIsPreserved proves the connector-resolution
// call sites surface DBConnectorResolver.Resolve's own error classification
// instead of blanket-wrapping every failure as ErrConnectorNotConfigured. A raw
// DB/transient error (which Resolve leaves untagged) must NOT be reported as
// "connector not configured" (the handler maps that sentinel to 422 — a DB
// outage should be a 500); only genuinely-unusable connectors carry the
// sentinel. Check is representative: all six call sites share the same pattern.
func TestResolverErrorClassificationIsPreserved(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := uuid.New()
	ctx := context.Background()

	// A raw, untagged error (e.g. a transient DB outage surfaced by Resolve)
	// must not be reclassified as ErrConnectorNotConfigured.
	rawSSO := NewSSOEnforcementChecker(db, &fakeConnector{resolveErr: &fakeErr{"dial tcp: connection refused"}})
	if _, err := rawSSO.Check(ctx, ws, connID); err == nil {
		t.Fatal("expected error from raw resolve failure")
	} else if errors.Is(err, ErrConnectorNotConfigured) {
		t.Fatalf("raw DB error must not be classified as ErrConnectorNotConfigured: %v", err)
	}

	// An ErrConnectorNotConfigured-tagged error (genuinely unusable connector)
	// must stay classified so the handler still returns 422.
	cfgSSO := NewSSOEnforcementChecker(db, &fakeConnector{resolveErr: fmt.Errorf("%w: connector %s not found", ErrConnectorNotConfigured, connID)})
	if _, err := cfgSSO.Check(ctx, ws, connID); !errors.Is(err, ErrConnectorNotConfigured) {
		t.Fatalf("not-configured error must remain classified: %v", err)
	}
}

// TestResolveSecretsDisabledClassifiesAsNotConfigured proves a connector that
// has a sealed secret envelope but no DEK to open it (the fail-closed
// disabledEncryptor wired when ACCESS_CREDENTIAL_DEK is unset returns
// access.ErrSecretsDisabled from Decrypt) is classified as
// ErrConnectorNotConfigured (→422), not blanket 500. It is
// unusable-by-configuration, the same class as the nil-encryptor guard, so the
// caller gets an actionable "fix your config" response instead of an opaque
// internal error.
func TestResolveSecretsDisabledClassifiesAsNotConfigured(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := &models.AccessConnector{
		WorkspaceID:    ws,
		Provider:       "fake",
		Status:         "active",
		SecretEnvelope: "sealed-envelope-with-no-key-to-open-it",
	}
	if err := db.Create(conn).Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}

	resolver := NewDBConnectorResolver(db, access.NewDisabledEncryptor())
	// Make the provider lookup succeed so Resolve reaches the secret-open path.
	resolver.lookup = func(string) (access.AccessConnector, error) { return &fakeConnector{}, nil }

	_, err := resolver.Resolve(context.Background(), ws, conn.ID)
	if err == nil {
		t.Fatal("expected error resolving a connector whose secrets cannot be opened")
	}
	if !errors.Is(err, ErrConnectorNotConfigured) {
		t.Fatalf("secrets-disabled open failure must classify as ErrConnectorNotConfigured (→422), got %v", err)
	}
}

// TestAuditChainUnforkableAfterSoftDelete proves the chain-head lookup is
// Unscoped: even if an audit row were soft-deleted (audit events are immutable
// and must never be deleted, but the model embeds gorm.DeletedAt so the
// capability exists), the next append still anchors on the true max chain_seq
// rather than an earlier surviving row. A scoped lookup would skip the deleted
// head, reuse its chain_seq, and fork the SHA-256 chain.
func TestAuditChainUnforkableAfterSoftDelete(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{}
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })
	ctx := context.Background()

	// Provision writes several audit events; capture the current chain head.
	mustProvision(t, reqSvc, prov, ws, connID, "ext-softdel")
	var head models.AuditEvent
	if err := db.WithContext(ctx).
		Where("workspace_id = ?", ws).
		Order("chain_seq desc").Limit(1).
		Take(&head).Error; err != nil {
		t.Fatalf("load head: %v", err)
	}

	// Soft-delete the head row (sets deleted_at; row still physically present).
	if err := db.WithContext(ctx).Delete(&head).Error; err != nil {
		t.Fatalf("soft-delete head: %v", err)
	}

	// A subsequent append (revoke) must chain off the soft-deleted head, not an
	// earlier survivor.
	var g models.AccessGrant
	if err := db.WithContext(ctx).Where("workspace_id = ?", ws).Order("created_at desc").Limit(1).Take(&g).Error; err != nil {
		t.Fatalf("load grant: %v", err)
	}
	if err := prov.RevokeGrant(ctx, ws, g.ID, "auditor", "post-softdelete append"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// The first event appended after the soft-deleted head must reuse the next
	// sequence and chain off the head's hash — not reuse the head's seq or chain
	// off an earlier survivor (either of which forks the chain).
	var successor models.AuditEvent
	if err := db.WithContext(ctx).Unscoped().
		Where("workspace_id = ? AND chain_seq = ?", ws, head.ChainSeq+1).
		Take(&successor).Error; err != nil {
		t.Fatalf("load successor at seq %d: %v", head.ChainSeq+1, err)
	}
	if successor.PrevHash != head.ChainHash {
		t.Fatalf("successor must chain off the true (soft-deleted) head: prev_hash %q != head chain_hash %q", successor.PrevHash, head.ChainHash)
	}

	// No two surviving-or-deleted rows may share a chain_seq (a reused seq is the
	// signature of a forked chain).
	var all []models.AuditEvent
	if err := db.WithContext(ctx).Unscoped().
		Where("workspace_id = ?", ws).
		Order("chain_seq asc").Find(&all).Error; err != nil {
		t.Fatalf("load all events: %v", err)
	}
	seenSeq := map[int64]uuid.UUID{}
	for _, ev := range all {
		if other, dup := seenSeq[ev.ChainSeq]; dup {
			t.Fatalf("chain forked: events %s and %s both use chain_seq %d", other, ev.ID, ev.ChainSeq)
		}
		seenSeq[ev.ChainSeq] = ev.ID
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
	// A revoked grant carries revoked_at (distinct from the expired path).
	var greload models.AccessGrant
	db.Where("id = ?", grant.ID).Take(&greload)
	if greload.State != GrantStateRevoked || greload.RevokedAt == nil {
		t.Fatalf("revoked grant must have state=revoked and revoked_at set, got state=%s revoked_at=%v", greload.State, greload.RevokedAt)
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

	p2, err := svc.Promote(ctx, ws, pol.ID, "admin", PromoteOptions{})
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if p2.State != PolicyStateActive || p2.PromotedAt == nil {
		t.Fatalf("expected active+promoted, got %s %v", p2.State, p2.PromotedAt)
	}
	if len(p2.DraftImpact) != 0 {
		t.Fatalf("expected DraftImpact cleared on promotion, got %s", p2.DraftImpact)
	}
	var afterPromote models.Policy
	if err := db.Where("workspace_id = ? AND id = ?", ws, pol.ID).Take(&afterPromote).Error; err != nil {
		t.Fatalf("reload promoted: %v", err)
	}
	if len(afterPromote.DraftImpact) != 0 {
		t.Fatalf("expected persisted DraftImpact NULL after promotion, got %s", afterPromote.DraftImpact)
	}
	firstPromoted := *p2.PromotedAt

	// Idempotent: promoting again returns unchanged (same PromotedAt).
	p3, err := svc.Promote(ctx, ws, pol.ID, "admin", PromoteOptions{})
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
	if _, err := svc.Simulate(ctx, ws, pol.ID); err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if _, err := svc.Promote(ctx, ws, pol.ID, "admin", PromoteOptions{}); err != nil {
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
	if _, err := svc.Simulate(ctx, ws, deny.ID); err != nil {
		t.Fatalf("simulate deny: %v", err)
	}
	if _, err := svc.Promote(ctx, ws, deny.ID, "admin", PromoteOptions{}); err != nil {
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

// TestPromoteRequiresSimulation proves the test-before-rollout guard: a draft
// that has never been simulated cannot be promoted, and editing a simulated
// draft (which clears the cached impact) re-arms the guard.
func TestPromoteRequiresSimulation(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	svc := NewPolicyService(db)
	ctx := context.Background()

	def := mustJSON(t, PolicyDefinition{Action: "grant", Subjects: []string{"u1"}, Resources: []string{"app:db"}, Role: "reader"})
	pol, err := svc.CreatePolicy(ctx, CreatePolicyInput{WorkspaceID: ws, Name: "p1", Definition: def, Actor: "admin"})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	// Never simulated → promotion is refused.
	if _, err := svc.Promote(ctx, ws, pol.ID, "admin", PromoteOptions{}); !errors.Is(err, ErrPolicyNotSimulated) {
		t.Fatalf("expected ErrPolicyNotSimulated promoting an unsimulated draft, got %v", err)
	}

	// Simulate, then promotion succeeds.
	if _, err := svc.Simulate(ctx, ws, pol.ID); err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if _, err := svc.Promote(ctx, ws, pol.ID, "admin", PromoteOptions{}); err != nil {
		t.Fatalf("Promote after simulate: %v", err)
	}
}

// TestPromoteReSimulateAfterEdit proves an edit invalidates a prior simulation:
// once UpdateDraft clears DraftImpact, promotion is refused until the draft is
// simulated again.
func TestPromoteReSimulateAfterEdit(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	svc := NewPolicyService(db)
	ctx := context.Background()

	def := mustJSON(t, PolicyDefinition{Action: "grant", Subjects: []string{"u1"}, Resources: []string{"app:db"}, Role: "reader"})
	pol, _ := svc.CreatePolicy(ctx, CreatePolicyInput{WorkspaceID: ws, Name: "p1", Definition: def, Actor: "admin"})
	if _, err := svc.Simulate(ctx, ws, pol.ID); err != nil {
		t.Fatalf("Simulate: %v", err)
	}

	// Edit the draft — this clears the cached simulation.
	def2 := mustJSON(t, PolicyDefinition{Action: "grant", Subjects: []string{"u1", "u2"}, Resources: []string{"app:db"}, Role: "reader"})
	if _, err := svc.UpdateDraft(ctx, ws, pol.ID, "", def2, "admin"); err != nil {
		t.Fatalf("UpdateDraft: %v", err)
	}

	if _, err := svc.Promote(ctx, ws, pol.ID, "admin", PromoteOptions{}); !errors.Is(err, ErrPolicyNotSimulated) {
		t.Fatalf("expected ErrPolicyNotSimulated after editing a simulated draft, got %v", err)
	}
}

// TestPromoteReChecksSimulationUnderLock proves the simulate-before-rollout
// guard reads the row's live state inside the promote transaction (not a stale
// pre-read). Clearing DraftImpact out-of-band — exactly the state a concurrent
// UpdateDraft would leave behind, the TOCTOU the row lock closes — makes a
// previously-simulated draft un-promotable.
func TestPromoteReChecksSimulationUnderLock(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	svc := NewPolicyService(db)
	ctx := context.Background()

	def := mustJSON(t, PolicyDefinition{Action: "grant", Subjects: []string{"u1"}, Resources: []string{"app:db"}, Role: "reader"})
	pol, _ := svc.CreatePolicy(ctx, CreatePolicyInput{WorkspaceID: ws, Name: "p1", Definition: def, Actor: "admin"})
	if _, err := svc.Simulate(ctx, ws, pol.ID); err != nil {
		t.Fatalf("Simulate: %v", err)
	}

	// Out-of-band clear of the cached impact (what an interleaved UpdateDraft
	// would do between a naive pre-read and the write).
	if err := db.Model(&models.Policy{}).
		Where("workspace_id = ? AND id = ?", ws, pol.ID).
		Update("draft_impact", nil).Error; err != nil {
		t.Fatalf("clear draft_impact: %v", err)
	}

	if _, err := svc.Promote(ctx, ws, pol.ID, "admin", PromoteOptions{}); !errors.Is(err, ErrPolicyNotSimulated) {
		t.Fatalf("expected ErrPolicyNotSimulated when impact cleared under lock, got %v", err)
	}
}

// TestPromoteBlocksHardConflict proves a grant-vs-deny conflict with a live
// policy blocks promotion, and that an audited force override clears the block
// and records the reason in the audit chain.
func TestPromoteBlocksHardConflict(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	svc := NewPolicyService(db)
	ctx := context.Background()

	// Live deny on (u1, app:db).
	denyDef := mustJSON(t, PolicyDefinition{Action: "deny", Subjects: []string{"u1"}, Resources: []string{"app:db"}})
	deny, _ := svc.CreatePolicy(ctx, CreatePolicyInput{WorkspaceID: ws, Name: "deny", Definition: denyDef, Actor: "admin"})
	if _, err := svc.Simulate(ctx, ws, deny.ID); err != nil {
		t.Fatalf("simulate deny: %v", err)
	}
	if _, err := svc.Promote(ctx, ws, deny.ID, "admin", PromoteOptions{}); err != nil {
		t.Fatalf("promote deny: %v", err)
	}

	// Conflicting grant draft over the same pair, simulated.
	grantDef := mustJSON(t, PolicyDefinition{Action: "grant", Subjects: []string{"u1"}, Resources: []string{"app:db"}, Role: "admin"})
	grant, _ := svc.CreatePolicy(ctx, CreatePolicyInput{WorkspaceID: ws, Name: "grant", Definition: grantDef, Actor: "admin"})
	if _, err := svc.Simulate(ctx, ws, grant.ID); err != nil {
		t.Fatalf("simulate grant: %v", err)
	}

	// Promotion is blocked, and the typed error carries the conflict.
	_, err := svc.Promote(ctx, ws, grant.ID, "admin", PromoteOptions{})
	if !errors.Is(err, ErrPolicyHasConflicts) {
		t.Fatalf("expected ErrPolicyHasConflicts, got %v", err)
	}
	var ce *PromoteConflictError
	if !errors.As(err, &ce) || len(ce.Conflicts) != 1 || ce.Conflicts[0].Kind != ConflictGrantVsDeny {
		t.Fatalf("expected PromoteConflictError with 1 grant_vs_deny conflict, got %v", err)
	}

	// A force override with no justification is rejected — an empty reason must
	// never be recorded as a blank audit entry on a security override.
	if _, err := svc.Promote(ctx, ws, grant.ID, "admin", PromoteOptions{Force: true, Reason: "  "}); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation forcing override without a reason, got %v", err)
	}

	// Audited override clears the block.
	promoted, err := svc.Promote(ctx, ws, grant.ID, "admin", PromoteOptions{Force: true, Reason: "reviewed: deny is being retired"})
	if err != nil {
		t.Fatalf("forced Promote: %v", err)
	}
	if promoted.State != PolicyStateActive {
		t.Fatalf("expected active after forced promote, got %s", promoted.State)
	}

	// The override is recorded in the audit chain.
	var ev models.AuditEvent
	if err := db.Where("workspace_id = ? AND action = ?", ws, "policy.promoted_with_override").Take(&ev).Error; err != nil {
		t.Fatalf("expected an override audit event: %v", err)
	}
	if len(ev.Metadata) == 0 || !strings.Contains(string(ev.Metadata), "reviewed: deny is being retired") {
		t.Fatalf("override audit metadata missing reason: %s", string(ev.Metadata))
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
	// An expired grant must NOT carry revoked_at: it expired, it was not
	// revoked. Stamping revoked_at would conflate the two terminal states in
	// the API and break callers distinguishing automatic expiry from revoke.
	if greload.RevokedAt != nil {
		t.Fatalf("expired grant must not have revoked_at set, got %v", greload.RevokedAt)
	}

	// Revoking an already-expired grant is a no-op: it is already terminal and
	// torn down at the provider, so it must not call the connector again nor
	// flip the recorded state from expired to revoked.
	if err := prov.RevokeGrant(ctx, ws, g.ID, "admin", "after expiry"); err != nil {
		t.Fatalf("RevokeGrant on expired grant: %v", err)
	}
	if fc.revokeCnt != 1 {
		t.Fatalf("expected exactly 1 connector revoke (from expiry), got %d", fc.revokeCnt)
	}
	db.Where("id = ?", g.ID).Take(&greload)
	if greload.State != GrantStateExpired || greload.RevokedAt != nil {
		t.Fatalf("expired grant must stay expired with no revoked_at, got state=%s revoked_at=%v", greload.State, greload.RevokedAt)
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

// fakeDisabler records BlockUser calls. When err is non-nil it is returned
// from every BlockUser call (after recording it) so tests can exercise the
// iam-core disable layer's failure and "already gone" paths.
type fakeDisabler struct {
	blocked map[string]int
	err     error
}

func (d *fakeDisabler) BlockUser(_ context.Context, userID string) error {
	if d.blocked == nil {
		d.blocked = map[string]int{}
	}
	d.blocked[userID]++
	return d.err
}

// killSwitchLayer returns the result for a named layer, or nil if absent.
func killSwitchLayer(res *LeaverResult, layer string) *KillSwitchLayerResult {
	for i := range res.Layers {
		if res.Layers[i].Layer == layer {
			return &res.Layers[i]
		}
	}
	return nil
}

// A leaver who no longer exists in iam-core is the kill switch's desired end
// state, so a 404 (wrapped as ErrNotFound) from BlockUser must count as success
// — not a failure that flips Errored and blocks downstream layers' callers.
func TestKillSwitchIAMCoreDisableTreatsMissingUserAsSuccess(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{}
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })
	disabler := &fakeDisabler{err: fmt.Errorf("%w: 404", iamcore.ErrNotFound)}
	jml := NewJMLService(db, reqSvc, NewWorkflowService(reqSvc), prov, fc, disabler)
	ctx := context.Background()

	mustProvision(t, reqSvc, prov, ws, connID, "ext-leaver")

	res, err := jml.HandleLeaver(ctx, ws, SCIMEvent{Method: "DELETE", UserExternalID: "ext-leaver"})
	if err != nil {
		t.Fatalf("HandleLeaver: %v", err)
	}
	if res.Errored {
		t.Fatalf("a user already absent in iam-core must not fail the kill switch: %+v", res.Layers)
	}
	if disabler.blocked["ext-leaver"] != 1 {
		t.Fatalf("expected BlockUser called once, got %d", disabler.blocked["ext-leaver"])
	}
	layer := killSwitchLayer(res, LayerIAMCoreDisable)
	if layer == nil {
		t.Fatalf("iam-core disable layer missing: %+v", res.Layers)
	}
	if layer.Status != LayerStatusDone {
		t.Fatalf("iam-core disable layer = %q (%s), want %q", layer.Status, layer.Detail, LayerStatusDone)
	}
}

// The carve-out is narrow: a non-404 BlockUser error (e.g. iam-core down) must
// still fail the layer and flip Errored so ops are not told a live user was
// disabled when they were not.
func TestKillSwitchIAMCoreDisableFailsOnNonNotFoundError(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{}
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })
	disabler := &fakeDisabler{err: errors.New("iam-core unreachable")}
	jml := NewJMLService(db, reqSvc, NewWorkflowService(reqSvc), prov, fc, disabler)
	ctx := context.Background()

	mustProvision(t, reqSvc, prov, ws, connID, "ext-leaver")

	res, err := jml.HandleLeaver(ctx, ws, SCIMEvent{Method: "DELETE", UserExternalID: "ext-leaver"})
	if err == nil {
		t.Fatal("expected an error because the iam-core disable layer failed")
	}
	if !res.Errored {
		t.Fatalf("expected Errored=true on a non-404 BlockUser failure: %+v", res.Layers)
	}
	layer := killSwitchLayer(res, LayerIAMCoreDisable)
	if layer == nil || layer.Status != LayerStatusFailed {
		t.Fatalf("iam-core disable layer = %+v, want status %q", layer, LayerStatusFailed)
	}
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

// failingApprover is a RequestApprover whose ApproveRequest always fails, used
// to prove ExecuteWorkflow preserves the resolved lane on approval failure.
type failingApprover struct{ err error }

func (f failingApprover) ApproveRequest(context.Context, uuid.UUID, uuid.UUID, string, string) error {
	return f.err
}

// TestExecuteWorkflowPreservesDecisionOnApproveError proves that when the
// auto-approve lane's ApproveRequest fails, ExecuteWorkflow still returns the
// resolved decision (which lane the request was routed to) rather than a zero
// WorkflowDecision, so the caller/UI does not lose the routing information.
func TestExecuteWorkflowPreservesDecisionOnApproveError(t *testing.T) {
	wantErr := errors.New("approve boom")
	wf := NewWorkflowService(failingApprover{err: wantErr})
	req := &models.AccessRequest{RiskLevel: RiskLow}
	req.ID = uuid.New()

	dec, err := wf.ExecuteWorkflow(context.Background(), uuid.New(), req, "system")
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected the approve error to propagate, got %v", err)
	}
	if dec.StepType != WorkflowStepAutoApprove {
		t.Fatalf("expected lane preserved as auto_approve, got %q", dec.StepType)
	}
	if dec.Approved {
		t.Fatalf("Approved must stay false when ApproveRequest failed")
	}
}

// TestHandleJoinerAutoProvisionsBaseline proves a SCIM joiner carrying a
// baseline resource+role is not only auto-approved but also provisioned: the
// grant must be materialized on the connector with no human in the loop,
// honoring HandleJoiner's "provisions baseline access" contract.
func TestHandleJoinerAutoProvisionsBaseline(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{}
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })
	jml := NewJMLService(db, reqSvc, NewWorkflowService(reqSvc), prov, fc, &fakeDisabler{})
	ctx := context.Background()

	req, err := jml.HandleJoiner(ctx, ws, SCIMEvent{
		Method:         "POST",
		UserExternalID: "ext-joiner",
		ConnectorID:    &connID,
		ResourceRef:    "app:db",
		Role:           "reader",
	})
	if err != nil {
		t.Fatalf("HandleJoiner: %v", err)
	}
	if req == nil {
		t.Fatal("expected a request for a baseline joiner")
	}
	// Request must have been driven all the way to active (provisioned).
	got, err := reqSvc.GetRequest(ctx, ws, req.ID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if got.State != StateActive {
		t.Fatalf("expected joiner request active after auto-provision, got %s", got.State)
	}
	if fc.provisionCnt != 1 {
		t.Fatalf("expected exactly 1 connector provision, got %d", fc.provisionCnt)
	}
	// A live grant must exist for the joiner.
	var grants int64
	db.Model(&models.AccessGrant{}).
		Where("workspace_id = ? AND iam_core_user_id = ? AND state = ? AND revoked_at IS NULL", ws, "ext-joiner", GrantStateActive).
		Count(&grants)
	if grants != 1 {
		t.Fatalf("expected 1 live grant for joiner, got %d", grants)
	}

	// Redelivery of the same SCIM joiner event must not double-provision
	// (Provision is idempotent: reuses the live grant).
	if _, err := jml.HandleJoiner(ctx, ws, SCIMEvent{
		Method: "POST", UserExternalID: "ext-joiner", ConnectorID: &connID,
		ResourceRef: "app:db", Role: "reader",
	}); err != nil {
		t.Fatalf("HandleJoiner redelivery: %v", err)
	}
	db.Model(&models.AccessGrant{}).
		Where("workspace_id = ? AND iam_core_user_id = ? AND revoked_at IS NULL", ws, "ext-joiner").
		Count(&grants)
	if grants != 1 {
		t.Fatalf("redelivery must not create a second grant, got %d live grants", grants)
	}
}

// TestHandleJoinerBaselineWithoutConnectorFailsFast proves a baseline joiner
// (ResourceRef+Role present) that carries no connector_id is rejected with
// ErrValidation before any request is created — so the SCIM caller gets an
// actionable 422 and, critically, redelivery of the connector-less event can
// never accrete dangling approved-but-unprovisionable requests.
func TestHandleJoinerBaselineWithoutConnectorFailsFast(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{}
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	jml := NewJMLService(db, reqSvc, NewWorkflowService(reqSvc), prov, fc, &fakeDisabler{})
	ctx := context.Background()

	evt := SCIMEvent{Method: "POST", UserExternalID: "ext-joiner", ResourceRef: "app:db", Role: "reader"} // no ConnectorID
	for i := 0; i < 3; i++ {
		req, err := jml.HandleJoiner(ctx, ws, evt)
		if !errors.Is(err, ErrValidation) {
			t.Fatalf("attempt %d: expected ErrValidation for connector-less baseline joiner, got %v", i, err)
		}
		if req != nil {
			t.Fatalf("attempt %d: no request should be created on validation failure, got %v", i, req)
		}
	}

	// No requests and no grants may have been created across the redeliveries.
	var reqCount, grantCount int64
	db.Model(&models.AccessRequest{}).Where("workspace_id = ?", ws).Count(&reqCount)
	db.Model(&models.AccessGrant{}).Where("workspace_id = ?", ws).Count(&grantCount)
	if reqCount != 0 || grantCount != 0 {
		t.Fatalf("connector-less joiner must create nothing, got %d requests and %d grants", reqCount, grantCount)
	}
	if fc.provisionCnt != 0 {
		t.Fatalf("no connector provision should occur, got %d", fc.provisionCnt)
	}
}

// TestOrphanDisableAggregatesRevocationFailures proves the "disable"
// disposition attempts every entitlement and aggregates failures (maximal
// revocation), instead of aborting on the first failed RevokeAccess. The
// disposition must NOT be committed when any revocation fails, so an operator
// re-run can idempotently retry.
func TestOrphanDisableAggregatesRevocationFailures(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	connID := seedConnector(t, db, ws, "fake")
	fc := &fakeConnector{
		entitlements: []access.Entitlement{
			{ResourceExternalID: "res-1", Role: "reader"},
			{ResourceExternalID: "res-2", Role: "reader"},
			{ResourceExternalID: "res-3", Role: "reader"},
		},
		revokeFailFor: map[string]bool{"res-1": true},
	}
	rec := NewOrphanReconciler(db, fc)
	ctx := context.Background()

	orphan := &models.AccessOrphanAccount{
		WorkspaceID:    ws,
		ConnectorID:    connID,
		ExternalUserID: "ext-orphan",
		Disposition:    OrphanDispositionPending,
	}
	if err := db.Create(orphan).Error; err != nil {
		t.Fatalf("seed orphan: %v", err)
	}

	err := rec.SetDisposition(ctx, ws, orphan.ID, OrphanDispositionDisable, "admin")
	if err == nil {
		t.Fatal("expected an aggregated error when a revocation fails")
	}
	// Every entitlement must have been attempted despite res-1 failing first.
	if len(fc.revokedResources) != 3 {
		t.Fatalf("expected all 3 entitlements attempted, got %v", fc.revokedResources)
	}
	// Disposition must remain pending (not committed) so a re-run can retry.
	var reloaded models.AccessOrphanAccount
	db.Where("id = ?", orphan.ID).Take(&reloaded)
	if reloaded.Disposition != OrphanDispositionPending {
		t.Fatalf("disposition must stay pending on failure, got %s", reloaded.Disposition)
	}

	// Clear the failure and re-run: all succeed, disposition commits.
	fc.revokeFailFor = nil
	if err := rec.SetDisposition(ctx, ws, orphan.ID, OrphanDispositionDisable, "admin"); err != nil {
		t.Fatalf("SetDisposition retry: %v", err)
	}
	db.Where("id = ?", orphan.ID).Take(&reloaded)
	if reloaded.Disposition != OrphanDispositionDisable {
		t.Fatalf("expected disable disposition after successful retry, got %s", reloaded.Disposition)
	}
}

// TestSubmitDecisionMissingItemReturnsItemNotFound proves that when the review
// exists but the item id is unknown, SubmitDecision returns the dedicated
// ErrReviewItemNotFound sentinel (not the misleading ErrReviewNotFound).
func TestSubmitDecisionMissingItemReturnsItemNotFound(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	reqSvc := NewAccessRequestService(db)
	fc := &fakeConnector{}
	prov := NewAccessProvisioningService(db, reqSvc, fc)
	rev := NewReviewService(db, prov)
	ctx := context.Background()

	review, _, err := rev.StartCampaign(ctx, ws, "q3-review", "admin")
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}

	err = rev.SubmitDecision(ctx, ws, review.ID, uuid.New(), ReviewDecisionCertify, "auditor", "looks fine")
	if !errors.Is(err, ErrReviewItemNotFound) {
		t.Fatalf("expected ErrReviewItemNotFound for a missing item, got %v", err)
	}
	// A genuinely missing review still returns ErrReviewNotFound.
	err = rev.SubmitDecision(ctx, ws, uuid.New(), uuid.New(), ReviewDecisionCertify, "auditor", "x")
	if !errors.Is(err, ErrReviewNotFound) {
		t.Fatalf("expected ErrReviewNotFound for a missing review, got %v", err)
	}
}

// TestCreatePolicyTxAtomicRollback verifies the transactional primitive that
// policy-pack Apply relies on: several CreatePolicyTx calls in one Transaction
// are all-or-nothing. A valid draft followed by an invalid one must leave zero
// persisted policies (and no orphaned audit rows), not a partial set.
func TestCreatePolicyTxAtomicRollback(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-tx")
	svc := NewPolicyService(db)
	ctx := context.Background()

	def := json.RawMessage(`{"action":"grant","subjects":["g:eng"],"resources":["sys:db"]}`)
	err := svc.Transaction(ctx, func(tx *gorm.DB) error {
		if _, err := svc.CreatePolicyTx(ctx, tx, CreatePolicyInput{
			WorkspaceID: ws, Name: "first-ok", Definition: def, Actor: "admin",
		}); err != nil {
			return err
		}
		// Second insert fails validation (empty name) after the first succeeded.
		_, err := svc.CreatePolicyTx(ctx, tx, CreatePolicyInput{
			WorkspaceID: ws, Name: "", Definition: def, Actor: "admin",
		})
		return err
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation, got %v", err)
	}

	rows, err := svc.ListPolicies(ctx, ws)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected rollback to leave 0 policies, got %d", len(rows))
	}

	var auditCount int64
	if err := db.Model(&models.AuditEvent{}).Where("workspace_id = ?", ws).Count(&auditCount).Error; err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if auditCount != 0 {
		t.Fatalf("expected rollback to leave 0 audit rows, got %d", auditCount)
	}
}
