package pam

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// --- test harness ---------------------------------------------------------

// testDEK is a deterministic 32-byte AES-256 key (base64) for the static
// EnvelopeEncryptor used in tests.
var testDEK = base64.StdEncoding.EncodeToString(make([]byte, 32))

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("auto-migrate: %v", err)
	}
	return db
}

func newTestEncryptor(t *testing.T) access.CredentialEncryptor {
	t.Helper()
	enc, err := access.CredentialEncryptorFromKey(testDEK)
	if err != nil {
		t.Fatalf("encryptor: %v", err)
	}
	return enc
}

func seedWorkspace(t *testing.T, db *gorm.DB, tenant string) uuid.UUID {
	t.Helper()
	ws := &models.Workspace{Name: tenant, IAMCoreTenantID: tenant, Plan: "base"}
	if err := db.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	return ws.ID
}

func seedDenyPolicy(t *testing.T, db *gorm.DB, workspaceID uuid.UUID, name string, subjects, resources []string) {
	t.Helper()
	body := mustJSON(t, map[string]any{
		"action":    "deny",
		"subjects":  subjects,
		"resources": resources,
	})
	p := &models.Policy{
		WorkspaceID: workspaceID,
		Name:        name,
		State:       "active",
		Definition:  datatypes.JSON(body),
	}
	if err := db.Create(p).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return b
}

// fakeValidator is an in-memory TokenValidator: it maps a raw token string to
// the claims it should validate to, so step-up tests need no live iam-core.
type fakeValidator struct {
	claims map[string]*iamcore.Claims
	err    error
}

func (f fakeValidator) Validate(token string) (*iamcore.Claims, error) {
	if f.err != nil {
		return nil, f.err
	}
	c, ok := f.claims[token]
	if !ok {
		return nil, errors.New("unknown token")
	}
	return c, nil
}

// --- vault tests ----------------------------------------------------------

func TestVaultSealOpenRoundTrip(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)

	target, err := v.CreateTarget(context.Background(), CreateTargetInput{
		WorkspaceID: ws,
		Name:        "db-prod",
		Protocol:    models.PAMProtocolPostgres,
		Address:     "db.internal:5432",
		Username:    "app",
		Secret:      Secret{Username: "app", Password: "s3cr3t"},
		Actor:       "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	if target.SecretEnvelope == "" {
		t.Fatal("expected sealed envelope, got empty")
	}
	if target.SecretEnvelope == "s3cr3t" {
		t.Fatal("secret stored in plaintext")
	}

	sec, err := v.OpenSecret(context.Background(), target)
	if err != nil {
		t.Fatalf("OpenSecret: %v", err)
	}
	if sec.Password != "s3cr3t" || sec.Username != "app" {
		t.Fatalf("round-trip mismatch: %+v", sec)
	}
}

// TestVaultAADBinding proves the envelope is bound to the target's row id: an
// envelope copied to a different target id fails to open (AES-GCM AAD mismatch).
func TestVaultAADBinding(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)

	target, err := v.CreateTarget(context.Background(), CreateTargetInput{
		WorkspaceID: ws, Name: "ssh-box", Protocol: models.PAMProtocolSSH,
		Address: "host:22", Secret: Secret{Password: "pw"}, Actor: "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}

	// Forge a sibling target row carrying the first target's ciphertext but its
	// own (different) id. Opening must fail because the AAD no longer matches.
	forged := *target
	forged.ID = uuid.New()
	if _, err := v.OpenSecret(context.Background(), &forged); err == nil {
		t.Fatal("expected AAD mismatch error opening copied envelope, got nil")
	}
}

// TestCreateTargetIdempotent proves target registration is safely re-runnable.
// Re-registering the identical target (same name + protocol + address) returns
// the existing row with created=false and never duplicates, so a bootstrapper
// can re-run without hitting the uq_pam_targets_name unique index. Re-using the
// name for a *different* upstream is a typed ErrTargetExists conflict (a clean
// 409 at the handler) rather than a raw unique-violation 500, and must not
// shadow or mutate the existing target.
func TestCreateTargetIdempotent(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	ctx := context.Background()

	in := CreateTargetInput{
		WorkspaceID: ws, Name: "db-prod", Protocol: models.PAMProtocolPostgres,
		Address: "db.internal:5432", Username: "app",
		Secret: Secret{Username: "app", Password: "s3cr3t"}, Actor: "admin",
	}

	first, created, err := v.CreateOrGetTarget(ctx, in)
	if err != nil || !created {
		t.Fatalf("first create: created=%v err=%v", created, err)
	}

	// Re-register the identical target: no error, no duplicate, same row, reused.
	second, created, err := v.CreateOrGetTarget(ctx, in)
	if err != nil {
		t.Fatalf("re-register identical: %v", err)
	}
	if created {
		t.Fatal("re-register of an identical target should reuse, got created=true")
	}
	if second.ID != first.ID {
		t.Fatalf("re-register returned a different row: %s != %s", second.ID, first.ID)
	}
	if rows, err := v.ListTargets(ctx, ws, 200); err != nil {
		t.Fatalf("ListTargets: %v", err)
	} else if len(rows) != 1 {
		t.Fatalf("expected exactly 1 target after re-register, got %d", len(rows))
	}

	// Re-register the SAME upstream but with a drifted security-relevant field
	// (require_mfa) is NOT silently converged: a create must never mutate — and
	// here would *downgrade* — an existing privileged target, since a value-typed
	// re-POST can't tell an omitted require_mfa from an intentional false. It's a
	// typed conflict the caller must resolve via an explicit update, and the
	// stored target must stay untouched.
	drift := in
	drift.RequireMFA = boolPtr(true)
	drift.LeaseTTL = 30 * time.Minute
	drift.Username = "app-rotated"
	if _, _, err := v.CreateOrGetTarget(ctx, drift); !errors.Is(err, ErrTargetExists) {
		t.Fatalf("want ErrTargetExists for a drifted re-register, got %v", err)
	}
	// The original target is unchanged: re-registering the IDENTICAL spec still
	// reuses the row and the security flag is still its original value.
	if cur, created, err := v.CreateOrGetTarget(ctx, in); err != nil || created || cur.ID != first.ID || cur.RequireMFA {
		t.Fatalf("drifted re-register mutated the target: id=%s created=%v require_mfa=%v err=%v",
			cur.ID, created, cur.RequireMFA, err)
	}
	if rows, err := v.ListTargets(ctx, ws, 200); err != nil {
		t.Fatalf("ListTargets: %v", err)
	} else if len(rows) != 1 {
		t.Fatalf("drifted re-register must not duplicate the target, got %d", len(rows))
	}
	// The denied conflict leaves a security audit trail (the pure reuse above
	// deliberately does not), recording the existing target and which fields the
	// re-register tried to change.
	var denied int64
	db.Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND action = ? AND target_ref = ?", ws, "pam.target.register_denied", first.ID.String()).
		Count(&denied)
	if denied != 1 {
		t.Fatalf("want exactly 1 pam.target.register_denied audit row, got %d", denied)
	}

	// Same name pointed at a different upstream → conflict, not a silent shadow.
	conflict := in
	conflict.Protocol = models.PAMProtocolSSH
	conflict.Address = "other.internal:22"
	if _, _, err := v.CreateOrGetTarget(ctx, conflict); !errors.Is(err, ErrTargetExists) {
		t.Fatalf("want ErrTargetExists for name reuse with a different upstream, got %v", err)
	}
	if rows, err := v.ListTargets(ctx, ws, 200); err != nil {
		t.Fatalf("ListTargets: %v", err)
	} else if len(rows) != 1 {
		t.Fatalf("conflict attempt mutated the target set: got %d", len(rows))
	}

	// CreateTarget (the bool-discarding wrapper) stays idempotent too.
	if w, err := v.CreateTarget(ctx, in); err != nil || w.ID != first.ID {
		t.Fatalf("CreateTarget wrapper not idempotent: id=%v err=%v", w, err)
	}

	// require_mfa tri-state: create an MFA-gated target, then prove an OMITTED
	// require_mfa is "no opinion" (clean reuse, no 409, no downgrade) while an
	// EXPLICIT false is a conflict the caller must resolve via an update — a
	// create can never silently drop the gate.
	gated := CreateTargetInput{
		WorkspaceID: ws, Name: "db-gated", Protocol: models.PAMProtocolPostgres,
		Address: "db.internal:5432", Username: "app", RequireMFA: boolPtr(true),
		Secret: Secret{Username: "app", Password: "s3cr3t"}, Actor: "admin",
	}
	g, created, err := v.CreateOrGetTarget(ctx, gated)
	if err != nil || !created || !g.RequireMFA {
		t.Fatalf("create gated target: created=%v require_mfa=%v err=%v", created, g.RequireMFA, err)
	}
	// Re-register omitting require_mfa, otherwise identical → reuse, gate intact.
	omitted := gated
	omitted.RequireMFA = nil
	if reuse, created, err := v.CreateOrGetTarget(ctx, omitted); err != nil || created || reuse.ID != g.ID || !reuse.RequireMFA {
		t.Fatalf("omitted require_mfa should reuse without downgrade: id=%s created=%v require_mfa=%v err=%v",
			reuse.ID, created, reuse.RequireMFA, err)
	}
	// Re-register with an EXPLICIT require_mfa=false → conflict, gate still on.
	downgrade := gated
	downgrade.RequireMFA = boolPtr(false)
	if _, _, err := v.CreateOrGetTarget(ctx, downgrade); !errors.Is(err, ErrTargetExists) {
		t.Fatalf("explicit require_mfa=false must 409, never silently downgrade, got %v", err)
	}
	if cur, err := v.GetTarget(ctx, ws, g.ID); err != nil || !cur.RequireMFA {
		t.Fatalf("gate was downgraded: require_mfa=%v err=%v", cur.RequireMFA, err)
	}
}

// boolPtr returns a pointer to b, for setting the tri-state CreateTargetInput
// RequireMFA in tests (nil = omitted/no-opinion, non-nil = explicit).
func boolPtr(b bool) *bool { return &b }

func TestVaultRevealRequiresStepUpWhenMFAGated(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")

	now := time.Now()
	gate := NewStepUpGate(fakeValidator{claims: map[string]*iamcore.Claims{
		"good": {Subject: "alice", TenantID: "tenant-a", MFASatisfied: true, Raw: map[string]any{"auth_time": float64(now.Unix())}},
	}}, time.Minute)
	gate.SetClock(func() time.Time { return now })

	v := NewVault(db, newTestEncryptor(t), gate)
	target, err := v.CreateTarget(context.Background(), CreateTargetInput{
		WorkspaceID: ws, Name: "vault-box", Protocol: models.PAMProtocolSSH,
		Address: "host:22", RequireMFA: boolPtr(true), Secret: Secret{Password: "pw"}, Actor: "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}

	// No step-up token → required error.
	if _, err := v.RevealSecret(context.Background(), ws, target.ID, "alice", ""); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("want ErrStepUpRequired, got %v", err)
	}
	// Valid step-up token → success.
	sec, err := v.RevealSecret(context.Background(), ws, target.ID, "alice", "good")
	if err != nil {
		t.Fatalf("RevealSecret with valid step-up: %v", err)
	}
	if sec.Password != "pw" {
		t.Fatalf("revealed secret mismatch: %+v", sec)
	}
}

// TestVaultRevealFailsClosedWithoutGate proves an MFA-gated target cannot be
// revealed when no step-up gate is configured.
func TestVaultRevealFailsClosedWithoutGate(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil) // no gate

	target, err := v.CreateTarget(context.Background(), CreateTargetInput{
		WorkspaceID: ws, Name: "vault-box", Protocol: models.PAMProtocolSSH,
		Address: "host:22", RequireMFA: boolPtr(true), Secret: Secret{Password: "pw"}, Actor: "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	if _, err := v.RevealSecret(context.Background(), ws, target.ID, "alice", "anything"); !errors.Is(err, ErrStepUpInvalid) {
		t.Fatalf("want ErrStepUpInvalid (fail-closed), got %v", err)
	}
}

// fakeAuditor records the standalone audit appends routed to it so a unit test
// can assert the Vault dispatches through the injected auditor (the pgxpool
// PgxAuditRepo in production) instead of the GORM lifecycle fallback. It also
// lets the test force an append failure. Even though standaloneAuditor is
// unexported, the exported SetAuditor accepts any value implementing
// AppendAudit, so the pgx routing path is unit-testable without Postgres.
type fakeAuditor struct {
	calls []database.AuditInput
	err   error
}

func (f *fakeAuditor) AppendAudit(_ context.Context, _ time.Time, in database.AuditInput) error {
	f.calls = append(f.calls, in)
	return f.err
}

// TestVaultRevealRoutesThroughInjectedAuditor proves the standalone audit path
// is wired end to end: with an auditor set, RevealSecret appends the
// pam.secret.revealed event through it (not the GORM fallback) with the exact
// AuditInput the pgx adapter will persist, and an auditor failure fails the
// reveal closed — a secret is never returned without its audit event recorded.
func TestVaultRevealRoutesThroughInjectedAuditor(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)

	target, err := v.CreateTarget(context.Background(), CreateTargetInput{
		WorkspaceID: ws, Name: "db-prod", Protocol: models.PAMProtocolPostgres,
		Address: "db.internal:5432", Username: "app",
		Secret: Secret{Username: "app", Password: "s3cr3t"}, Actor: "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}

	// Wire the auditor AFTER CreateTarget so its (in-transaction, GORM) audit
	// does not count: only the standalone reveal append should reach the fake.
	auditor := &fakeAuditor{}
	v.SetAuditor(auditor)

	if _, err := v.RevealSecret(context.Background(), ws, target.ID, "alice", ""); err != nil {
		t.Fatalf("RevealSecret: %v", err)
	}
	if len(auditor.calls) != 1 {
		t.Fatalf("want exactly 1 standalone append through the injected auditor, got %d", len(auditor.calls))
	}
	got := auditor.calls[0]
	if got.WorkspaceID != ws || got.Actor != "alice" || got.Action != "pam.secret.revealed" || got.TargetRef != target.ID.String() {
		t.Fatalf("audit input mismatch: %+v", got)
	}
	if len(got.Metadata) == 0 {
		t.Fatal("expected metadata JSON on the reveal audit event")
	}

	auditor.err = errors.New("append failed")
	if _, err := v.RevealSecret(context.Background(), ws, target.ID, "alice", ""); err == nil {
		t.Fatal("expected RevealSecret to fail closed when the auditor append fails")
	}
}

func TestVaultGetTargetIsWorkspaceScoped(t *testing.T) {
	db := newTestDB(t)
	wsA := seedWorkspace(t, db, "tenant-a")
	wsB := seedWorkspace(t, db, "tenant-b")
	v := NewVault(db, newTestEncryptor(t), nil)

	target, err := v.CreateTarget(context.Background(), CreateTargetInput{
		WorkspaceID: wsA, Name: "box", Protocol: models.PAMProtocolSSH,
		Address: "host:22", Secret: Secret{Password: "pw"}, Actor: "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	// Reading target from another workspace must look like "not found".
	if _, err := v.GetTarget(context.Background(), wsB, target.ID); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("cross-tenant read: want ErrTargetNotFound, got %v", err)
	}
}

func TestVaultRotateSecret(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)

	target, err := v.CreateTarget(context.Background(), CreateTargetInput{
		WorkspaceID: ws, Name: "box", Protocol: models.PAMProtocolSSH,
		Address: "host:22", Secret: Secret{Password: "old"}, Actor: "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	if err := v.RotateSecret(context.Background(), ws, target.ID, Secret{Password: "new"}, "admin"); err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	reloaded, err := v.GetTarget(context.Background(), ws, target.ID)
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	sec, err := v.OpenSecret(context.Background(), reloaded)
	if err != nil {
		t.Fatalf("OpenSecret: %v", err)
	}
	if sec.Password != "new" {
		t.Fatalf("rotation did not take effect: %+v", sec)
	}
	if reloaded.SecretRotatedAt == nil {
		t.Fatal("SecretRotatedAt not stamped")
	}
}

// --- connect-token tests --------------------------------------------------

func TestConnectTokenOneShotRedemption(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	broker := NewBroker(db, v, nil)

	target, err := v.CreateTarget(context.Background(), CreateTargetInput{
		WorkspaceID: ws, Name: "box", Protocol: models.PAMProtocolSSH,
		Address: "host:22", Secret: Secret{Password: "pw"}, Actor: "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	raw, _, err := broker.MintConnectToken(context.Background(), MintInput{
		WorkspaceID: ws, TargetID: target.ID, Subject: "alice", Actor: "admin",
	})
	if err != nil {
		t.Fatalf("MintConnectToken: %v", err)
	}

	leased, err := broker.RedeemConnectToken(context.Background(), raw, "1.2.3.4:5555")
	if err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	if leased.Secret.Password != "pw" {
		t.Fatalf("leased secret mismatch: %+v", leased.Secret)
	}
	if leased.Session == nil || leased.Session.State != models.PAMSessionActive {
		t.Fatal("expected an active session after redemption")
	}

	// The session-opened event is appended atomically with the redemption.
	var opened int64
	db.Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND action = ? AND target_ref = ?", ws, "pam.session.opened", target.ID.String()).
		Count(&opened)
	if opened != 1 {
		t.Fatalf("want 1 pam.session.opened audit row, got %d", opened)
	}

	// Second redemption of the same token must fail (one-shot, replay-safe).
	if _, err := broker.RedeemConnectToken(context.Background(), raw, "1.2.3.4:5556"); !errors.Is(err, ErrConnectToken) {
		t.Fatalf("replay redeem: want ErrConnectToken, got %v", err)
	}
}

func TestConnectTokenExpiry(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	broker := NewBroker(db, v, nil)

	base := time.Now()
	broker.SetClock(func() time.Time { return base })

	target, err := v.CreateTarget(context.Background(), CreateTargetInput{
		WorkspaceID: ws, Name: "box", Protocol: models.PAMProtocolSSH,
		Address: "host:22", LeaseTTL: 30 * time.Second,
		Secret: Secret{Password: "pw"}, Actor: "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	raw, _, err := broker.MintConnectToken(context.Background(), MintInput{
		WorkspaceID: ws, TargetID: target.ID, Subject: "alice", Actor: "admin",
	})
	if err != nil {
		t.Fatalf("MintConnectToken: %v", err)
	}

	// Advance past the lease window: redemption must fail as expired.
	broker.SetClock(func() time.Time { return base.Add(time.Minute) })
	if _, err := broker.RedeemConnectToken(context.Background(), raw, "1.2.3.4:5555"); !errors.Is(err, ErrConnectToken) {
		t.Fatalf("expired redeem: want ErrConnectToken, got %v", err)
	}
}

func TestConnectTokenUnknownRejected(t *testing.T) {
	db := newTestDB(t)
	v := NewVault(db, newTestEncryptor(t), nil)
	broker := NewBroker(db, v, nil)
	if _, err := broker.RedeemConnectToken(context.Background(), "not-a-real-token", "x"); !errors.Is(err, ErrConnectToken) {
		t.Fatalf("unknown token: want ErrConnectToken, got %v", err)
	}
}

// --- command-policy tests -------------------------------------------------

func TestCommandPolicyDenyGlob(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	seedDenyPolicy(t, db, ws, "no-drops", []string{"*"}, []string{"cmd:*drop table*"})

	eval := NewCommandPolicyEvaluator(db, time.Millisecond)

	deny, err := eval.Evaluate(context.Background(), ws, "alice", "DROP TABLE users;")
	if err != nil {
		t.Fatalf("Evaluate deny: %v", err)
	}
	if deny.Allowed() {
		t.Fatalf("expected deny for DROP TABLE, got %+v", deny)
	}

	allow, err := eval.Evaluate(context.Background(), ws, "alice", "SELECT 1;")
	if err != nil {
		t.Fatalf("Evaluate allow: %v", err)
	}
	if !allow.Allowed() {
		t.Fatalf("expected allow for SELECT, got %+v", allow)
	}
}

func TestCommandPolicySubjectScoped(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	seedDenyPolicy(t, db, ws, "bob-no-rm", []string{"bob"}, []string{"cmd:rm -rf*"})

	eval := NewCommandPolicyEvaluator(db, time.Millisecond)

	// Denied for bob.
	d, _ := eval.Evaluate(context.Background(), ws, "bob", "rm -rf /")
	if d.Allowed() {
		t.Fatal("expected deny for bob")
	}
	// Allowed for alice (rule is subject-scoped to bob).
	a, _ := eval.Evaluate(context.Background(), ws, "alice", "rm -rf /")
	if !a.Allowed() {
		t.Fatal("expected allow for alice (not in rule subjects)")
	}
}

func TestCommandPolicyEmptyCommandAllowed(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	eval := NewCommandPolicyEvaluator(db, time.Second)
	d, err := eval.Evaluate(context.Background(), ws, "alice", "   ")
	if err != nil || !d.Allowed() {
		t.Fatalf("empty command should be allowed, got %+v err=%v", d, err)
	}
}

// TestCommandPolicyCacheSizeBoundedLRU verifies the rule cache enforces a hard
// entry cap by evicting the least-recently-used workspace, so a gateway serving
// many concurrent distinct workspaces within one TTL window cannot grow the
// cache without bound.
func TestCommandPolicyCacheSizeBoundedLRU(t *testing.T) {
	db := newTestDB(t)
	// Long TTL so nothing expires during the test: this forces the size-cap
	// LRU path rather than the expiry-eviction path.
	eval := NewCommandPolicyEvaluator(db, time.Hour)
	eval.maxEntries = 3

	clk := time.Unix(0, 0)
	eval.SetClock(func() time.Time { return clk })

	ws1, ws2, ws3, ws4 := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	advanceEval := func(ws uuid.UUID) {
		clk = clk.Add(time.Second)
		if _, err := eval.Evaluate(context.Background(), ws, "alice", "SELECT 1;"); err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
	}

	advanceEval(ws1) // fill
	advanceEval(ws2)
	advanceEval(ws3) // cache now full at the cap
	advanceEval(ws1) // touch ws1 so ws2 is the LRU
	advanceEval(ws4) // miss → must evict LRU (ws2) to stay at the cap

	eval.mu.Lock()
	defer eval.mu.Unlock()
	if len(eval.cache) != 3 {
		t.Fatalf("cache size = %d, want hard cap of 3", len(eval.cache))
	}
	if _, ok := eval.cache[ws2]; ok {
		t.Fatal("ws2 should have been evicted as least-recently-used")
	}
	for _, ws := range []uuid.UUID{ws1, ws3, ws4} {
		if _, ok := eval.cache[ws]; !ok {
			t.Fatalf("expected workspace %s to remain cached", ws)
		}
	}
}

// --- session-manager tests ------------------------------------------------

func TestSessionManagerLogsCommandAndDecision(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	seedDenyPolicy(t, db, ws, "no-drops", []string{"*"}, []string{"cmd:*drop*"})
	eval := NewCommandPolicyEvaluator(db, time.Millisecond)
	mgr := NewSessionManager(db, eval, nil)

	session := &models.PAMSession{
		WorkspaceID: ws, TargetID: uuid.New(), Subject: "alice",
		Protocol: models.PAMProtocolPostgres, State: models.PAMSessionActive,
		StartedAt: time.Now(),
	}
	session.ID = uuid.New()

	d1, err := mgr.LogCommand(context.Background(), session, "SELECT 1;")
	if err != nil {
		t.Fatalf("LogCommand allow: %v", err)
	}
	if !d1.Allowed() {
		t.Fatal("expected allow")
	}
	d2, err := mgr.LogCommand(context.Background(), session, "DROP TABLE t;")
	if err != nil {
		t.Fatalf("LogCommand deny: %v", err)
	}
	if d2.Allowed() {
		t.Fatal("expected deny")
	}

	// Two command rows, monotonically increasing seq, decisions recorded.
	var rows []models.PAMSessionCommand
	if err := db.Where("session_id = ?", session.ID).Order("seq asc").Find(&rows).Error; err != nil {
		t.Fatalf("load commands: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 command rows, got %d", len(rows))
	}
	if rows[0].Seq != 1 || rows[1].Seq != 2 {
		t.Fatalf("seq not monotonic: %d, %d", rows[0].Seq, rows[1].Seq)
	}
	if rows[1].Decision != models.PAMDecisionDeny {
		t.Fatalf("second command should be denied, got %q", rows[1].Decision)
	}

	// Each command also lands in the audit chain.
	var auditCount int64
	db.Model(&models.AuditEvent{}).Where("workspace_id = ? AND action = ?", ws, "pam.command").Count(&auditCount)
	if auditCount != 2 {
		t.Fatalf("want 2 audit rows, got %d", auditCount)
	}
}

func TestSessionManagerTerminateInvokesController(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	broker := NewBroker(db, v, nil)
	target, err := v.CreateTarget(context.Background(), CreateTargetInput{
		WorkspaceID: ws, Name: "box", Protocol: models.PAMProtocolSSH,
		Address: "host:22", Secret: Secret{Password: "pw"}, Actor: "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	raw, _, err := broker.MintConnectToken(context.Background(), MintInput{WorkspaceID: ws, TargetID: target.ID, Subject: "alice", Actor: "admin"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	leased, err := broker.RedeemConnectToken(context.Background(), raw, "x")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}

	ctrl := &fakeController{}
	mgr := NewSessionManager(db, nil, ctrl)
	if err := mgr.TerminateSession(context.Background(), ws, leased.Session.ID, "admin-bob"); err != nil {
		t.Fatalf("TerminateSession: %v", err)
	}
	if !ctrl.terminated {
		t.Fatal("controller Terminate was not invoked")
	}
	var reloaded models.PAMSession
	if err := db.Where("id = ?", leased.Session.ID).Take(&reloaded).Error; err != nil {
		t.Fatalf("reload session: %v", err)
	}
	if reloaded.State != models.PAMSessionTerminated || reloaded.TerminatedBy != "admin-bob" {
		t.Fatalf("session not marked terminated: %+v", reloaded)
	}
}

// Pausing a session that is no longer active is a state-machine conflict, not a
// malformed request: setPause must return ErrSessionNotActive (which the HTTP
// edge maps to 409 Conflict), not the generic ErrValidation (400).
func TestSessionManagerPauseNonActiveIsConflict(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	broker := NewBroker(db, v, nil)
	target, err := v.CreateTarget(context.Background(), CreateTargetInput{
		WorkspaceID: ws, Name: "box", Protocol: models.PAMProtocolSSH,
		Address: "host:22", Secret: Secret{Password: "pw"}, Actor: "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	raw, _, err := broker.MintConnectToken(context.Background(), MintInput{WorkspaceID: ws, TargetID: target.ID, Subject: "alice", Actor: "admin"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	leased, err := broker.RedeemConnectToken(context.Background(), raw, "x")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}

	mgr := NewSessionManager(db, nil, nil)
	if err := mgr.TerminateSession(context.Background(), ws, leased.Session.ID, "admin-bob"); err != nil {
		t.Fatalf("TerminateSession: %v", err)
	}

	err = mgr.PauseSession(context.Background(), ws, leased.Session.ID, "admin-bob")
	if !errors.Is(err, ErrSessionNotActive) {
		t.Fatalf("pause terminated session: want ErrSessionNotActive, got %v", err)
	}
	if errors.Is(err, ErrValidation) {
		t.Fatal("pause of non-active session must not be ErrValidation (would map to 400, not 409)")
	}
}

func TestSessionManagerCloseIsIdempotentAuditOnce(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	broker := NewBroker(db, v, nil)
	target, err := v.CreateTarget(context.Background(), CreateTargetInput{
		WorkspaceID: ws, Name: "box", Protocol: models.PAMProtocolSSH,
		Address: "host:22", Secret: Secret{Password: "pw"}, Actor: "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	raw, _, err := broker.MintConnectToken(context.Background(), MintInput{WorkspaceID: ws, TargetID: target.ID, Subject: "alice", Actor: "admin"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	leased, err := broker.RedeemConnectToken(context.Background(), raw, "x")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}

	mgr := NewSessionManager(db, nil, nil)
	// Close twice, then terminate: only the first transition should flip the
	// row and append a chain entry; the later calls must be no-ops.
	for i := 0; i < 2; i++ {
		if err := mgr.CloseSession(context.Background(), ws, leased.Session.ID); err != nil {
			t.Fatalf("CloseSession #%d: %v", i, err)
		}
	}
	if err := mgr.TerminateSession(context.Background(), ws, leased.Session.ID, "admin-bob"); err != nil {
		t.Fatalf("TerminateSession after close: %v", err)
	}

	var closedAudits int64
	if err := db.Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND action = ?", ws, "pam.session.closed").
		Count(&closedAudits).Error; err != nil {
		t.Fatalf("count closed audits: %v", err)
	}
	if closedAudits != 1 {
		t.Fatalf("expected exactly 1 pam.session.closed audit entry, got %d", closedAudits)
	}
	// The terminate after close must not have produced a terminated entry,
	// because the session was already closed (state != active).
	var termAudits int64
	if err := db.Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND action = ?", ws, "pam.session.terminated").
		Count(&termAudits).Error; err != nil {
		t.Fatalf("count terminated audits: %v", err)
	}
	if termAudits != 0 {
		t.Fatalf("expected 0 pam.session.terminated audit entries (already closed), got %d", termAudits)
	}
}

// TestLogCommandSeqUniqueConstraintEnforced proves the per-session monotonic
// counter invariant is enforced at the database layer: two command rows cannot
// share a (workspace_id, session_id, seq). This is what lets LogCommand retry a
// concurrent seq collision (e.g. parallel SSH channels) instead of silently
// writing a duplicate.
func TestLogCommandSeqUniqueConstraintEnforced(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	sessionID := uuid.New()

	first := &models.PAMSessionCommand{
		WorkspaceID: ws, SessionID: sessionID, Seq: 1, Command: "a", Decision: models.PAMDecisionAllow,
	}
	if err := db.Create(first).Error; err != nil {
		t.Fatalf("insert first command: %v", err)
	}
	dup := &models.PAMSessionCommand{
		WorkspaceID: ws, SessionID: sessionID, Seq: 1, Command: "b", Decision: models.PAMDecisionAllow,
	}
	err := db.Create(dup).Error
	if !errors.Is(err, gorm.ErrDuplicatedKey) {
		t.Fatalf("expected gorm.ErrDuplicatedKey on duplicate (session_id, seq), got %v", err)
	}
}

// TestLogCommandContinuesSeqAfterPriorRow verifies LogCommand reads MAX(seq) and
// assigns the next value rather than colliding when a row already exists for the
// session — the normal (non-racing) path that the unique constraint guards.
func TestLogCommandContinuesSeqAfterPriorRow(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	mgr := NewSessionManager(db, nil, nil)
	session := &models.PAMSession{
		WorkspaceID: ws, TargetID: uuid.New(), Subject: "alice",
		Protocol: models.PAMProtocolSSH, State: models.PAMSessionActive, StartedAt: time.Now(),
	}
	session.ID = uuid.New()

	// Seed seq=1 directly, then let LogCommand allocate the next.
	seed := &models.PAMSessionCommand{WorkspaceID: ws, SessionID: session.ID, Seq: 1, Command: "seed", Decision: models.PAMDecisionAllow}
	if err := db.Create(seed).Error; err != nil {
		t.Fatalf("seed command: %v", err)
	}
	if _, err := mgr.LogCommand(context.Background(), session, "whoami"); err != nil {
		t.Fatalf("LogCommand: %v", err)
	}
	var rows []models.PAMSessionCommand
	if err := db.Where("session_id = ?", session.ID).Order("seq asc").Find(&rows).Error; err != nil {
		t.Fatalf("load commands: %v", err)
	}
	if len(rows) != 2 || rows[0].Seq != 1 || rows[1].Seq != 2 {
		t.Fatalf("want seq 1,2; got %+v", rows)
	}
	if rows[1].Command != "whoami" {
		t.Fatalf("unexpected second command: %q", rows[1].Command)
	}
}

type fakeController struct {
	terminated bool
	paused     bool
}

func (f *fakeController) Terminate(uuid.UUID) bool { f.terminated = true; return true }
func (f *fakeController) Pause(uuid.UUID) bool     { f.paused = true; return true }
func (f *fakeController) Resume(uuid.UUID) bool    { f.paused = false; return true }

// --- step-up gate tests ---------------------------------------------------

func TestStepUpGateValidation(t *testing.T) {
	now := time.Now()
	val := fakeValidator{claims: map[string]*iamcore.Claims{
		"fresh-mfa":   {Subject: "alice", TenantID: "tenant-a", MFASatisfied: true, Raw: map[string]any{"auth_time": float64(now.Unix())}},
		"no-mfa":      {Subject: "alice", TenantID: "tenant-a", MFASatisfied: false, Raw: map[string]any{"auth_time": float64(now.Unix())}},
		"wrong-sub":   {Subject: "mallory", TenantID: "tenant-a", MFASatisfied: true, Raw: map[string]any{"auth_time": float64(now.Unix())}},
		"wrong-ten":   {Subject: "alice", TenantID: "tenant-b", MFASatisfied: true, Raw: map[string]any{"auth_time": float64(now.Unix())}},
		"stale":       {Subject: "alice", TenantID: "tenant-a", MFASatisfied: true, Raw: map[string]any{"auth_time": float64(now.Add(-time.Hour).Unix())}},
		"no-authtime": {Subject: "alice", TenantID: "tenant-a", MFASatisfied: true, Raw: map[string]any{}},
	}}
	gate := NewStepUpGate(val, 5*time.Minute)
	gate.SetClock(func() time.Time { return now })

	cases := []struct {
		name    string
		token   string
		wantErr error
	}{
		{"valid", "fresh-mfa", nil},
		{"missing", "", ErrStepUpRequired},
		{"no mfa claim", "no-mfa", ErrStepUpInvalid},
		{"subject mismatch", "wrong-sub", ErrStepUpInvalid},
		{"tenant mismatch", "wrong-ten", ErrStepUpInvalid},
		{"stale", "stale", ErrStepUpInvalid},
		{"no auth_time", "no-authtime", ErrStepUpInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := gate.Require("alice", "tenant-a", tc.token)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("want nil, got %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestStepUpGateDisabledFailsClosed(t *testing.T) {
	var gate *StepUpGate // nil gate
	if gate.Enabled() {
		t.Fatal("nil gate must not be enabled")
	}
	g2 := NewStepUpGate(nil, time.Minute) // no validator
	if g2.Enabled() {
		t.Fatal("gate without validator must not be enabled")
	}
	if err := g2.Require("alice", "tenant-a", "tok"); !errors.Is(err, ErrStepUpInvalid) {
		t.Fatalf("want ErrStepUpInvalid, got %v", err)
	}
}
