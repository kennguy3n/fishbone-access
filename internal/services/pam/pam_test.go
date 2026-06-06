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
		Address: "host:22", RequireMFA: true, Secret: Secret{Password: "pw"}, Actor: "admin",
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
		Address: "host:22", RequireMFA: true, Secret: Secret{Password: "pw"}, Actor: "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	if _, err := v.RevealSecret(context.Background(), ws, target.ID, "alice", "anything"); !errors.Is(err, ErrStepUpInvalid) {
		t.Fatalf("want ErrStepUpInvalid (fail-closed), got %v", err)
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

type fakeController struct{ terminated bool }

func (f *fakeController) Terminate(uuid.UUID) bool { f.terminated = true; return true }

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
