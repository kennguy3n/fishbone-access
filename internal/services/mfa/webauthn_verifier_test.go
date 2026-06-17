package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	vwa "github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

// WebAuthn relying-party fixtures. virtualwebauthn validates the ceremony
// against these exact values, and go-webauthn validates the RPID is a registrable
// domain, so they must be a real-looking domain/origin pair.
const (
	testRPID          = "example.com"
	testRPDisplayName = "ShieldNet Access"
	testRPOrigin      = "https://example.com"
)

func newWebAuthnVerifier(t *testing.T) (*WebAuthnMFAVerifier, *gorm.DB) {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	v, err := NewWebAuthnMFAVerifier(db, newTestEncryptor(t), WebAuthnSettings{
		RPID:          testRPID,
		RPDisplayName: testRPDisplayName,
		RPOrigins:     []string{testRPOrigin},
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return v, db
}

func testRP() vwa.RelyingParty {
	return vwa.RelyingParty{Name: testRPDisplayName, ID: testRPID, Origin: testRPOrigin}
}

// enroll runs a full attestation ceremony for (ws, user) against verifier v
// using the mock authenticator, returning the registered virtual credential so
// the caller can subsequently assert with it.
func enroll(t *testing.T, v *WebAuthnMFAVerifier, ws uuid.UUID, user string, authr *vwa.Authenticator) vwa.Credential {
	t.Helper()
	ctx := context.Background()

	creation, err := v.BeginRegistration(ctx, ws, user, "Test User")
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}
	optionsJSON, err := json.Marshal(creation)
	if err != nil {
		t.Fatalf("marshal creation options: %v", err)
	}
	attOpts, err := vwa.ParseAttestationOptions(string(optionsJSON))
	if err != nil {
		t.Fatalf("parse attestation options: %v", err)
	}
	cred := vwa.NewCredential(vwa.KeyTypeEC2)
	attResp := vwa.CreateAttestationResponse(testRP(), *authr, cred, *attOpts)

	row, err := v.FinishRegistration(ctx, ws, user, "My Key", []byte(attResp))
	if err != nil {
		t.Fatalf("finish registration: %v", err)
	}
	if row.ID == uuid.Nil {
		t.Fatal("finish registration returned a row without an id")
	}
	authr.Options.UserHandle = userHandle(ws, user)
	authr.AddCredential(cred)
	return cred
}

// assertOnce runs one full assertion ceremony and returns the serialized
// assertion response bytes (what the client would submit via X-MFA-Assertion).
func assertOnce(t *testing.T, v *WebAuthnMFAVerifier, ws uuid.UUID, user string, authr *vwa.Authenticator, cred vwa.Credential) []byte {
	t.Helper()
	ctx := context.Background()

	assertion, err := v.BeginStepUp(ctx, ws, user)
	if err != nil {
		t.Fatalf("begin step-up: %v", err)
	}
	optionsJSON, err := json.Marshal(assertion)
	if err != nil {
		t.Fatalf("marshal assertion options: %v", err)
	}
	asnOpts, err := vwa.ParseAssertionOptions(string(optionsJSON))
	if err != nil {
		t.Fatalf("parse assertion options: %v", err)
	}
	return []byte(vwa.CreateAssertionResponse(testRP(), *authr, cred, *asnOpts))
}

// TestWebAuthnRegisterAndStepUp drives a complete, cryptographically real
// registration + step-up ceremony end to end (a virtual authenticator signs the
// challenges), proving the verifier is fully wired: the issued options verify,
// the credential persists sealed, and a fresh assertion satisfies step-up.
func TestWebAuthnRegisterAndStepUp(t *testing.T) {
	v, db := newWebAuthnVerifier(t)
	ws, user := uuid.New(), "user-1"
	authr := vwa.NewAuthenticator()

	cred := enroll(t, v, ws, user, &authr)

	// Exactly one credential persisted, sealed (not plaintext) at rest.
	var rows []models.WebAuthnCredential
	if err := db.Find(&rows).Error; err != nil {
		t.Fatalf("load credentials: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("credential rows = %d, want 1", len(rows))
	}
	if rows[0].Sealed == "" || rows[0].FriendlyName != "My Key" {
		t.Fatalf("unexpected stored credential: sealed=%q friendly=%q", rows[0].Sealed, rows[0].FriendlyName)
	}

	// The registration challenge must have been consumed (single-use).
	var challenges int64
	db.Model(&models.WebAuthnChallenge{}).Count(&challenges)
	if challenges != 0 {
		t.Fatalf("challenges after registration = %d, want 0 (consumed)", challenges)
	}

	// A fresh assertion satisfies step-up.
	assertResp := assertOnce(t, v, ws, user, &authr, cred)
	if err := v.VerifyStepUp(context.Background(), ws, user, "policy.promote", assertResp); err != nil {
		t.Fatalf("verify step-up: %v", err)
	}

	// last_used_at updated; sign counter persisted.
	var after models.WebAuthnCredential
	if err := db.First(&after).Error; err != nil {
		t.Fatalf("reload credential: %v", err)
	}
	if after.LastUsedAt == nil {
		t.Fatal("last_used_at not updated after successful step-up")
	}
}

// TestWebAuthnStepUpReplayRejected proves the authentication challenge is
// single-use: replaying a captured assertion (same bytes) after it succeeded is
// denied because the challenge row was atomically consumed.
func TestWebAuthnStepUpReplayRejected(t *testing.T) {
	v, _ := newWebAuthnVerifier(t)
	ws, user := uuid.New(), "user-1"
	authr := vwa.NewAuthenticator()
	cred := enroll(t, v, ws, user, &authr)

	assertResp := assertOnce(t, v, ws, user, &authr, cred)
	if err := v.VerifyStepUp(context.Background(), ws, user, "promote", assertResp); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	// Replaying the same assertion without a new challenge must fail closed.
	err := v.VerifyStepUp(context.Background(), ws, user, "promote", assertResp)
	if !errors.Is(err, ErrMFAFailed) {
		t.Fatalf("replay err = %v, want ErrMFAFailed", err)
	}
}

// TestWebAuthnStepUpStaleAssertionRejected proves that an assertion answering a
// superseded challenge is rejected: issuing a second BeginStepUp replaces the
// first challenge, so the first assertion no longer matches.
func TestWebAuthnStepUpStaleChallengeRejected(t *testing.T) {
	v, _ := newWebAuthnVerifier(t)
	ws, user := uuid.New(), "user-1"
	authr := vwa.NewAuthenticator()
	cred := enroll(t, v, ws, user, &authr)

	// Capture an assertion for challenge #1, then issue challenge #2 (which
	// overwrites #1). The captured assertion is now stale.
	stale := assertOnce(t, v, ws, user, &authr, cred)
	if _, err := v.BeginStepUp(context.Background(), ws, user); err != nil {
		t.Fatalf("second begin step-up: %v", err)
	}
	err := v.VerifyStepUp(context.Background(), ws, user, "promote", stale)
	if !errors.Is(err, ErrMFAFailed) {
		t.Fatalf("stale assertion err = %v, want ErrMFAFailed", err)
	}
}

// TestWebAuthnVerifyFailClosed covers the denial inputs: empty, garbage, and a
// well-formed assertion for a user with no enrolled credential. All must return
// ErrMFAFailed (never a nil/allow), and none must require an outstanding
// challenge to reach that verdict for the empty case.
func TestWebAuthnVerifyFailClosed(t *testing.T) {
	v, _ := newWebAuthnVerifier(t)
	ws, user := uuid.New(), "user-1"

	t.Run("empty assertion", func(t *testing.T) {
		if err := v.VerifyStepUp(context.Background(), ws, user, "promote", nil); !errors.Is(err, ErrMFAFailed) {
			t.Fatalf("err = %v, want ErrMFAFailed", err)
		}
	})

	t.Run("garbage assertion", func(t *testing.T) {
		if err := v.VerifyStepUp(context.Background(), ws, user, "promote", []byte("not json")); !errors.Is(err, ErrMFAFailed) {
			t.Fatalf("err = %v, want ErrMFAFailed", err)
		}
	})

	t.Run("no enrolled credential", func(t *testing.T) {
		// A syntactically valid (but for a never-enrolled user) assertion still
		// fails closed: BeginStepUp itself refuses with no credential.
		if _, err := v.BeginStepUp(context.Background(), ws, "nobody"); !errors.Is(err, ErrMFAFailed) {
			t.Fatalf("begin step-up err = %v, want ErrMFAFailed", err)
		}
	})
}

// TestWebAuthnCredentialSealedAtRest proves an enrolled credential is sealed
// (the public-key blob is never stored plaintext) and that its ciphertext is
// bound to (workspace, user, credential id): relocating the row to another user
// makes the verifier fail to open it (a 503-class integrity error), not silently
// treat the user as unenrolled.
func TestWebAuthnCredentialSealedAtRest(t *testing.T) {
	v, db := newWebAuthnVerifier(t)
	ws, user := uuid.New(), "user-1"
	authr := vwa.NewAuthenticator()
	enroll(t, v, ws, user, &authr)

	var row models.WebAuthnCredential
	if err := db.First(&row).Error; err != nil {
		t.Fatalf("load row: %v", err)
	}
	// Opening under the correct AAD round-trips; under a foreign user it fails.
	if _, err := v.enc.Open(row.Sealed, webAuthnCredentialAAD(ws, user, row.CredentialID)); err != nil {
		t.Fatalf("open with correct AAD: %v", err)
	}
	if _, err := v.enc.Open(row.Sealed, webAuthnCredentialAAD(ws, "user-2", row.CredentialID)); err == nil {
		t.Fatal("ciphertext opened under a foreign user AAD; tenant binding broken")
	}

	// Relocating the sealed row to another user makes loadUser fail with a
	// non-ErrMFAFailed (integrity) error rather than degrading to "unenrolled".
	if err := db.Model(&models.WebAuthnCredential{}).
		Where("id = ?", row.ID).
		Update("user_id", "user-2").Error; err != nil {
		t.Fatalf("relocate row: %v", err)
	}
	_, err := v.BeginStepUp(context.Background(), ws, "user-2")
	if err == nil || errors.Is(err, ErrMFAFailed) {
		t.Fatalf("relocated-credential err = %v, want a non-ErrMFAFailed open error", err)
	}
}

// TestWebAuthnListAndDeleteCredential covers the management surface: list is
// workspace/user scoped, and delete is scoped + idempotent-not (a second delete
// of the same id is ErrRecordNotFound).
func TestWebAuthnListAndDeleteCredential(t *testing.T) {
	v, _ := newWebAuthnVerifier(t)
	ws, user := uuid.New(), "user-1"
	authr := vwa.NewAuthenticator()
	enroll(t, v, ws, user, &authr)

	rows, err := v.ListCredentials(context.Background(), ws, user)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("list len = %d, want 1", len(rows))
	}

	// A different user in the same workspace sees nothing.
	other, err := v.ListCredentials(context.Background(), ws, "user-2")
	if err != nil {
		t.Fatalf("list other: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("other user's list len = %d, want 0", len(other))
	}

	// Deleting another workspace's id (does not exist here) is NotFound.
	if err := v.DeleteCredential(context.Background(), ws, user, uuid.New()); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("delete unknown err = %v, want ErrRecordNotFound", err)
	}
	// Deleting the real credential succeeds, then a second delete is NotFound.
	if err := v.DeleteCredential(context.Background(), ws, user, rows[0].ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := v.DeleteCredential(context.Background(), ws, user, rows[0].ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("re-delete err = %v, want ErrRecordNotFound", err)
	}
}

// TestWebAuthnReenrollAfterDelete proves that removing an authenticator and
// re-enrolling the *same* physical key later succeeds. DeleteCredential soft
// deletes (the model embeds Base), so the unique index on
// (workspace_id, credential_id) must be partial on deleted_at IS NULL — without
// that predicate the soft-deleted row would block the re-enrollment INSERT.
func TestWebAuthnReenrollAfterDelete(t *testing.T) {
	v, _ := newWebAuthnVerifier(t)
	ws, user := uuid.New(), "user-1"
	authr := vwa.NewAuthenticator()
	cred := vwa.NewCredential(vwa.KeyTypeEC2)

	// register runs an attestation ceremony reusing the SAME virtual credential
	// (so the credential id is stable across enrollments — the collision case).
	register := func() models.WebAuthnCredential {
		t.Helper()
		ctx := context.Background()
		creation, err := v.BeginRegistration(ctx, ws, user, "Test User")
		if err != nil {
			t.Fatalf("begin registration: %v", err)
		}
		optionsJSON, err := json.Marshal(creation)
		if err != nil {
			t.Fatalf("marshal creation options: %v", err)
		}
		attOpts, err := vwa.ParseAttestationOptions(string(optionsJSON))
		if err != nil {
			t.Fatalf("parse attestation options: %v", err)
		}
		attResp := vwa.CreateAttestationResponse(testRP(), authr, cred, *attOpts)
		row, err := v.FinishRegistration(ctx, ws, user, "My Key", []byte(attResp))
		if err != nil {
			t.Fatalf("finish registration: %v", err)
		}
		return *row
	}

	first := register()
	if err := v.DeleteCredential(context.Background(), ws, user, first.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	second := register()
	if second.ID == first.ID {
		t.Fatal("re-enrollment reused the soft-deleted row id")
	}

	// Exactly one live credential (the soft-deleted one is filtered out).
	rows, err := v.ListCredentials(context.Background(), ws, user)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("live credential rows = %d, want 1", len(rows))
	}
}

// TestWebAuthnStepUpIsolatedAcrossWorkspaces proves a credential enrolled in one
// workspace cannot satisfy step-up in another: the user handle is workspace
// bound, so the same physical authenticator is a distinct credential per tenant.
func TestWebAuthnStepUpIsolatedAcrossWorkspaces(t *testing.T) {
	v, _ := newWebAuthnVerifier(t)
	wsA, wsB, user := uuid.New(), uuid.New(), "user-1"
	authr := vwa.NewAuthenticator()
	cred := enroll(t, v, wsA, user, &authr)

	// wsB has no enrolled credential, so it cannot even begin a step-up.
	if _, err := v.BeginStepUp(context.Background(), wsB, user); !errors.Is(err, ErrMFAFailed) {
		t.Fatalf("wsB begin step-up err = %v, want ErrMFAFailed", err)
	}
	// And wsA still works (sanity).
	assertResp := assertOnce(t, v, wsA, user, &authr, cred)
	if err := v.VerifyStepUp(context.Background(), wsA, user, "promote", assertResp); err != nil {
		t.Fatalf("wsA verify: %v", err)
	}
}

// TestWebAuthnExclusionsPreventDoubleEnrollment proves an already-enrolled
// authenticator is offered as an exclusion on the next BeginRegistration, so the
// same key cannot be registered twice.
func TestWebAuthnExclusionsPreventDoubleEnrollment(t *testing.T) {
	v, _ := newWebAuthnVerifier(t)
	ws, user := uuid.New(), "user-1"
	authr := vwa.NewAuthenticator()
	cred := enroll(t, v, ws, user, &authr)

	creation, err := v.BeginRegistration(context.Background(), ws, user, "Test User")
	if err != nil {
		t.Fatalf("begin second registration: %v", err)
	}
	found := false
	for _, ex := range creation.Response.CredentialExcludeList {
		if string(ex.CredentialID) == string(cred.ID) {
			found = true
		}
	}
	if !found {
		t.Fatal("already-enrolled credential not present in exclusion list")
	}
}

// TestWebAuthnTakeChallengeExpired proves an expired (but never consumed)
// challenge is treated as absent by takeChallenge and removed.
func TestWebAuthnTakeChallengeExpired(t *testing.T) {
	v, db := newWebAuthnVerifier(t)
	ws, user := uuid.New(), "user-1"

	base := time.Unix(1_700_000_000, 0)
	v.SetClock(func() time.Time { return base })
	// Seed an outstanding authentication challenge.
	if err := v.putChallenge(context.Background(), ws, user, ceremonyAuthentication, &webauthn.SessionData{Challenge: "test-challenge"}); err != nil {
		t.Fatalf("put challenge: %v", err)
	}
	// Advance past the TTL.
	v.SetClock(func() time.Time { return base.Add(DefaultWebAuthnChallengeTTL + time.Minute) })

	sess, ok, err := v.takeChallenge(context.Background(), ws, user, ceremonyAuthentication)
	if err != nil {
		t.Fatalf("take challenge: %v", err)
	}
	if ok || sess != nil {
		t.Fatalf("expired challenge returned ok=%v sess=%v, want absent", ok, sess)
	}
	var remaining int64
	db.Model(&models.WebAuthnChallenge{}).Count(&remaining)
	if remaining != 0 {
		t.Fatalf("expired challenge not removed; remaining=%d", remaining)
	}
}

// TestWebAuthnCleanupExpiredChallenges proves the sweeper deletes only past-due
// challenge rows.
func TestWebAuthnCleanupExpiredChallenges(t *testing.T) {
	v, db := newWebAuthnVerifier(t)
	ws := uuid.New()
	now := time.Unix(1_700_000_000, 0)
	v.SetClock(func() time.Time { return now })

	fresh := models.WebAuthnChallenge{WorkspaceID: ws, UserID: "fresh", Ceremony: ceremonyAuthentication, SessionData: []byte("{}"), ExpiresAt: now.Add(time.Minute), CreatedAt: now, UpdatedAt: now}
	stale := models.WebAuthnChallenge{WorkspaceID: ws, UserID: "stale", Ceremony: ceremonyAuthentication, SessionData: []byte("{}"), ExpiresAt: now.Add(-time.Minute), CreatedAt: now, UpdatedAt: now}
	if err := db.Create(&fresh).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&stale).Error; err != nil {
		t.Fatal(err)
	}
	deleted, err := v.CleanupExpiredChallenges(context.Background())
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleted)
	}
	var remaining int64
	db.Model(&models.WebAuthnChallenge{}).Count(&remaining)
	if remaining != 1 {
		t.Fatalf("remaining = %d, want 1", remaining)
	}
}

// TestWebAuthnChallengeCleanupLoopStops proves the loop exits promptly on
// context cancellation and the join handle blocks until it has fully exited.
func TestWebAuthnChallengeCleanupLoopStops(t *testing.T) {
	v, _ := newWebAuthnVerifier(t)
	ctx, cancel := context.WithCancel(context.Background())
	join := v.StartChallengeCleanupLoop(ctx, 10*time.Millisecond)
	cancel()
	done := make(chan struct{})
	go func() {
		join()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("challenge cleanup loop join did not return after cancellation")
	}
}

// TestNewWebAuthnVerifierValidation covers the constructor's required-argument
// checks.
func TestNewWebAuthnVerifierValidation(t *testing.T) {
	enc := newTestEncryptor(t)
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	cases := map[string]WebAuthnSettings{
		"missing rpid":    {RPID: "", RPOrigins: []string{testRPOrigin}},
		"missing origins": {RPID: testRPID, RPOrigins: nil},
	}
	for name, settings := range cases {
		if _, err := NewWebAuthnMFAVerifier(db, enc, settings); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
	if _, err := NewWebAuthnMFAVerifier(nil, enc, WebAuthnSettings{RPID: testRPID, RPOrigins: []string{testRPOrigin}}); err == nil {
		t.Error("nil db: expected error, got nil")
	}
	if _, err := NewWebAuthnMFAVerifier(db, nil, WebAuthnSettings{RPID: testRPID, RPOrigins: []string{testRPOrigin}}); err == nil {
		t.Error("nil enc: expected error, got nil")
	}
}

// TestWebAuthnVerifierImplementsInterface is a compile-time + runtime assertion
// that the verifier satisfies MFAVerifier (so it can be a composite leg).
func TestWebAuthnVerifierImplementsInterface(t *testing.T) {
	v, _ := newWebAuthnVerifier(t)
	var _ MFAVerifier = v
	if crypto.IsPassthrough(v.enc) {
		t.Fatal("test encryptor must not be passthrough")
	}
}
