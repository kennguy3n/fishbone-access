package mfa

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

// testSecret is a fixed base32 TOTP secret so generated codes are deterministic
// across runs. It is a test fixture, not a credential.
const testSecret = "JBSWY3DPEHPK3PXP"

// testDEK is a fixed base64-encoded 32-byte key used to exercise the real
// AES-GCM at-rest encryption path in tests (not a credential).
const testDEK = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

func newTestEncryptor(t *testing.T) crypto.Encryptor {
	t.Helper()
	enc, err := crypto.NewAESGCMEncryptor(testDEK)
	if err != nil {
		t.Fatalf("new test encryptor: %v", err)
	}
	return enc
}

func newTOTPVerifier(t *testing.T) (*TOTPMFAVerifier, *gorm.DB) {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// A SQLite ":memory:" database is private to each physical connection, so a
	// pooled second connection would see an empty schema. Pin the pool to one
	// connection so every goroutine in the concurrent-replay test shares the
	// single migrated in-memory DB. (True cross-connection atomicity of the
	// ON CONFLICT claim is exercised by the Postgres integration test.)
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	v, err := NewTOTPMFAVerifier(db, newTestEncryptor(t))
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return v, db
}

// seedSecret stores a TOTP secret the way an enrollment writer would: sealed at
// rest via the verifier's SealTOTPSecret, so the persisted column holds
// ciphertext and the verifier's open-on-read path is exercised end to end.
func seedSecret(t *testing.T, db *gorm.DB, v *TOTPMFAVerifier, ws uuid.UUID, userID, secret string, verified bool, disabledAt *time.Time) {
	t.Helper()
	sealed, err := v.SealTOTPSecret(ws, userID, secret)
	if err != nil {
		t.Fatalf("seal secret: %v", err)
	}
	row := models.UserTOTPSecret{
		WorkspaceID: ws,
		UserID:      userID,
		Secret:      sealed,
		Verified:    verified,
		DisabledAt:  disabledAt,
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("seed secret: %v", err)
	}
}

func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, at)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	return code
}

func TestVerifyStepUpHappyPath(t *testing.T) {
	v, db := newTOTPVerifier(t)
	ws, user := uuid.New(), "user-1"
	seedSecret(t, db, v, ws, user, testSecret, true, nil)

	now := time.Unix(1_700_000_000, 0)
	v.SetClock(func() time.Time { return now })
	code := codeAt(t, testSecret, now)

	if err := v.VerifyStepUp(context.Background(), ws, user, "policy.promote", []byte(code)); err != nil {
		t.Fatalf("verify valid code: %v", err)
	}
	// The accepted code was claimed (one row, hash only — not the code).
	var used []models.PAMTOTPUsedCode
	if err := db.Find(&used).Error; err != nil {
		t.Fatalf("load used: %v", err)
	}
	if len(used) != 1 {
		t.Fatalf("used rows = %d, want 1", len(used))
	}
	if used[0].CodeHash == code || used[0].CodeHash == "" {
		t.Fatalf("code must be stored hashed, got %q", used[0].CodeHash)
	}
}

// TestSecretEncryptedAtRest proves the enrolled shared secret is never stored in
// plaintext and that its ciphertext is bound to the (workspace, user) it was
// sealed for: a row relocated to a different user fails to open, so a DB-level
// attacker cannot lift one tenant's secret into another principal.
func TestSecretEncryptedAtRest(t *testing.T) {
	v, db := newTOTPVerifier(t)
	ws, user := uuid.New(), "user-1"
	seedSecret(t, db, v, ws, user, testSecret, true, nil)

	var stored models.UserTOTPSecret
	if err := db.Where("workspace_id = ? AND user_id = ?", ws, user).First(&stored).Error; err != nil {
		t.Fatalf("load stored secret: %v", err)
	}
	if stored.Secret == testSecret {
		t.Fatal("secret persisted in plaintext; want sealed ciphertext")
	}
	// The ciphertext must decrypt back to the plaintext under the matching AAD.
	plain, err := v.enc.Open(stored.Secret, totpSecretAAD(ws, user))
	if err != nil {
		t.Fatalf("open with correct AAD: %v", err)
	}
	if string(plain) != testSecret {
		t.Fatalf("decrypted = %q, want %q", plain, testSecret)
	}
	// Same ciphertext, different user (AAD) must fail authentication.
	if _, err := v.enc.Open(stored.Secret, totpSecretAAD(ws, "user-2")); err == nil {
		t.Fatal("ciphertext opened under a foreign user AAD; tenant binding broken")
	}

	// End to end: relocating the sealed row to another user makes step-up fail
	// with a verifier (integrity) error, not a bad-code result.
	if err := db.Model(&models.UserTOTPSecret{}).
		Where("workspace_id = ? AND user_id = ?", ws, user).
		Update("user_id", "user-2").Error; err != nil {
		t.Fatalf("relocate row: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	v.SetClock(func() time.Time { return now })
	code := codeAt(t, testSecret, now)
	err = v.VerifyStepUp(context.Background(), ws, "user-2", "promote", []byte(code))
	if err == nil || errors.Is(err, ErrMFAFailed) {
		t.Fatalf("relocated-secret verify err = %v, want a non-ErrMFAFailed open error", err)
	}
}

func TestVerifyStepUpReplayRejected(t *testing.T) {
	v, db := newTOTPVerifier(t)
	ws, user := uuid.New(), "user-1"
	seedSecret(t, db, v, ws, user, testSecret, true, nil)
	now := time.Unix(1_700_000_000, 0)
	v.SetClock(func() time.Time { return now })
	code := codeAt(t, testSecret, now)

	if err := v.VerifyStepUp(context.Background(), ws, user, "promote", []byte(code)); err != nil {
		t.Fatalf("first use: %v", err)
	}
	// Reusing the same still-time-valid code must be rejected.
	err := v.VerifyStepUp(context.Background(), ws, user, "promote", []byte(code))
	if !errors.Is(err, ErrMFAFailed) {
		t.Fatalf("replay err = %v, want ErrMFAFailed", err)
	}
}

// TestVerifyStepUpConcurrentReplay fires two goroutines with the same valid code
// and asserts exactly one wins — the DB-atomic claim must serialize them.
func TestVerifyStepUpConcurrentReplay(t *testing.T) {
	v, db := newTOTPVerifier(t)
	ws, user := uuid.New(), "user-1"
	seedSecret(t, db, v, ws, user, testSecret, true, nil)
	now := time.Unix(1_700_000_000, 0)
	v.SetClock(func() time.Time { return now })
	code := codeAt(t, testSecret, now)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var successes, failures int
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := v.VerifyStepUp(context.Background(), ws, user, "promote", []byte(code))
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successes++
			} else if errors.Is(err, ErrMFAFailed) {
				failures++
			} else {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if successes != 1 || failures != 1 {
		t.Fatalf("successes=%d failures=%d, want exactly 1 each", successes, failures)
	}
}

// TestVerifyStepUpReplayIsolatedAcrossWorkspaces proves a code "used" in one
// workspace does not block the same code/user in another workspace (the claim
// is keyed by workspace_id) — tenant isolation of the replay table.
func TestVerifyStepUpReplayIsolatedAcrossWorkspaces(t *testing.T) {
	v, db := newTOTPVerifier(t)
	wsA, wsB, user := uuid.New(), uuid.New(), "user-1"
	seedSecret(t, db, v, wsA, user, testSecret, true, nil)
	seedSecret(t, db, v, wsB, user, testSecret, true, nil)
	now := time.Unix(1_700_000_000, 0)
	v.SetClock(func() time.Time { return now })
	code := codeAt(t, testSecret, now)

	if err := v.VerifyStepUp(context.Background(), wsA, user, "promote", []byte(code)); err != nil {
		t.Fatalf("wsA use: %v", err)
	}
	if err := v.VerifyStepUp(context.Background(), wsB, user, "promote", []byte(code)); err != nil {
		t.Fatalf("wsB must accept the same code independently, got: %v", err)
	}
}

func TestVerifyStepUpRejectsBadInput(t *testing.T) {
	v, db := newTOTPVerifier(t)
	ws, user := uuid.New(), "user-1"
	seedSecret(t, db, v, ws, user, testSecret, true, nil)
	now := time.Unix(1_700_000_000, 0)
	v.SetClock(func() time.Time { return now })

	cases := map[string][]byte{
		"empty":      []byte(""),
		"too short":  []byte("12345"),
		"too long":   []byte("1234567"),
		"non-digit":  []byte("12a456"),
		"wrong code": []byte("000000"),
	}
	for name, assertion := range cases {
		// "000000" is astronomically unlikely to be the live code; treat a rare
		// coincidence as acceptable by regenerating away from it.
		if name == "wrong code" && string(assertion) == codeAt(t, testSecret, now) {
			continue
		}
		if err := v.VerifyStepUp(context.Background(), ws, user, "promote", assertion); !errors.Is(err, ErrMFAFailed) {
			t.Errorf("%s: err = %v, want ErrMFAFailed", name, err)
		}
	}
}

func TestVerifyStepUpNoEnrolledSecret(t *testing.T) {
	v, _ := newTOTPVerifier(t)
	now := time.Unix(1_700_000_000, 0)
	v.SetClock(func() time.Time { return now })
	// No secret seeded for this (ws,user).
	err := v.VerifyStepUp(context.Background(), uuid.New(), "nobody", "promote", []byte(codeAt(t, testSecret, now)))
	if !errors.Is(err, ErrMFAFailed) {
		t.Fatalf("err = %v, want ErrMFAFailed", err)
	}
}

func TestVerifyStepUpUnverifiedOrDisabledSecretRejected(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	t.Run("unverified", func(t *testing.T) {
		v, db := newTOTPVerifier(t)
		ws, user := uuid.New(), "u"
		seedSecret(t, db, v, ws, user, testSecret, false, nil) // not verified
		v.SetClock(func() time.Time { return now })
		if err := v.VerifyStepUp(context.Background(), ws, user, "promote", []byte(codeAt(t, testSecret, now))); !errors.Is(err, ErrMFAFailed) {
			t.Fatalf("unverified secret err = %v, want ErrMFAFailed", err)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		v, db := newTOTPVerifier(t)
		ws, user := uuid.New(), "u"
		disabled := now.Add(-time.Hour)
		seedSecret(t, db, v, ws, user, testSecret, true, &disabled)
		v.SetClock(func() time.Time { return now })
		if err := v.VerifyStepUp(context.Background(), ws, user, "promote", []byte(codeAt(t, testSecret, now))); !errors.Is(err, ErrMFAFailed) {
			t.Fatalf("disabled secret err = %v, want ErrMFAFailed", err)
		}
	})
}

func TestCleanupExpiredUsedCodes(t *testing.T) {
	v, db := newTOTPVerifier(t)
	ws, user := uuid.New(), "user-1"
	now := time.Unix(1_700_000_000, 0)
	v.SetClock(func() time.Time { return now })

	// One fresh row, one stale row (older than retention).
	fresh := models.PAMTOTPUsedCode{WorkspaceID: ws, UserID: user, CodeHash: "fresh", UsedAt: now.Add(-10 * time.Second)}
	stale := models.PAMTOTPUsedCode{WorkspaceID: ws, UserID: user, CodeHash: "stale", UsedAt: now.Add(-10 * time.Minute)}
	if err := db.Create(&fresh).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&stale).Error; err != nil {
		t.Fatal(err)
	}

	deleted, err := v.CleanupExpiredUsedCodes(context.Background(), DefaultTOTPUsedCodeRetention)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1 (only the stale row)", deleted)
	}
	var remaining int64
	db.Model(&models.PAMTOTPUsedCode{}).Count(&remaining)
	if remaining != 1 {
		t.Fatalf("remaining = %d, want 1 (the fresh row)", remaining)
	}
}

// TestTOTPEnrollmentLifecycle drives the full self-service enrollment flow:
// begin issues a sealed pending secret + provisioning URI, status reflects
// pending, finishing with a valid code activates it, and step-up then succeeds
// with a fresh code from the same secret.
func TestTOTPEnrollmentLifecycle(t *testing.T) {
	v, db := newTOTPVerifier(t)
	ws, user := uuid.New(), "user-1"
	now := time.Unix(1_700_000_000, 0)
	v.SetClock(func() time.Time { return now })

	enr, err := v.BeginEnrollment(context.Background(), ws, user, "", "")
	if err != nil {
		t.Fatalf("begin enrollment: %v", err)
	}
	if enr.Secret == "" || enr.OtpauthURL == "" {
		t.Fatalf("enrollment missing secret/url: %+v", enr)
	}

	// A pending (unverified, sealed) row exists; step-up must NOT yet pass.
	st, err := v.Status(context.Background(), ws, user)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !st.Pending || st.Verified {
		t.Fatalf("status after begin = %+v, want pending only", st)
	}
	var pending models.UserTOTPSecret
	if err := db.Where("workspace_id = ? AND user_id = ?", ws, user).First(&pending).Error; err != nil {
		t.Fatalf("load pending: %v", err)
	}
	if pending.Secret == enr.Secret {
		t.Fatal("pending secret stored in plaintext; want sealed ciphertext")
	}

	// Finishing with a valid code activates the secret.
	if err := v.FinishEnrollment(context.Background(), ws, user, codeAt(t, enr.Secret, now)); err != nil {
		t.Fatalf("finish enrollment: %v", err)
	}
	st, err = v.Status(context.Background(), ws, user)
	if err != nil {
		t.Fatalf("status after finish: %v", err)
	}
	if !st.Verified || st.Pending {
		t.Fatalf("status after finish = %+v, want verified only", st)
	}

	// Step-up now succeeds with a fresh code (advance one step so it's not the
	// same code that the finish flow would have burned).
	later := now.Add(31 * time.Second)
	v.SetClock(func() time.Time { return later })
	if err := v.VerifyStepUp(context.Background(), ws, user, "promote", []byte(codeAt(t, enr.Secret, later))); err != nil {
		t.Fatalf("verify step-up after enrollment: %v", err)
	}
}

// TestTOTPFinishEnrollmentBurnsCode proves the code that confirms enrollment is
// consumed in the anti-replay table, so the same code cannot then satisfy a
// step-up within its remaining validity window — keeping the single-use
// invariant uniform with VerifyStepUp.
func TestTOTPFinishEnrollmentBurnsCode(t *testing.T) {
	v, db := newTOTPVerifier(t)
	ws, user := uuid.New(), "user-1"
	now := time.Unix(1_700_000_000, 0)
	v.SetClock(func() time.Time { return now })

	enr, err := v.BeginEnrollment(context.Background(), ws, user, "", "")
	if err != nil {
		t.Fatalf("begin enrollment: %v", err)
	}
	code := codeAt(t, enr.Secret, now)
	if err := v.FinishEnrollment(context.Background(), ws, user, code); err != nil {
		t.Fatalf("finish enrollment: %v", err)
	}

	// The confirmation code was claimed exactly once, stored hashed (not verbatim).
	var used []models.PAMTOTPUsedCode
	if err := db.Find(&used).Error; err != nil {
		t.Fatalf("load used: %v", err)
	}
	if len(used) != 1 {
		t.Fatalf("used rows = %d, want 1 (the enrollment code)", len(used))
	}
	if used[0].CodeHash == code || used[0].CodeHash == "" {
		t.Fatalf("code must be stored hashed, got %q", used[0].CodeHash)
	}

	// Replaying that same, still-time-valid code for a step-up must be rejected.
	if err := v.VerifyStepUp(context.Background(), ws, user, "promote", []byte(code)); !errors.Is(err, ErrMFAFailed) {
		t.Fatalf("step-up with burned enrollment code err = %v, want ErrMFAFailed", err)
	}
}

// TestTOTPFinishEnrollmentWrongCode proves an incorrect confirmation code is
// rejected and the secret stays pending (not activated).
func TestTOTPFinishEnrollmentWrongCode(t *testing.T) {
	v, _ := newTOTPVerifier(t)
	ws, user := uuid.New(), "user-1"
	now := time.Unix(1_700_000_000, 0)
	v.SetClock(func() time.Time { return now })

	if _, err := v.BeginEnrollment(context.Background(), ws, user, "", ""); err != nil {
		t.Fatalf("begin enrollment: %v", err)
	}
	if err := v.FinishEnrollment(context.Background(), ws, user, "000000"); !errors.Is(err, ErrMFAFailed) {
		t.Fatalf("finish with wrong code err = %v, want ErrMFAFailed", err)
	}
	st, err := v.Status(context.Background(), ws, user)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.Verified || !st.Pending {
		t.Fatalf("status after failed finish = %+v, want still pending", st)
	}
}

// TestTOTPFinishEnrollmentNoPending proves finishing without an outstanding
// enrollment fails closed.
func TestTOTPFinishEnrollmentNoPending(t *testing.T) {
	v, _ := newTOTPVerifier(t)
	ws, user := uuid.New(), "user-1"
	now := time.Unix(1_700_000_000, 0)
	v.SetClock(func() time.Time { return now })
	if err := v.FinishEnrollment(context.Background(), ws, user, codeAt(t, testSecret, now)); !errors.Is(err, ErrMFAFailed) {
		t.Fatalf("finish with no pending err = %v, want ErrMFAFailed", err)
	}
}

// TestTOTPBeginEnrollmentReplacesPending proves repeated begins leave only one
// pending row (an abandoned attempt is cleared).
func TestTOTPBeginEnrollmentReplacesPending(t *testing.T) {
	v, db := newTOTPVerifier(t)
	ws, user := uuid.New(), "user-1"
	now := time.Unix(1_700_000_000, 0)
	v.SetClock(func() time.Time { return now })

	if _, err := v.BeginEnrollment(context.Background(), ws, user, "", ""); err != nil {
		t.Fatalf("begin 1: %v", err)
	}
	if _, err := v.BeginEnrollment(context.Background(), ws, user, "", ""); err != nil {
		t.Fatalf("begin 2: %v", err)
	}
	var pending int64
	db.Model(&models.UserTOTPSecret{}).Where("workspace_id = ? AND user_id = ? AND verified = ?", ws, user, false).Count(&pending)
	if pending != 1 {
		t.Fatalf("pending rows = %d, want 1", pending)
	}
}

// TestTOTPBeginEnrollmentKeepsVerifiedActive proves re-enrolling does not
// disrupt an existing verified secret until the new one is confirmed: the old
// secret still satisfies step-up while a new pending secret exists.
func TestTOTPBeginEnrollmentKeepsVerifiedActive(t *testing.T) {
	v, db := newTOTPVerifier(t)
	ws, user := uuid.New(), "user-1"
	now := time.Unix(1_700_000_000, 0)
	v.SetClock(func() time.Time { return now })

	// An existing verified secret usable for step-up.
	seedSecret(t, db, v, ws, user, testSecret, true, nil)
	// Re-enroll: a new pending secret is provisioned but not yet confirmed.
	if _, err := v.BeginEnrollment(context.Background(), ws, user, "", ""); err != nil {
		t.Fatalf("begin re-enrollment: %v", err)
	}
	st, err := v.Status(context.Background(), ws, user)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !st.Verified || !st.Pending {
		t.Fatalf("status during re-enrollment = %+v, want verified AND pending", st)
	}
	// The old verified secret still satisfies step-up.
	if err := v.VerifyStepUp(context.Background(), ws, user, "promote", []byte(codeAt(t, testSecret, now))); err != nil {
		t.Fatalf("old secret must still work during re-enrollment: %v", err)
	}
}

// TestTOTPDisable proves disabling removes the factor: step-up fails afterward
// and status reports neither verified nor pending. It is idempotent.
func TestTOTPDisable(t *testing.T) {
	v, db := newTOTPVerifier(t)
	ws, user := uuid.New(), "user-1"
	now := time.Unix(1_700_000_000, 0)
	v.SetClock(func() time.Time { return now })
	seedSecret(t, db, v, ws, user, testSecret, true, nil)

	if err := v.DisableTOTP(context.Background(), ws, user); err != nil {
		t.Fatalf("disable: %v", err)
	}
	st, err := v.Status(context.Background(), ws, user)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.Verified || st.Pending {
		t.Fatalf("status after disable = %+v, want none", st)
	}
	if err := v.VerifyStepUp(context.Background(), ws, user, "promote", []byte(codeAt(t, testSecret, now))); !errors.Is(err, ErrMFAFailed) {
		t.Fatalf("step-up after disable err = %v, want ErrMFAFailed", err)
	}
	// Idempotent: a second disable is a no-op.
	if err := v.DisableTOTP(context.Background(), ws, user); err != nil {
		t.Fatalf("second disable: %v", err)
	}
}

// TestStartUsedCodeCleanupLoopStops proves the loop exits promptly on context
// cancellation without logging spurious errors (no panic / goroutine leak), and
// that the returned join handle blocks until the goroutine has fully exited —
// the property cmd/ztna-api relies on to order shutdown before the DB pool
// closes.
func TestStartUsedCodeCleanupLoopStops(t *testing.T) {
	v, _ := newTOTPVerifier(t)
	ctx, cancel := context.WithCancel(context.Background())
	join := v.StartUsedCodeCleanupLoop(ctx, 10*time.Millisecond, time.Second)
	cancel()
	// join must return once the goroutine observes cancellation. Guard with a
	// timeout so a regression (e.g. the loop ignoring ctx) fails deterministically
	// instead of hanging the suite.
	done := make(chan struct{})
	go func() {
		join()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup loop join did not return after context cancellation")
	}
}
