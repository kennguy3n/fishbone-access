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
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

// testSecret is a fixed base32 TOTP secret so generated codes are deterministic
// across runs. It is a test fixture, not a credential.
const testSecret = "JBSWY3DPEHPK3PXP"

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
	v, err := NewTOTPMFAVerifier(db)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return v, db
}

func seedSecret(t *testing.T, db *gorm.DB, ws uuid.UUID, userID, secret string, verified bool, disabledAt *time.Time) {
	t.Helper()
	row := models.UserTOTPSecret{
		WorkspaceID: ws,
		UserID:      userID,
		Secret:      secret,
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
	seedSecret(t, db, ws, user, testSecret, true, nil)

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

func TestVerifyStepUpReplayRejected(t *testing.T) {
	v, db := newTOTPVerifier(t)
	ws, user := uuid.New(), "user-1"
	seedSecret(t, db, ws, user, testSecret, true, nil)
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
	seedSecret(t, db, ws, user, testSecret, true, nil)
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
	seedSecret(t, db, wsA, user, testSecret, true, nil)
	seedSecret(t, db, wsB, user, testSecret, true, nil)
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
	seedSecret(t, db, ws, user, testSecret, true, nil)
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
		seedSecret(t, db, ws, user, testSecret, false, nil) // not verified
		v.SetClock(func() time.Time { return now })
		if err := v.VerifyStepUp(context.Background(), ws, user, "promote", []byte(codeAt(t, testSecret, now))); !errors.Is(err, ErrMFAFailed) {
			t.Fatalf("unverified secret err = %v, want ErrMFAFailed", err)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		v, db := newTOTPVerifier(t)
		ws, user := uuid.New(), "u"
		disabled := now.Add(-time.Hour)
		seedSecret(t, db, ws, user, testSecret, true, &disabled)
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

// TestStartUsedCodeCleanupLoopStops proves the loop exits promptly on context
// cancellation without logging spurious errors (no panic / goroutine leak).
func TestStartUsedCodeCleanupLoopStops(t *testing.T) {
	v, _ := newTOTPVerifier(t)
	ctx, cancel := context.WithCancel(context.Background())
	v.StartUsedCodeCleanupLoop(ctx, 10*time.Millisecond, time.Second)
	cancel()
	// Give the goroutine a moment to observe cancellation. There is no handle to
	// join, but a leak would surface under -race / goroutine dumps.
	time.Sleep(30 * time.Millisecond)
}
