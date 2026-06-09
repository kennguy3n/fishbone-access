package mfa

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// TOTP validation parameters (RFC 6238). Period+Skew bound how long a single
// code is mathematically valid on the server, which in turn drives the
// replay-table retention window.
const (
	totpPeriodSeconds = 30
	totpSkewSteps     = 1 // ±1 step (±30s) tolerance for client/server clock drift
)

// DefaultTOTPUsedCodeRetention is the wall-clock window during which an
// accepted code is remembered (and therefore refused as a replay). With
// Period=30 and Skew=1 a code is valid for at most three 30-second steps
// (~90s), so retention is pinned to that window: the used-codes table only
// holds rows that could still pass validation, and anything older has aged out
// of the validation window and is no longer attack-relevant.
const DefaultTOTPUsedCodeRetention = 90 * time.Second

// DefaultCleanupInterval is the cadence StartUsedCodeCleanupLoop sweeps expired
// rows when the caller passes 0.
const DefaultCleanupInterval = 60 * time.Second

// TOTPMFAVerifier implements MFAVerifier with RFC 6238 TOTP validation plus
// single-use (anti-replay) enforcement. After a code validates, the verifier
// claims (workspace_id, user_id, sha256(code)) in pam_totp_used_codes via
// INSERT ... ON CONFLICT DO NOTHING; a zero RowsAffected means another request
// already burned the code, which is treated as a replay. The claim is atomic at
// the DB level, so two concurrent verifications of the same code resolve to
// exactly one success.
type TOTPMFAVerifier struct {
	db  *gorm.DB
	now func() time.Time // injectable for tests
}

// NewTOTPMFAVerifier constructs a verifier backed by db.
func NewTOTPMFAVerifier(db *gorm.DB) (*TOTPMFAVerifier, error) {
	if db == nil {
		return nil, errors.New("mfa: TOTPMFAVerifier: db is nil")
	}
	return &TOTPMFAVerifier{db: db, now: time.Now}, nil
}

// SetClock overrides the time source. Test-only; a nil function restores
// time.Now. Used to drive deterministic code generation/expiry in tests.
func (v *TOTPMFAVerifier) SetClock(now func() time.Time) {
	if now == nil {
		v.now = time.Now
		return
	}
	v.now = now
}

// hashCode returns the lowercase hex SHA-256 of a validated code. Only the hash
// is persisted: the code is a shared-secret-derived value and remains sensitive
// even after use, so storing it verbatim would needlessly widen the blast
// radius of a replay-table disclosure. SHA-256 is collision-resistant enough
// that two distinct 6-digit codes never collide in the (workspace,user) keyspace.
func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// VerifyStepUp validates the 6-digit TOTP code in assertion against the user's
// enrolled secret for the workspace, then atomically claims the code so it
// cannot be replayed within its remaining validity window. Returns nil on
// success and ErrMFAFailed (wrapped with a server-side reason) on any failure.
func (v *TOTPMFAVerifier) VerifyStepUp(ctx context.Context, workspaceID uuid.UUID, userID, scope string, assertion []byte) error {
	if workspaceID == uuid.Nil || userID == "" {
		return fmt.Errorf("%w: workspace and user are required", ErrMFAFailed)
	}
	if len(assertion) == 0 {
		return ErrMFAFailed
	}

	code := strings.TrimSpace(string(assertion))
	if len(code) != 6 {
		return fmt.Errorf("%w: TOTP code must be exactly 6 digits", ErrMFAFailed)
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return fmt.Errorf("%w: TOTP code must contain only digits", ErrMFAFailed)
		}
	}

	var secret models.UserTOTPSecret
	err := v.db.WithContext(ctx).
		Where("workspace_id = ? AND user_id = ? AND verified = ? AND disabled_at IS NULL", workspaceID, userID, true).
		First(&secret).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("%w: no TOTP secret enrolled", ErrMFAFailed)
		}
		return fmt.Errorf("mfa: TOTPMFAVerifier: load secret: %w", err)
	}

	ok, vErr := totp.ValidateCustom(code, secret.Secret, v.now(), totp.ValidateOpts{
		Period:    totpPeriodSeconds,
		Skew:      totpSkewSteps,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if vErr != nil {
		logger.Warnf(ctx, "mfa: TOTPMFAVerifier: validate error workspace_id=%s user_id=%s: %v", workspaceID, userID, vErr)
	}
	if !ok {
		return fmt.Errorf("%w: invalid TOTP code", ErrMFAFailed)
	}

	// Anti-replay: claim the (workspace_id, user_id, code_hash) row. The
	// composite PK makes the INSERT atomic; a conflict (another request already
	// used this code) is absorbed silently and leaves RowsAffected == 0, which
	// is the replay signal.
	used := models.PAMTOTPUsedCode{
		WorkspaceID: workspaceID,
		UserID:      userID,
		CodeHash:    hashCode(code),
		UsedAt:      v.now(),
	}
	res := v.db.WithContext(ctx).
		Clauses(clause.OnConflict{DoNothing: true}).
		Create(&used)
	if res.Error != nil {
		// Log scope (never the code — it is a secret even after use) so audit
		// can correlate which surface triggered the failure.
		logger.Warnf(ctx, "mfa: TOTPMFAVerifier: claim used code workspace_id=%s user_id=%s scope=%s: %v", workspaceID, userID, scope, res.Error)
		return fmt.Errorf("mfa: TOTPMFAVerifier: claim used code: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		logger.Warnf(ctx, "mfa: TOTPMFAVerifier: replay rejected workspace_id=%s user_id=%s scope=%s", workspaceID, userID, scope)
		return fmt.Errorf("%w: TOTP code already used", ErrMFAFailed)
	}

	return nil
}

// CleanupExpiredUsedCodes deletes rows whose UsedAt is older than retention.
// Returns the number of rows removed. Falling behind on cleanup is never a
// security regression (the unique constraint still blocks replays) — it only
// grows the table — so callers run it on a periodic best-effort loop.
func (v *TOTPMFAVerifier) CleanupExpiredUsedCodes(ctx context.Context, retention time.Duration) (int64, error) {
	if retention <= 0 {
		retention = DefaultTOTPUsedCodeRetention
	}
	cutoff := v.now().Add(-retention)
	res := v.db.WithContext(ctx).
		Where("used_at < ?", cutoff).
		Delete(&models.PAMTOTPUsedCode{})
	if res.Error != nil {
		return 0, fmt.Errorf("mfa: TOTPMFAVerifier: cleanup used codes: %w", res.Error)
	}
	return res.RowsAffected, nil
}

// StartUsedCodeCleanupLoop runs CleanupExpiredUsedCodes on a fixed cadence until
// ctx is cancelled. The first sweep happens after one interval (not at boot) so
// multiple replicas don't stampede the DB on startup. interval defaults to
// DefaultCleanupInterval and retention to DefaultTOTPUsedCodeRetention when
// non-positive. Per-sweep errors are logged but never stop the loop — a
// transient DB issue must not silently kill replay protection's GC.
func (v *TOTPMFAVerifier) StartUsedCodeCleanupLoop(ctx context.Context, interval, retention time.Duration) {
	if interval <= 0 {
		interval = DefaultCleanupInterval
	}
	if retention <= 0 {
		retention = DefaultTOTPUsedCodeRetention
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// select picks a ready case at random, so on graceful shutdown
				// the ticker can win the race against ctx.Done() even when both
				// are pending. Guard here so we don't dispatch a DELETE under an
				// already-cancelled context (which would log a spurious
				// "context canceled" warning on every shutdown).
				if ctx.Err() != nil {
					return
				}
				_, err := v.CleanupExpiredUsedCodes(ctx, retention)
				if err != nil {
					// ctx may have been cancelled between the guard and the
					// driver round-trip (connection-pool contention). Treat any
					// post-cancel error as a clean shutdown: errors.Is catches
					// the canonical context sentinels and sql.ErrTxDone catches
					// the database/sql layer surfacing cancellation as a
					// finished transaction.
					if ctx.Err() != nil ||
						errors.Is(err, context.Canceled) ||
						errors.Is(err, context.DeadlineExceeded) ||
						errors.Is(err, sql.ErrTxDone) {
						return
					}
					logger.Warnf(ctx, "mfa: TOTPMFAVerifier: cleanup sweep failed: %v", err)
				}
			}
		}
	}()
}

var _ MFAVerifier = (*TOTPMFAVerifier)(nil)
