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
	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
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
	enc crypto.Encryptor
	now func() time.Time // injectable for tests
}

// NewTOTPMFAVerifier constructs a verifier backed by db, encrypting enrolled
// TOTP shared secrets at rest with enc. enc is the same DEK-backed envelope
// encryptor used for connector credentials; when no DEK is configured it is the
// fail-closed PassthroughEncryptor, so step-up MFA refuses to operate on a
// secret it cannot seal/open rather than silently falling back to plaintext —
// matching how the connector secret path fails closed without a DEK.
func NewTOTPMFAVerifier(db *gorm.DB, enc crypto.Encryptor) (*TOTPMFAVerifier, error) {
	if db == nil {
		return nil, errors.New("mfa: TOTPMFAVerifier: db is nil")
	}
	if enc == nil {
		return nil, errors.New("mfa: TOTPMFAVerifier: encryptor is nil")
	}
	return &TOTPMFAVerifier{db: db, enc: enc, now: time.Now}, nil
}

// totpSecretAAD binds an enrolled secret's ciphertext to the (workspace, user)
// it belongs to. AES-GCM authenticates this AAD, so a secret row copied to
// another tenant or user (e.g. via SQL injection or a restore) fails to open
// rather than yielding a usable secret — a tenant-isolation guarantee on top of
// confidentiality.
func totpSecretAAD(workspaceID uuid.UUID, userID string) []byte {
	return []byte("totp-secret:" + workspaceID.String() + ":" + userID)
}

// SealTOTPSecret encrypts a base32 TOTP shared secret for storage in
// UserTOTPSecret.Secret, binding it to (workspace, user). Enrollment writers
// (and tests) MUST route through this so the column never holds plaintext; the
// verifier's read path opens it with the matching AAD.
func (v *TOTPMFAVerifier) SealTOTPSecret(workspaceID uuid.UUID, userID, base32Secret string) (string, error) {
	sealed, err := v.enc.Seal([]byte(base32Secret), totpSecretAAD(workspaceID, userID))
	if err != nil {
		return "", fmt.Errorf("mfa: TOTPMFAVerifier: seal secret: %w", err)
	}
	return sealed, nil
}

// TOTPEnrollment is the one-time provisioning payload returned by
// BeginEnrollment. It is sensitive: OtpauthURL embeds the shared secret, so it
// is shown to the enrolling user exactly once (to render the QR / key) and
// never persisted in plaintext or logged. The matching secret is already sealed
// in an unverified user_totp_secrets row by the time this is returned.
type TOTPEnrollment struct {
	// Secret is the base32-encoded shared secret, for manual entry when a user
	// cannot scan the QR code.
	Secret string
	// OtpauthURL is the otpauth://totp/... provisioning URI the client renders
	// as a QR code for the authenticator app.
	OtpauthURL string
}

// TOTPStatus reports a user's TOTP enrolment state for the account MFA summary.
type TOTPStatus struct {
	// Verified is true when the user has a confirmed, active TOTP secret usable
	// for step-up (a BeginEnrollment that was completed by FinishEnrollment).
	Verified bool
	// Pending is true when an unverified secret is awaiting FinishEnrollment.
	Pending bool
}

// BeginEnrollment provisions a fresh TOTP secret for (workspace, user): it
// generates an RFC 6238 secret, seals it into a new UNVERIFIED
// user_totp_secrets row, and returns the otpauth provisioning URI for the
// client to display. Any prior unverified (abandoned) row for the user is
// cleared first; an already-verified secret is left untouched so the user keeps
// working step-up until FinishEnrollment confirms the new one. issuer and
// accountName label the credential in the authenticator app.
func (v *TOTPMFAVerifier) BeginEnrollment(ctx context.Context, workspaceID uuid.UUID, userID, issuer, accountName string) (*TOTPEnrollment, error) {
	if workspaceID == uuid.Nil || userID == "" {
		return nil, errors.New("mfa: TOTPMFAVerifier: workspace and user are required")
	}
	if issuer == "" {
		issuer = "ShieldNet Access"
	}
	if accountName == "" {
		accountName = userID
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Period:      totpPeriodSeconds,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, fmt.Errorf("mfa: TOTPMFAVerifier: generate secret: %w", err)
	}
	sealed, err := v.SealTOTPSecret(workspaceID, userID, key.Secret())
	if err != nil {
		return nil, err
	}
	if err := v.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Drop any abandoned, never-confirmed attempt so a user only ever has
		// one pending secret at a time.
		if err := tx.Where("workspace_id = ? AND user_id = ? AND verified = ?", workspaceID, userID, false).
			Delete(&models.UserTOTPSecret{}).Error; err != nil {
			return err
		}
		return tx.Create(&models.UserTOTPSecret{
			WorkspaceID: workspaceID,
			UserID:      userID,
			Secret:      sealed,
			Verified:    false,
		}).Error
	}); err != nil {
		return nil, fmt.Errorf("mfa: TOTPMFAVerifier: store pending secret: %w", err)
	}
	return &TOTPEnrollment{Secret: key.Secret(), OtpauthURL: key.URL()}, nil
}

// FinishEnrollment confirms a pending TOTP secret by validating a code the user
// generated from it, proving their authenticator is configured. On success the
// pending row becomes the single active verified secret and any prior verified
// secret for the user is disabled, so exactly one secret is live. Returns
// ErrMFAFailed when there is no pending secret or the code is wrong.
func (v *TOTPMFAVerifier) FinishEnrollment(ctx context.Context, workspaceID uuid.UUID, userID, code string) error {
	if workspaceID == uuid.Nil || userID == "" {
		return fmt.Errorf("%w: workspace and user are required", ErrMFAFailed)
	}
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return fmt.Errorf("%w: TOTP code must be exactly 6 digits", ErrMFAFailed)
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return fmt.Errorf("%w: TOTP code must contain only digits", ErrMFAFailed)
		}
	}

	var pending models.UserTOTPSecret
	err := v.db.WithContext(ctx).
		Where("workspace_id = ? AND user_id = ? AND verified = ?", workspaceID, userID, false).
		Order("created_at DESC").
		First(&pending).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("%w: no pending TOTP enrollment", ErrMFAFailed)
		}
		return fmt.Errorf("mfa: TOTPMFAVerifier: load pending secret: %w", err)
	}

	plainSecret, err := v.enc.Open(pending.Secret, totpSecretAAD(workspaceID, userID))
	if err != nil {
		return fmt.Errorf("mfa: TOTPMFAVerifier: open pending secret: %w", err)
	}
	ok, vErr := totp.ValidateCustom(code, string(plainSecret), v.now(), totp.ValidateOpts{
		Period:    totpPeriodSeconds,
		Skew:      totpSkewSteps,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if vErr != nil {
		logger.Warnf(ctx, "mfa: TOTPMFAVerifier: enrollment validate error workspace_id=%s user_id=%s: %v", workspaceID, userID, vErr)
	}
	if !ok {
		return fmt.Errorf("%w: invalid TOTP code", ErrMFAFailed)
	}

	if err := v.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Retire any previously verified secret so exactly one remains active.
		if err := tx.Model(&models.UserTOTPSecret{}).
			Where("workspace_id = ? AND user_id = ? AND verified = ? AND id <> ?", workspaceID, userID, true, pending.ID).
			Update("disabled_at", v.now()).Error; err != nil {
			return err
		}
		return tx.Model(&models.UserTOTPSecret{}).
			Where("id = ?", pending.ID).
			Updates(map[string]any{"verified": true, "disabled_at": nil}).Error
	}); err != nil {
		return fmt.Errorf("mfa: TOTPMFAVerifier: confirm secret: %w", err)
	}
	logger.Infof(ctx, "mfa: TOTPMFAVerifier: TOTP enrolled workspace_id=%s user_id=%s", workspaceID, userID)
	return nil
}

// DisableTOTP removes a user's TOTP factor: it disables any verified secret and
// clears pending attempts. It is idempotent (no error when nothing is enrolled).
func (v *TOTPMFAVerifier) DisableTOTP(ctx context.Context, workspaceID uuid.UUID, userID string) error {
	if workspaceID == uuid.Nil || userID == "" {
		return errors.New("mfa: TOTPMFAVerifier: workspace and user are required")
	}
	return v.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("workspace_id = ? AND user_id = ? AND verified = ?", workspaceID, userID, false).
			Delete(&models.UserTOTPSecret{}).Error; err != nil {
			return err
		}
		return tx.Model(&models.UserTOTPSecret{}).
			Where("workspace_id = ? AND user_id = ? AND verified = ? AND disabled_at IS NULL", workspaceID, userID, true).
			Update("disabled_at", v.now()).Error
	})
}

// Status reports whether the user has a verified and/or pending TOTP secret, for
// the account MFA-methods summary.
func (v *TOTPMFAVerifier) Status(ctx context.Context, workspaceID uuid.UUID, userID string) (TOTPStatus, error) {
	if workspaceID == uuid.Nil || userID == "" {
		return TOTPStatus{}, errors.New("mfa: TOTPMFAVerifier: workspace and user are required")
	}
	var verified, pending int64
	if err := v.db.WithContext(ctx).Model(&models.UserTOTPSecret{}).
		Where("workspace_id = ? AND user_id = ? AND verified = ? AND disabled_at IS NULL", workspaceID, userID, true).
		Count(&verified).Error; err != nil {
		return TOTPStatus{}, fmt.Errorf("mfa: TOTPMFAVerifier: status: %w", err)
	}
	if err := v.db.WithContext(ctx).Model(&models.UserTOTPSecret{}).
		Where("workspace_id = ? AND user_id = ? AND verified = ?", workspaceID, userID, false).
		Count(&pending).Error; err != nil {
		return TOTPStatus{}, fmt.Errorf("mfa: TOTPMFAVerifier: status: %w", err)
	}
	return TOTPStatus{Verified: verified > 0, Pending: pending > 0}, nil
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

	// The stored secret is sealed at rest; open it with the (workspace, user)
	// AAD it was bound to. A decrypt failure is an integrity/availability fault
	// (wrong DEK, tampered row, or no DEK configured), not a user-facing bad
	// code, so it surfaces as a verifier error → 503 rather than ErrMFAFailed.
	plainSecret, err := v.enc.Open(secret.Secret, totpSecretAAD(workspaceID, userID))
	if err != nil {
		return fmt.Errorf("mfa: TOTPMFAVerifier: open secret: %w", err)
	}

	ok, vErr := totp.ValidateCustom(code, string(plainSecret), v.now(), totp.ValidateOpts{
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
//
// It returns a join function that blocks until the background goroutine has
// fully exited. Callers that own the lifecycle (cmd/ztna-api) cancel ctx and
// then call join() on shutdown so the loop is guaranteed to have stopped before
// the DB pool is closed — the same deterministic ordering the lifecycle
// scheduler uses. The returned func is safe to call exactly once; tests that do
// not care about shutdown ordering may ignore it.
func (v *TOTPMFAVerifier) StartUsedCodeCleanupLoop(ctx context.Context, interval, retention time.Duration) (join func()) {
	if interval <= 0 {
		interval = DefaultCleanupInterval
	}
	if retention <= 0 {
		retention = DefaultTOTPUsedCodeRetention
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
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
	return func() { <-done }
}

var _ MFAVerifier = (*TOTPMFAVerifier)(nil)
