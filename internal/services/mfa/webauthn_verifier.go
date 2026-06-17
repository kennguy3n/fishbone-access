package mfa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// WebAuthn ceremony kinds, used as the third primary-key column of
// webauthn_challenges so one registration and one authentication challenge can
// be outstanding per user at a time.
const (
	ceremonyRegistration   = "registration"
	ceremonyAuthentication = "authentication"
)

// DefaultWebAuthnChallengeTTL bounds how long a server-issued ceremony
// challenge stays valid. A challenge is a one-shot nonce that must be answered
// promptly by an interactive user; a short window limits the time an
// intercepted (but unanswered) challenge could be useful and keeps the
// challenge table small. It is independent of the go-webauthn session's own
// optional expiry — this verifier always enforces its own TTL on the row.
const DefaultWebAuthnChallengeTTL = 5 * time.Minute

// DefaultWebAuthnChallengeCleanupInterval is the cadence
// StartChallengeCleanupLoop sweeps expired, never-consumed challenges when the
// caller passes 0.
const DefaultWebAuthnChallengeCleanupInterval = 5 * time.Minute

// defaultRPDisplayName is used when the caller leaves RPDisplayName empty; the
// go-webauthn library refuses to begin a registration without one.
const defaultRPDisplayName = "ShieldNet Access"

// WebAuthnSettings is the relying-party configuration the WebAuthn verifier
// needs, decoupled from the config package so this service layer does not
// depend on it. cmd/ztna-api maps config.WebAuthnConfig onto this.
type WebAuthnSettings struct {
	// RPID is the relying-party identifier (registrable domain, no scheme/port).
	RPID string
	// RPDisplayName is the human-readable relying-party name shown by some
	// authenticators during enrolment. Defaults to defaultRPDisplayName.
	RPDisplayName string
	// RPOrigins is the allow-list of fully-qualified origins a ceremony may be
	// completed from.
	RPOrigins []string
}

// WebAuthnMFAVerifier implements MFAVerifier with W3C WebAuthn/FIDO2 assertions
// — a phishing-resistant possession factor (security key or platform
// authenticator) — alongside, not replacing, the TOTP verifier behind the
// composite step-up gate.
//
// All cryptographic protocol handling (challenge binding, origin/RPID checks,
// attestation, signature verification, signature-counter clone detection) is
// delegated to go-webauthn. This type owns persistence and the step-up
// contract: it seals each enrolled credential at rest, issues and single-uses
// short-lived challenges, and maps every failure onto the fail-closed
// MFAVerifier semantics (ErrMFAFailed for a denial; a wrapped error → 503 for
// an infrastructure/integrity fault such as a sealing-key problem).
type WebAuthnMFAVerifier struct {
	db  *gorm.DB
	enc crypto.Encryptor
	web *webauthn.WebAuthn
	ttl time.Duration
	now func() time.Time // injectable for tests
}

// NewWebAuthnMFAVerifier constructs a verifier backed by db, sealing enrolled
// credentials at rest with enc (the same DEK-backed envelope encryptor used for
// connector credentials and TOTP secrets; the fail-closed PassthroughEncryptor
// when no DEK is configured, so WebAuthn refuses to persist a credential it
// cannot seal rather than storing public-key material in the clear). settings
// must carry a valid RPID and at least one origin (see WebAuthnConfig.Configured).
func NewWebAuthnMFAVerifier(db *gorm.DB, enc crypto.Encryptor, settings WebAuthnSettings) (*WebAuthnMFAVerifier, error) {
	if db == nil {
		return nil, errors.New("mfa: WebAuthnMFAVerifier: db is nil")
	}
	if enc == nil {
		return nil, errors.New("mfa: WebAuthnMFAVerifier: encryptor is nil")
	}
	if settings.RPID == "" {
		return nil, errors.New("mfa: WebAuthnMFAVerifier: RPID is required")
	}
	if len(settings.RPOrigins) == 0 {
		return nil, errors.New("mfa: WebAuthnMFAVerifier: at least one RP origin is required")
	}
	displayName := settings.RPDisplayName
	if displayName == "" {
		displayName = defaultRPDisplayName
	}
	web, err := webauthn.New(&webauthn.Config{
		RPID:          settings.RPID,
		RPDisplayName: displayName,
		RPOrigins:     settings.RPOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// Prefer (not require) user verification: a PIN/biometric upgrades
			// the assertion to two-factor-on-the-key, but requiring it would
			// reject otherwise-valid roaming keys that can't do UV. The factor
			// is still "something you have" at minimum.
			UserVerification: protocol.VerificationPreferred,
			// Allow both roaming (security key) and platform (Touch ID/Windows
			// Hello) authenticators; do not constrain residentKey so a key is
			// not forced to consume a discoverable-credential slot.
			ResidentKey: protocol.ResidentKeyRequirementDiscouraged,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("mfa: WebAuthnMFAVerifier: configure relying party: %w", err)
	}
	return &WebAuthnMFAVerifier{db: db, enc: enc, web: web, ttl: DefaultWebAuthnChallengeTTL, now: time.Now}, nil
}

// SetClock overrides the time source. Test-only; a nil function restores
// time.Now.
func (v *WebAuthnMFAVerifier) SetClock(now func() time.Time) {
	if now == nil {
		v.now = time.Now
		return
	}
	v.now = now
}

// userHandle derives the stable, opaque WebAuthn user handle for (workspace,
// user). The handle is bound into every credential at registration and checked
// against the stored credential at assertion, so it must be deterministic
// across restarts and the same for both ceremonies. A 32-byte SHA-256 digest is
// well under the 64-byte handle limit and reveals neither the workspace nor the
// user id (which are not meant to be exposed in the handle).
func userHandle(workspaceID uuid.UUID, userID string) []byte {
	sum := sha256.Sum256([]byte("webauthn-user:" + workspaceID.String() + ":" + userID))
	return sum[:]
}

// webAuthnCredentialAAD binds a sealed credential record to the (workspace,
// user, credential id) it belongs to. AES-GCM authenticates this AAD, so a
// credential row copied to another tenant/user, or re-pointed at a different
// credential id, fails to open rather than yielding a usable public key — a
// tenant-isolation guarantee on top of confidentiality.
func webAuthnCredentialAAD(workspaceID uuid.UUID, userID string, credentialID []byte) []byte {
	return []byte("webauthn-cred:" + workspaceID.String() + ":" + userID + ":" + hex.EncodeToString(credentialID))
}

// webAuthnUser adapts a user's stored, decoded credentials to webauthn.User.
// Credentials are decoded once at load time (WebAuthnCredentials cannot return
// an error), so a decrypt/decode fault surfaces from the loader as a verifier
// error rather than being silently swallowed here.
type webAuthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webAuthnUser) WebAuthnName() string                       { return u.name }
func (u *webAuthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// loadUser builds the webauthn.User adapter for (workspace, user) by loading and
// unsealing every enrolled credential. A decrypt/decode failure is an
// integrity/availability fault (wrong DEK, tampered row, or no DEK configured),
// so it is returned as an error (→ 503) rather than degrading to "no
// credentials"; downgrading would let a sealing-key outage silently weaken
// step-up to TOTP-or-nothing.
func (v *WebAuthnMFAVerifier) loadUser(ctx context.Context, workspaceID uuid.UUID, userID, displayName string) (*webAuthnUser, error) {
	var rows []models.WebAuthnCredential
	if err := v.db.WithContext(ctx).
		Where("workspace_id = ? AND user_id = ?", workspaceID, userID).
		Order("created_at").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("mfa: WebAuthnMFAVerifier: load credentials: %w", err)
	}

	creds := make([]webauthn.Credential, 0, len(rows))
	for i := range rows {
		cred, err := v.openCredential(workspaceID, userID, rows[i])
		if err != nil {
			return nil, err
		}
		creds = append(creds, cred)
	}

	if displayName == "" {
		displayName = userID
	}
	return &webAuthnUser{
		id:          userHandle(workspaceID, userID),
		name:        userID,
		displayName: displayName,
		credentials: creds,
	}, nil
}

// openCredential unseals one stored credential row into a webauthn.Credential.
func (v *WebAuthnMFAVerifier) openCredential(workspaceID uuid.UUID, userID string, row models.WebAuthnCredential) (webauthn.Credential, error) {
	plain, err := v.enc.Open(row.Sealed, webAuthnCredentialAAD(workspaceID, userID, row.CredentialID))
	if err != nil {
		return webauthn.Credential{}, fmt.Errorf("mfa: WebAuthnMFAVerifier: open credential %s: %w", row.ID, err)
	}
	var cred webauthn.Credential
	if err := json.Unmarshal(plain, &cred); err != nil {
		return webauthn.Credential{}, fmt.Errorf("mfa: WebAuthnMFAVerifier: decode credential %s: %w", row.ID, err)
	}
	return cred, nil
}

// sealCredential serializes and seals a webauthn.Credential for storage.
func (v *WebAuthnMFAVerifier) sealCredential(workspaceID uuid.UUID, userID string, cred *webauthn.Credential) (string, error) {
	plain, err := json.Marshal(cred)
	if err != nil {
		return "", fmt.Errorf("mfa: WebAuthnMFAVerifier: encode credential: %w", err)
	}
	sealed, err := v.enc.Seal(plain, webAuthnCredentialAAD(workspaceID, userID, cred.ID))
	if err != nil {
		return "", fmt.Errorf("mfa: WebAuthnMFAVerifier: seal credential: %w", err)
	}
	return sealed, nil
}

// putChallenge upserts the single outstanding challenge for (workspace, user,
// ceremony), replacing any prior one so a fresh Begin* always supersedes a
// stale challenge. The session data is stored verbatim (it is a nonce, not a
// long-term secret).
func (v *WebAuthnMFAVerifier) putChallenge(ctx context.Context, workspaceID uuid.UUID, userID, ceremony string, session *webauthn.SessionData) error {
	raw, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("mfa: WebAuthnMFAVerifier: encode session: %w", err)
	}
	now := v.now()
	row := models.WebAuthnChallenge{
		WorkspaceID: workspaceID,
		UserID:      userID,
		Ceremony:    ceremony,
		SessionData: raw,
		ExpiresAt:   now.Add(v.ttl),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := v.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "workspace_id"}, {Name: "user_id"}, {Name: "ceremony"}},
			DoUpdates: clause.AssignmentColumns([]string{"session_data", "expires_at", "updated_at"}),
		}).
		Create(&row).Error; err != nil {
		return fmt.Errorf("mfa: WebAuthnMFAVerifier: store challenge: %w", err)
	}
	return nil
}

// takeChallenge atomically consumes the outstanding challenge for (workspace,
// user, ceremony): it DELETEs the row and decodes it, returning ok=false when
// no live challenge exists. The atomic delete is the single-use guarantee — two
// concurrent verifications of the same assertion resolve to exactly one
// consumer; the loser sees ok=false. An expired row is treated as absent (and
// removed). A decode error of a row we did delete is reported as err so a
// corrupt challenge is loud rather than silently a denial.
func (v *WebAuthnMFAVerifier) takeChallenge(ctx context.Context, workspaceID uuid.UUID, userID, ceremony string) (session *webauthn.SessionData, ok bool, err error) {
	var row models.WebAuthnChallenge
	res := v.db.WithContext(ctx).
		Clauses(clause.Returning{}).
		Where("workspace_id = ? AND user_id = ? AND ceremony = ?", workspaceID, userID, ceremony).
		Delete(&row)
	if res.Error != nil {
		return nil, false, fmt.Errorf("mfa: WebAuthnMFAVerifier: consume challenge: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return nil, false, nil
	}
	if row.ExpiresAt.Before(v.now()) {
		return nil, false, nil
	}
	var sess webauthn.SessionData
	if err := json.Unmarshal(row.SessionData, &sess); err != nil {
		return nil, false, fmt.Errorf("mfa: WebAuthnMFAVerifier: decode challenge session: %w", err)
	}
	return &sess, true, nil
}

// BeginRegistration starts enrolment of a new authenticator for (workspace,
// user): it issues the credential-creation options the browser passes to
// navigator.credentials.create() and stores the matching challenge. Already
// enrolled credentials are excluded so the same authenticator cannot be
// registered twice. displayName is shown by some authenticators; pass "" to
// default to the user id.
func (v *WebAuthnMFAVerifier) BeginRegistration(ctx context.Context, workspaceID uuid.UUID, userID, displayName string) (*protocol.CredentialCreation, error) {
	if workspaceID == uuid.Nil || userID == "" {
		return nil, errors.New("mfa: WebAuthnMFAVerifier: workspace and user are required")
	}
	user, err := v.loadUser(ctx, workspaceID, userID, displayName)
	if err != nil {
		return nil, err
	}
	exclusions := make([]protocol.CredentialDescriptor, 0, len(user.credentials))
	for i := range user.credentials {
		exclusions = append(exclusions, user.credentials[i].Descriptor())
	}
	creation, session, err := v.web.BeginRegistration(user, webauthn.WithExclusions(exclusions))
	if err != nil {
		return nil, fmt.Errorf("mfa: WebAuthnMFAVerifier: begin registration: %w", err)
	}
	if err := v.putChallenge(ctx, workspaceID, userID, ceremonyRegistration, session); err != nil {
		return nil, err
	}
	return creation, nil
}

// FinishRegistration completes enrolment: it verifies the authenticator's
// attestation response against the outstanding registration challenge and, on
// success, persists the new credential sealed at rest. friendlyName is an
// optional human label for the credential list. The challenge is single-used
// regardless of outcome (a fresh BeginRegistration is required to retry).
func (v *WebAuthnMFAVerifier) FinishRegistration(ctx context.Context, workspaceID uuid.UUID, userID, friendlyName string, body []byte) (*models.WebAuthnCredential, error) {
	if workspaceID == uuid.Nil || userID == "" {
		return nil, errors.New("mfa: WebAuthnMFAVerifier: workspace and user are required")
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("%w: empty registration response", ErrMFAFailed)
	}
	session, ok, err := v.takeChallenge(ctx, workspaceID, userID, ceremonyRegistration)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: no outstanding registration challenge", ErrMFAFailed)
	}

	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: malformed registration response: %v", ErrMFAFailed, err)
	}
	user, err := v.loadUser(ctx, workspaceID, userID, "")
	if err != nil {
		return nil, err
	}
	cred, err := v.web.CreateCredential(user, *session, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMFAFailed, err)
	}

	sealed, err := v.sealCredential(workspaceID, userID, cred)
	if err != nil {
		return nil, err
	}
	row := models.WebAuthnCredential{
		WorkspaceID:  workspaceID,
		UserID:       userID,
		CredentialID: cred.ID,
		Sealed:       sealed,
		FriendlyName: friendlyName,
		SignCount:    cred.Authenticator.SignCount,
		CloneWarning: cred.Authenticator.CloneWarning,
		AAGUID:       cred.Authenticator.AAGUID,
	}
	if err := v.db.WithContext(ctx).Create(&row).Error; err != nil {
		return nil, fmt.Errorf("mfa: WebAuthnMFAVerifier: persist credential: %w", err)
	}
	logger.Infof(ctx, "mfa: WebAuthnMFAVerifier: credential enrolled workspace_id=%s user_id=%s credential=%s", workspaceID, userID, row.ID)
	return &row, nil
}

// BeginStepUp starts an authentication ceremony for (workspace, user): it issues
// the assertion-request options the browser passes to
// navigator.credentials.get() and stores the matching challenge. The actual
// assertion is later submitted through the X-MFA-Assertion header and verified
// by VerifyStepUp. Returns ErrMFAFailed when the user has no enrolled
// credential (nothing to assert with).
func (v *WebAuthnMFAVerifier) BeginStepUp(ctx context.Context, workspaceID uuid.UUID, userID string) (*protocol.CredentialAssertion, error) {
	if workspaceID == uuid.Nil || userID == "" {
		return nil, errors.New("mfa: WebAuthnMFAVerifier: workspace and user are required")
	}
	user, err := v.loadUser(ctx, workspaceID, userID, "")
	if err != nil {
		return nil, err
	}
	if len(user.credentials) == 0 {
		return nil, fmt.Errorf("%w: no WebAuthn credential enrolled", ErrMFAFailed)
	}
	assertion, session, err := v.web.BeginLogin(user)
	if err != nil {
		return nil, fmt.Errorf("mfa: WebAuthnMFAVerifier: begin step-up: %w", err)
	}
	if err := v.putChallenge(ctx, workspaceID, userID, ceremonyAuthentication, session); err != nil {
		return nil, err
	}
	return assertion, nil
}

// VerifyStepUp validates a WebAuthn assertion against the user's enrolled
// credentials and the outstanding authentication challenge, then single-uses
// the challenge so the assertion cannot be replayed. It implements MFAVerifier.
//
// Failure mapping is fail-closed: a missing/expired challenge, a malformed or
// non-verifying assertion, an unknown credential, or a consumed (replayed)
// challenge all return ErrMFAFailed (→ 403). An infrastructure/integrity fault
// (DB error, or a sealing-key problem opening a stored credential) returns a
// wrapped error (→ 503), never a silent allow. A signature-counter regression
// (possible authenticator clone) is logged loudly but, per the WebAuthn spec's
// guidance, is NOT by itself fatal to this assertion.
func (v *WebAuthnMFAVerifier) VerifyStepUp(ctx context.Context, workspaceID uuid.UUID, userID, scope string, assertion []byte) error {
	if workspaceID == uuid.Nil || userID == "" {
		return fmt.Errorf("%w: workspace and user are required", ErrMFAFailed)
	}
	if len(assertion) == 0 {
		return ErrMFAFailed
	}

	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(assertion))
	if err != nil {
		return fmt.Errorf("%w: malformed assertion: %v", ErrMFAFailed, err)
	}

	user, err := v.loadUser(ctx, workspaceID, userID, "")
	if err != nil {
		return err
	}
	if len(user.credentials) == 0 {
		return fmt.Errorf("%w: no WebAuthn credential enrolled", ErrMFAFailed)
	}

	session, ok, err := v.takeChallenge(ctx, workspaceID, userID, ceremonyAuthentication)
	if err != nil {
		return err
	}
	if !ok {
		// Either no challenge was issued, it expired, or a concurrent request
		// already consumed it (replay). All deny.
		logger.Warnf(ctx, "mfa: WebAuthnMFAVerifier: no live step-up challenge workspace_id=%s user_id=%s scope=%s", workspaceID, userID, scope)
		return fmt.Errorf("%w: no outstanding step-up challenge", ErrMFAFailed)
	}

	cred, err := v.web.ValidateLogin(user, *session, parsed)
	if err != nil {
		logger.Warnf(ctx, "mfa: WebAuthnMFAVerifier: assertion rejected workspace_id=%s user_id=%s scope=%s: %v", workspaceID, userID, scope, err)
		return fmt.Errorf("%w: assertion did not verify", ErrMFAFailed)
	}

	// Persist the post-assertion authenticator state (monotonic counter, clone
	// verdict, last-used) so a future regression is detectable and the admin
	// list reflects reality. A failure to persist must not retroactively allow
	// or deny the assertion that already verified, so it is logged, not fatal.
	if err := v.updateCredentialState(ctx, workspaceID, userID, scope, cred); err != nil {
		logger.Warnf(ctx, "mfa: WebAuthnMFAVerifier: persist credential state workspace_id=%s user_id=%s scope=%s: %v", workspaceID, userID, scope, err)
	}
	return nil
}

// updateCredentialState re-seals the verified credential and updates the
// monotonic sign counter, clone-warning verdict, and last-used timestamp on the
// matching stored row. A clone warning (the authenticator's counter went
// backwards) is surfaced loudly: it is the standard signal of a possibly cloned
// authenticator and an operator should investigate and consider revoking the
// credential.
func (v *WebAuthnMFAVerifier) updateCredentialState(ctx context.Context, workspaceID uuid.UUID, userID, scope string, cred *webauthn.Credential) error {
	if cred.Authenticator.CloneWarning {
		logger.Warnf(ctx, "mfa: WebAuthnMFAVerifier: SIGNATURE COUNTER REGRESSION (possible cloned authenticator) workspace_id=%s user_id=%s scope=%s", workspaceID, userID, scope)
	}
	sealed, err := v.sealCredential(workspaceID, userID, cred)
	if err != nil {
		return err
	}
	now := v.now()
	res := v.db.WithContext(ctx).
		Model(&models.WebAuthnCredential{}).
		Where("workspace_id = ? AND credential_id = ?", workspaceID, cred.ID).
		Updates(map[string]any{
			"sealed":        sealed,
			"sign_count":    cred.Authenticator.SignCount,
			"clone_warning": cred.Authenticator.CloneWarning,
			"last_used_at":  &now,
			"updated_at":    now,
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("credential %x not found for update", cred.ID)
	}
	return nil
}

// ListCredentials returns a user's enrolled authenticators for display. The
// returned rows carry only non-sensitive metadata: the sealed envelope, raw
// credential id, and AAGUID are hidden by the model's json tags, so a caller
// can serialize these directly without leaking key material.
func (v *WebAuthnMFAVerifier) ListCredentials(ctx context.Context, workspaceID uuid.UUID, userID string) ([]models.WebAuthnCredential, error) {
	if workspaceID == uuid.Nil || userID == "" {
		return nil, errors.New("mfa: WebAuthnMFAVerifier: workspace and user are required")
	}
	var rows []models.WebAuthnCredential
	if err := v.db.WithContext(ctx).
		Where("workspace_id = ? AND user_id = ?", workspaceID, userID).
		Order("created_at").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("mfa: WebAuthnMFAVerifier: list credentials: %w", err)
	}
	return rows, nil
}

// DeleteCredential removes one of the user's enrolled authenticators by its
// row id. It is workspace- and user-scoped so a caller can only delete a
// credential they own. Returns gorm.ErrRecordNotFound when no such credential
// exists for the (workspace, user).
func (v *WebAuthnMFAVerifier) DeleteCredential(ctx context.Context, workspaceID uuid.UUID, userID string, credentialRowID uuid.UUID) error {
	if workspaceID == uuid.Nil || userID == "" || credentialRowID == uuid.Nil {
		return errors.New("mfa: WebAuthnMFAVerifier: workspace, user, and credential id are required")
	}
	res := v.db.WithContext(ctx).
		Where("workspace_id = ? AND user_id = ? AND id = ?", workspaceID, userID, credentialRowID).
		Delete(&models.WebAuthnCredential{})
	if res.Error != nil {
		return fmt.Errorf("mfa: WebAuthnMFAVerifier: delete credential: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// CleanupExpiredChallenges deletes challenge rows whose ExpiresAt is past.
// Falling behind is never a security regression (an expired challenge is
// already rejected by takeChallenge) — it only grows the table — so callers run
// it best-effort on a periodic loop.
func (v *WebAuthnMFAVerifier) CleanupExpiredChallenges(ctx context.Context) (int64, error) {
	res := v.db.WithContext(ctx).
		Where("expires_at < ?", v.now()).
		Delete(&models.WebAuthnChallenge{})
	if res.Error != nil {
		return 0, fmt.Errorf("mfa: WebAuthnMFAVerifier: cleanup challenges: %w", res.Error)
	}
	return res.RowsAffected, nil
}

// StartChallengeCleanupLoop runs CleanupExpiredChallenges on a fixed cadence
// until ctx is cancelled, mirroring TOTPMFAVerifier.StartUsedCodeCleanupLoop. It
// returns a join function that blocks until the background goroutine has exited,
// so cmd/ztna-api can cancel ctx then join() before closing the DB pool. The
// first sweep happens after one interval (not at boot) so replicas don't
// stampede the DB on startup. interval defaults to
// DefaultWebAuthnChallengeCleanupInterval when non-positive.
func (v *WebAuthnMFAVerifier) StartChallengeCleanupLoop(ctx context.Context, interval time.Duration) (join func()) {
	if interval <= 0 {
		interval = DefaultWebAuthnChallengeCleanupInterval
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
				if ctx.Err() != nil {
					return
				}
				if _, err := v.CleanupExpiredChallenges(ctx); err != nil {
					if ctx.Err() != nil ||
						errors.Is(err, context.Canceled) ||
						errors.Is(err, context.DeadlineExceeded) ||
						errors.Is(err, sql.ErrTxDone) {
						return
					}
					logger.Warnf(ctx, "mfa: WebAuthnMFAVerifier: cleanup sweep failed: %v", err)
				}
			}
		}
	}()
	return func() { <-done }
}

var _ MFAVerifier = (*WebAuthnMFAVerifier)(nil)
