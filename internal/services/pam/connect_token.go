package pam

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// ErrConnectToken is the single sentinel the gateway matches on for any
// redemption failure (unknown, already-consumed, or expired token). It is
// deliberately coarse so the wire-protocol handlers cannot leak which of those
// it was to an unauthenticated client probing tokens.
var ErrConnectToken = errors.New("pam: invalid or expired connect token")

// defaultLeaseTTL bounds how long a freshly minted connect token stays
// redeemable when the target sets no explicit lease.
const defaultLeaseTTL = 2 * time.Minute

// rawTokenBytes is the entropy of a connect token before base64url encoding.
const rawTokenBytes = 32

// LeasedSession is the in-memory bundle the gateway receives when it redeems a
// connect token: the resolved target, the opened upstream credential (delivered
// JIT, never persisted by the gateway), and the freshly created session row.
type LeasedSession struct {
	Target  *models.PAMTarget
	Secret  Secret
	Session *models.PAMSession
}

// Broker mints and redeems one-shot connect tokens. A token authorizes exactly
// one session against one target: the raw token is shown to the operator once
// at mint time and only its SHA-256 hash is stored, and redemption atomically
// flips pending → consumed so the same token can never open two sessions.
type Broker struct {
	db         *gorm.DB
	vault      *Vault
	stepUp     *StepUpGate
	defaultTTL time.Duration
	now        func() time.Time
}

// NewBroker wires a broker. vault opens the upstream credential at redeem time;
// stepUp gates minting a token for an MFA-required target.
func NewBroker(db *gorm.DB, vault *Vault, stepUp *StepUpGate) *Broker {
	return &Broker{
		db:         db,
		vault:      vault,
		stepUp:     stepUp,
		defaultTTL: defaultLeaseTTL,
		now:        time.Now,
	}
}

// SetClock overrides the time source (tests).
func (b *Broker) SetClock(now func() time.Time) {
	if now != nil {
		b.now = now
	}
}

// MintInput requests a one-shot connect token for a target on behalf of a
// subject. StepUpToken is required when the target is MFA-gated: minting a
// token for such a target is itself the sensitive operation, so it carries the
// step-up assertion and the redeemed token then authorizes the session without
// the wire-protocol proxy needing to drive OIDC.
type MintInput struct {
	WorkspaceID uuid.UUID
	TargetID    uuid.UUID
	Subject     string
	StepUpToken string
	Actor       string
}

// MintConnectToken issues a token and returns the raw secret value (shown
// once). The caller hands the raw token to the operator; only its hash is
// persisted.
func (b *Broker) MintConnectToken(ctx context.Context, in MintInput) (rawToken string, token *models.PAMConnectToken, err error) {
	if in.WorkspaceID == uuid.Nil || in.TargetID == uuid.Nil {
		return "", nil, fmt.Errorf("%w: workspace_id and target_id are required", ErrValidation)
	}
	if in.Subject == "" {
		return "", nil, fmt.Errorf("%w: subject is required", ErrValidation)
	}
	target, err := b.vault.GetTarget(ctx, in.WorkspaceID, in.TargetID)
	if err != nil {
		return "", nil, err
	}
	if target.RequireMFA {
		if !b.stepUp.Enabled() {
			return "", nil, fmt.Errorf("%w: target requires MFA but step-up gate is not configured", ErrStepUpInvalid)
		}
		var ws models.Workspace
		if err := b.db.WithContext(ctx).Where("id = ?", in.WorkspaceID).Take(&ws).Error; err != nil {
			return "", nil, fmt.Errorf("pam: resolve workspace tenant for step-up: %w", err)
		}
		if err := b.stepUp.Require(in.Subject, ws.IAMCoreTenantID, in.StepUpToken); err != nil {
			return "", nil, err
		}
	}

	raw, hash, err := newToken()
	if err != nil {
		return "", nil, err
	}
	ttl := b.defaultTTL
	if target.LeaseTTLSeconds > 0 {
		ttl = time.Duration(target.LeaseTTLSeconds) * time.Second
	}
	now := b.now()
	row := &models.PAMConnectToken{
		WorkspaceID: in.WorkspaceID,
		TargetID:    in.TargetID,
		TokenHash:   hash,
		Subject:     in.Subject,
		State:       models.PAMConnectTokenPending,
		ExpiresAt:   now.Add(ttl),
	}
	if err := b.db.WithContext(ctx).Create(row).Error; err != nil {
		return "", nil, fmt.Errorf("pam: mint connect token: %w", err)
	}
	if err := b.vault.audit(ctx, in.WorkspaceID, in.Actor, "pam.connect_token.minted", in.TargetID.String(), map[string]any{
		"subject":    in.Subject,
		"expires_at": row.ExpiresAt.UTC().Format(time.RFC3339),
	}); err != nil {
		return "", nil, err
	}
	return raw, row, nil
}

// RedeemConnectToken validates a raw token and, on success, atomically consumes
// it and opens a session. It is the gateway's entrypoint: the returned
// LeasedSession carries the opened credential for in-memory JIT injection.
// Redemption is replay-safe — the pending → consumed update is conditional on
// the token still being pending, so two concurrent redemptions of the same
// token cannot both succeed.
func (b *Broker) RedeemConnectToken(ctx context.Context, rawToken, clientAddr string) (*LeasedSession, error) {
	hash := hashToken(rawToken)
	now := b.now()

	var leased *LeasedSession
	err := b.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var token models.PAMConnectToken
		err := tx.Where("token_hash = ?", hash).Take(&token).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrConnectToken
		}
		if err != nil {
			return fmt.Errorf("pam: load connect token: %w", err)
		}
		if token.State != models.PAMConnectTokenPending {
			return ErrConnectToken
		}
		if now.After(token.ExpiresAt) {
			// Best-effort expiry stamp so a swept token reads as expired, not
			// pending; the redemption still fails regardless of this update.
			tx.Model(&token).Updates(map[string]any{"state": models.PAMConnectTokenExpired, "updated_at": now})
			return ErrConnectToken
		}

		var target models.PAMTarget
		if err := tx.Where("workspace_id = ? AND id = ?", token.WorkspaceID, token.TargetID).
			Take(&target).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrTargetNotFound
			}
			return fmt.Errorf("pam: load target for redemption: %w", err)
		}

		session := &models.PAMSession{
			WorkspaceID: token.WorkspaceID,
			TargetID:    token.TargetID,
			Subject:     token.Subject,
			Protocol:    target.Protocol,
			State:       models.PAMSessionActive,
			ClientAddr:  clientAddr,
			StartedAt:   now,
		}
		session.ID = uuid.New()
		session.ReplayKey = fmt.Sprintf("sessions/%s/replay.bin", session.ID)
		if err := tx.Create(session).Error; err != nil {
			return fmt.Errorf("pam: create session: %w", err)
		}

		// Conditional consume: only flip a still-pending token. RowsAffected==0
		// means a concurrent redemption won the race, so this one must fail.
		res := tx.Model(&models.PAMConnectToken{}).
			Where("id = ? AND state = ?", token.ID, models.PAMConnectTokenPending).
			Updates(map[string]any{
				"state":       models.PAMConnectTokenConsumed,
				"consumed_at": now,
				"session_id":  session.ID,
				"updated_at":  now,
			})
		if res.Error != nil {
			return fmt.Errorf("pam: consume connect token: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrConnectToken
		}

		secret, err := b.vault.OpenSecret(ctx, &target)
		if err != nil {
			return err
		}
		leased = &LeasedSession{Target: &target, Secret: secret, Session: session}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if err := b.vault.audit(ctx, leased.Session.WorkspaceID, leased.Session.Subject, "pam.session.opened", leased.Target.ID.String(), map[string]any{
		"session_id":  leased.Session.ID.String(),
		"protocol":    leased.Target.Protocol,
		"client_addr": clientAddr,
	}); err != nil {
		return nil, err
	}
	return leased, nil
}

// newToken returns a fresh random raw token and its storage hash.
func newToken() (raw, hash string, err error) {
	buf := make([]byte, rawTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("pam: generate connect token: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	return raw, hashToken(raw), nil
}

// hashToken returns the hex SHA-256 of a raw token, the only form persisted.
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
