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

// LeaseValidator binds the connect-token broker to the JIT lease state machine.
// When a token carries a LeaseID the broker calls these inside the
// mint/redeem transaction so the lease's liveness is checked against the same
// snapshot as the token mutation — a lease that expired or was revoked a
// moment earlier cannot have a token minted or redeemed against it. It is
// satisfied by *PAMLeaseService; declaring it as an interface keeps the broker
// unit-testable with a fake and documents the exact coupling.
type LeaseValidator interface {
	// ValidateLeaseTx returns nil iff the lease is live (granted, not revoked,
	// not expired) and bound to the given subject and target.
	ValidateLeaseTx(ctx context.Context, tx *gorm.DB, workspaceID, leaseID uuid.UUID, subject string, targetID uuid.UUID) error
	// MarkActivatedTx flips the lease approved→active on first session open.
	MarkActivatedTx(ctx context.Context, tx *gorm.DB, workspaceID, leaseID uuid.UUID, now time.Time) error
}

// Broker mints and redeems one-shot connect tokens. A token authorizes exactly
// one session against one target: the raw token is shown to the operator once
// at mint time and only its SHA-256 hash is stored, and redemption atomically
// flips pending → consumed so the same token can never open two sessions.
type Broker struct {
	db         *gorm.DB
	vault      *Vault
	stepUp     *StepUpGate
	leases     LeaseValidator
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

// SetLeaseValidator installs the JIT-lease binding. Once set, a token minted
// with a LeaseID is validated against the lease at mint and redeem; tokens
// minted without a LeaseID are unaffected (the legacy direct-mint path). When
// no validator is set a token carrying a LeaseID is rejected fail-closed at
// mint — a lease-bound token whose lease cannot be checked must never be issued.
func (b *Broker) SetLeaseValidator(v LeaseValidator) { b.leases = v }

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
	// LeaseID, when set, binds the token to a JIT lease. The broker validates
	// the lease is live and bound to (Subject, TargetID) before minting, and
	// re-validates at redeem. Nil selects the legacy direct-mint path.
	LeaseID *uuid.UUID
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
	// Lease binding: a token may only be minted against a live lease bound to
	// the same subject and target. Fail-closed: a LeaseID with no configured
	// validator is rejected rather than silently minting an unchecked token.
	if in.LeaseID != nil {
		if b.leases == nil {
			return "", nil, fmt.Errorf("%w: lease-bound mint requested but lease validator is not configured", ErrValidation)
		}
		if err := b.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			return b.leases.ValidateLeaseTx(ctx, tx, in.WorkspaceID, *in.LeaseID, in.Subject, in.TargetID)
		}); err != nil {
			return "", nil, err
		}
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
		LeaseID:     in.LeaseID,
	}
	// A lease-bound token must never outlive its lease window: clamp the token
	// TTL so an expired lease cannot still have a redeemable token. The redeem
	// path re-validates the lease regardless, but clamping keeps the token's own
	// expires_at honest for the operator and the sweep.
	if in.LeaseID != nil {
		if lease, lerr := b.loadLeaseExpiry(ctx, in.WorkspaceID, *in.LeaseID); lerr == nil && lease != nil && lease.Before(row.ExpiresAt) {
			row.ExpiresAt = *lease
		}
	}
	// Create the token row and its chained audit record in one transaction so a
	// minted token can never exist without an audit trail (and a failed audit
	// append rolls the token back rather than leaving an orphaned pending row
	// that only the lease sweep can clean up). Mirrors RedeemConnectToken.
	if err := b.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(row).Error; err != nil {
			return fmt.Errorf("pam: mint connect token: %w", err)
		}
		return b.vault.auditTx(ctx, tx, in.WorkspaceID, in.Actor, "pam.connect_token.minted", in.TargetID.String(), map[string]any{
			"subject":    in.Subject,
			"expires_at": row.ExpiresAt.UTC().Format(time.RFC3339),
		})
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

		// Re-validate the lease against the same snapshot as the consume. A lease
		// that expired or was revoked between mint and redeem must fail closed —
		// the credential is brokered only while the lease is live. The coarse
		// ErrConnectToken is returned (not the specific lease error) so an
		// unauthenticated client probing the wire cannot distinguish "lease
		// expired" from "unknown token".
		if token.LeaseID != nil {
			if b.leases == nil {
				return ErrConnectToken
			}
			if verr := b.leases.ValidateLeaseTx(ctx, tx, token.WorkspaceID, *token.LeaseID, token.Subject, token.TargetID); verr != nil {
				return ErrConnectToken
			}
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
			LeaseID:     token.LeaseID,
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

		// First session open against the lease flips it approved→active (idempotent).
		if token.LeaseID != nil && b.leases != nil {
			if err := b.leases.MarkActivatedTx(ctx, tx, token.WorkspaceID, *token.LeaseID, now); err != nil {
				return err
			}
		}

		secret, err := b.vault.OpenSecret(ctx, &target)
		if err != nil {
			return err
		}

		// Append the session-opened event inside the same transaction as the
		// token consume + session create, so a privileged session can never be
		// opened without its chained audit record (and a failed append rolls
		// the whole redemption back, leaving the token still usable).
		if err := b.vault.auditTx(ctx, tx, session.WorkspaceID, session.Subject, "pam.session.opened", target.ID.String(), map[string]any{
			"session_id":  session.ID.String(),
			"protocol":    target.Protocol,
			"client_addr": clientAddr,
		}); err != nil {
			return err
		}
		leased = &LeasedSession{Target: &target, Secret: secret, Session: session}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return leased, nil
}

// loadLeaseExpiry returns a lease's expires_at for TTL clamping at mint time,
// or nil when the lease has no expiry (not yet approved). It is a best-effort
// read outside any transaction; the authoritative liveness check is
// ValidateLeaseTx inside the mint/redeem transaction.
func (b *Broker) loadLeaseExpiry(ctx context.Context, workspaceID, leaseID uuid.UUID) (*time.Time, error) {
	var lease models.PAMLease
	if err := b.db.WithContext(ctx).
		Select("expires_at").
		Where("workspace_id = ? AND id = ?", workspaceID, leaseID).
		Take(&lease).Error; err != nil {
		return nil, err
	}
	return lease.ExpiresAt, nil
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
