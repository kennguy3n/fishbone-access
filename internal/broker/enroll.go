package broker

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
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// ErrEnrollment is the coarse sentinel for any enrollment-token failure
// (unknown, already-consumed, or expired). It is intentionally vague so the
// public enrollment endpoint cannot confirm to an unauthenticated caller which
// case it hit while probing tokens — the same posture as the PAM connect token.
var ErrEnrollment = errors.New("broker: invalid or expired enrollment token")

// ErrValidation marks a bad caller request (missing fields, etc.).
var ErrValidation = errors.New("broker: validation error")

const (
	// defaultEnrollTokenTTL bounds how long a freshly minted enrollment token
	// stays redeemable. Short by design: an enrollment secret should be used
	// within minutes of an operator generating it, not days later.
	defaultEnrollTokenTTL = 15 * time.Minute
	// maxEnrollTokenTTL is the hard server-side ceiling on a token lifetime. A
	// caller-supplied TTL is clamped to this so an operator can never mint a
	// long-lived (effectively non-expiring) enrollment secret that would defeat
	// the one-shot, short-lived posture, regardless of the requested value.
	maxEnrollTokenTTL = 1 * time.Hour
	// enrollTokenBytes is the entropy of an enrollment token before base64url.
	enrollTokenBytes = 32
)

// EnrollmentService mints one-shot enrollment tokens and redeems them into an
// agent identity (a signed client certificate). It mirrors the PAM connect
// token broker: the raw token is shown once and only its hash is stored, and
// redemption atomically flips pending → consumed so a token enrolls at most one
// agent. Every enroll and revoke appends to the workspace audit hash chain in
// the same transaction as the state change.
type EnrollmentService struct {
	db        *gorm.DB
	ca        *AgentCA
	relayAddr string
	tokenTTL  time.Duration
	certTTL   time.Duration
	now       func() time.Time
}

// NewEnrollmentService wires the service. relayAddr is the public address the
// agent should dial (host:port), embedded in the enrollment response. ca must
// be a full signing CA (certificate + key).
func NewEnrollmentService(db *gorm.DB, ca *AgentCA, relayAddr string) *EnrollmentService {
	return &EnrollmentService{
		db:        db,
		ca:        ca,
		relayAddr: relayAddr,
		tokenTTL:  defaultEnrollTokenTTL,
		certTTL:   defaultCertTTL,
		now:       time.Now,
	}
}

// SetClock overrides the time source (tests).
func (s *EnrollmentService) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// SetTokenTTL overrides the enrollment-token lifetime.
func (s *EnrollmentService) SetTokenTTL(d time.Duration) {
	if d > 0 {
		s.tokenTTL = d
	}
}

// MintTokenInput requests a one-shot enrollment token for a named agent.
type MintTokenInput struct {
	WorkspaceID uuid.UUID
	Name        string
	Actor       string
	TTL         time.Duration
}

// MintToken issues an enrollment token and returns the raw secret (shown once).
func (s *EnrollmentService) MintToken(ctx context.Context, in MintTokenInput) (string, *models.AgentEnrollmentToken, error) {
	if in.WorkspaceID == uuid.Nil {
		return "", nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if in.Name == "" {
		return "", nil, fmt.Errorf("%w: name is required", ErrValidation)
	}
	raw, hash, err := newEnrollToken()
	if err != nil {
		return "", nil, err
	}
	ttl := s.tokenTTL
	if in.TTL > 0 {
		ttl = in.TTL
	}
	if ttl > maxEnrollTokenTTL {
		ttl = maxEnrollTokenTTL
	}
	now := s.now()
	row := &models.AgentEnrollmentToken{
		WorkspaceID: in.WorkspaceID,
		TokenHash:   hash,
		Name:        in.Name,
		State:       models.AgentEnrollTokenPending,
		ExpiresAt:   now.Add(ttl),
		CreatedBy:   in.Actor,
	}
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(row).Error; err != nil {
			return fmt.Errorf("broker: mint enrollment token: %w", err)
		}
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: in.WorkspaceID,
			Actor:       in.Actor,
			Action:      AuditActionAgentTokenMint,
			TargetRef:   row.ID.String(),
			Metadata: auditMeta(map[string]any{
				"name":       in.Name,
				"expires_at": row.ExpiresAt.UTC().Format(time.RFC3339),
			}),
		})
	}); err != nil {
		return "", nil, err
	}
	return raw, row, nil
}

// EnrollInput is the agent's redemption request: the raw enrollment token and a
// PEM CSR proving possession of the private key the issued certificate binds.
type EnrollInput struct {
	RawToken     string
	CSRPEM       []byte
	AgentVersion string
	Platform     string
}

// EnrollmentResult is what the agent needs to bring up its tunnel: its signed
// client certificate, the CA to verify the relay, and where to dial.
type EnrollmentResult struct {
	AgentID       uuid.UUID
	ClientCertPEM []byte
	CACertPEM     []byte
	RelayAddr     string
	NotAfter      time.Time
}

// Enroll redeems a token: it validates the token is live, signs a client
// certificate for a freshly allocated agent id, creates the agent row, and
// atomically consumes the token (binding it to the new agent). The whole thing
// is one transaction so a signed-but-unpersisted agent or a consumed-but-
// agentless token can never result. Replay-safe: the pending → consumed update
// is conditional on the token still being pending.
func (s *EnrollmentService) Enroll(ctx context.Context, in EnrollInput) (*EnrollmentResult, error) {
	if in.RawToken == "" || len(in.CSRPEM) == 0 {
		return nil, fmt.Errorf("%w: token and csr are required", ErrValidation)
	}
	if s.ca == nil {
		return nil, errors.New("broker: enrollment requires a signing CA")
	}
	now := s.now()
	hash := hashEnrollToken(in.RawToken)

	var token models.AgentEnrollmentToken
	err := s.db.WithContext(ctx).
		Where("token_hash = ?", hash).
		First(&token).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrEnrollment
		}
		return nil, err
	}
	if token.State != models.AgentEnrollTokenPending || now.After(token.ExpiresAt) {
		return nil, ErrEnrollment
	}

	agentID := uuid.New()
	issued, err := s.ca.SignAgentCertFromCSR(in.CSRPEM, agentID, token.WorkspaceID, s.certTTL)
	if err != nil {
		return nil, fmt.Errorf("broker: %w", err)
	}

	agent := &models.TargetAgent{
		Base:            models.Base{ID: agentID},
		WorkspaceID:     token.WorkspaceID,
		Name:            token.Name,
		CertFingerprint: issued.Fingerprint,
		CertSerial:      issued.Serial,
		CertNotAfter:    issued.NotAfter,
		Status:          models.AgentStatusEnrolled,
		AgentVersion:    in.AgentVersion,
		Platform:        in.Platform,
	}

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Insert the agent first so the token's agent_id foreign key has a row to
		// reference, then consume the token conditional on it still being pending.
		// Concurrency is still safe: two racing redemptions both insert an agent,
		// but only one conditional UPDATE matches (RowsAffected == 1); the loser
		// returns ErrEnrollment, which rolls back the whole transaction — including
		// its just-inserted agent — so a token still enrolls at most one agent.
		if err := tx.Create(agent).Error; err != nil {
			return fmt.Errorf("broker: create agent: %w", err)
		}
		res := tx.Model(&models.AgentEnrollmentToken{}).
			Where("id = ? AND state = ?", token.ID, models.AgentEnrollTokenPending).
			Updates(map[string]any{
				"state":       models.AgentEnrollTokenConsumed,
				"consumed_at": now,
				"agent_id":    agentID,
				"updated_at":  now,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrEnrollment
		}
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: token.WorkspaceID,
			Actor:       "agent:" + agentID.String(),
			Action:      AuditActionAgentEnroll,
			TargetRef:   agentID.String(),
			Metadata: auditMeta(map[string]any{
				"name":     token.Name,
				"platform": in.Platform,
				"version":  in.AgentVersion,
			}),
		})
	}); err != nil {
		return nil, err
	}

	return &EnrollmentResult{
		AgentID:       agentID,
		ClientCertPEM: issued.CertPEM,
		CACertPEM:     s.ca.CertPEM(),
		RelayAddr:     s.relayAddr,
		NotAfter:      issued.NotAfter,
	}, nil
}

// Revoke marks an agent revoked: the relay will refuse its certificate on the
// next connect and refuse to broker new sessions through any tunnel it still
// holds (AuthorizeDial fails closed). Idempotent — revoking an already-revoked
// agent is a no-op success.
func (s *EnrollmentService) Revoke(ctx context.Context, workspaceID, agentID uuid.UUID, actor string) error {
	if workspaceID == uuid.Nil || agentID == uuid.Nil {
		return fmt.Errorf("%w: workspace_id and agent_id are required", ErrValidation)
	}
	now := s.now()
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.TargetAgent{}).
			Where("id = ? AND workspace_id = ? AND status <> ?", agentID, workspaceID, models.AgentStatusRevoked).
			Updates(map[string]any{
				"status":     models.AgentStatusRevoked,
				"revoked_at": now,
				"revoked_by": actor,
				"updated_at": now,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			// Either unknown or already revoked. Distinguish unknown so the API
			// can 404, but treat already-revoked as success (idempotent).
			var count int64
			if err := tx.Model(&models.TargetAgent{}).
				Where("id = ? AND workspace_id = ?", agentID, workspaceID).
				Count(&count).Error; err != nil {
				return err
			}
			if count == 0 {
				return gorm.ErrRecordNotFound
			}
			return nil
		}
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      AuditActionAgentRevoke,
			TargetRef:   agentID.String(),
		})
	})
}

func newEnrollToken() (raw, hash string, err error) {
	buf := make([]byte, enrollTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("broker: generate enrollment token: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	return raw, hashEnrollToken(raw), nil
}

func hashEnrollToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// EnrollHTTPRequest is the public enrollment endpoint's request body: the
// one-shot token and a PEM CSR the agent generated locally, plus inventory.
type EnrollHTTPRequest struct {
	Token        string `json:"token"`
	CSR          string `json:"csr"`
	AgentVersion string `json:"agent_version,omitempty"`
	Platform     string `json:"platform,omitempty"`
}

// EnrollHTTPResponse is the enrollment endpoint's response: the signed client
// certificate (PEM), the CA to verify the relay (PEM), and where to dial. The
// agent's private key never leaves the agent host.
type EnrollHTTPResponse struct {
	AgentID    string    `json:"agent_id"`
	ClientCert string    `json:"client_cert"`
	CACert     string    `json:"ca_cert"`
	RelayAddr  string    `json:"relay_addr"`
	NotAfter   time.Time `json:"not_after"`
}
