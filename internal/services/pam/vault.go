package pam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// ErrTargetNotFound is returned when a target does not exist in the workspace.
// A target in another workspace is indistinguishable from a missing one, so
// this never leaks cross-tenant existence.
var ErrTargetNotFound = errors.New("pam: target not found")

// ErrValidation marks a bad caller input (missing workspace, unknown protocol).
var ErrValidation = errors.New("pam: validation error")

// Secret is the upstream credential sealed per target. Exactly which fields are
// populated depends on the protocol: SSH uses PrivateKey (preferred) or
// Password; Postgres/MySQL use Password; k8s-exec uses Token. It is delivered
// to the proxy in-memory at connect time and never written to disk in
// plaintext.
type Secret struct {
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Token      string `json:"token,omitempty"`
}

// CreateTargetInput describes a new privileged target plus its upstream
// credential. Secret is sealed before it touches the database.
type CreateTargetInput struct {
	WorkspaceID uuid.UUID
	Name        string
	Protocol    string
	Address     string
	Username    string
	RequireMFA  bool
	LeaseTTL    time.Duration
	Config      datatypes.JSON
	Secret      Secret
	Actor       string
}

// Vault is the per-target credential store. It seals each target's upstream
// credential with the per-workspace EnvelopeEncryptor (AES-256-GCM, the
// target's own id bound as AAD), gates secret reveal behind step-up MFA, and
// supports in-place rotation. All reads and writes are workspace-scoped.
type Vault struct {
	db     *gorm.DB
	enc    access.CredentialEncryptor
	stepUp *StepUpGate
	now    func() time.Time
}

// NewVault wires a vault. enc MUST be a real encryptor (the fail-closed
// DisabledEncryptor is acceptable — it refuses to seal rather than writing
// plaintext). stepUp may be nil, in which case MFA-gated targets cannot be
// revealed (fail-closed).
func NewVault(db *gorm.DB, enc access.CredentialEncryptor, stepUp *StepUpGate) *Vault {
	return &Vault{db: db, enc: enc, stepUp: stepUp, now: time.Now}
}

// SetClock overrides the time source (tests).
func (v *Vault) SetClock(now func() time.Time) {
	if now != nil {
		v.now = now
	}
}

// CreateTarget seals the supplied credential and persists a new target. The row
// id is generated up front and bound as the AES-GCM AAD so the sealed envelope
// is cryptographically tied to this exact row and cannot be copied to another.
func (v *Vault) CreateTarget(ctx context.Context, in CreateTargetInput) (*models.PAMTarget, error) {
	if v == nil || v.db == nil {
		return nil, fmt.Errorf("pam: Vault not initialised")
	}
	if in.WorkspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if strings.TrimSpace(in.Name) == "" {
		return nil, fmt.Errorf("%w: target name is required", ErrValidation)
	}
	if !validProtocol(in.Protocol) {
		return nil, fmt.Errorf("%w: unknown protocol %q", ErrValidation, in.Protocol)
	}
	if strings.TrimSpace(in.Address) == "" {
		return nil, fmt.Errorf("%w: target address is required", ErrValidation)
	}

	id := uuid.New()
	envelope, keyVersion, err := v.seal(ctx, in.WorkspaceID, id, in.Secret)
	if err != nil {
		return nil, err
	}

	row := &models.PAMTarget{
		Base:             models.Base{ID: id},
		WorkspaceID:      in.WorkspaceID,
		Name:             strings.TrimSpace(in.Name),
		Protocol:         in.Protocol,
		Address:          strings.TrimSpace(in.Address),
		Username:         strings.TrimSpace(in.Username),
		Config:           in.Config,
		SecretEnvelope:   envelope,
		SecretKeyVersion: keyVersion,
		RequireMFA:       in.RequireMFA,
		LeaseTTLSeconds:  int(in.LeaseTTL.Seconds()),
	}
	// Create the target row and its audit record in one transaction so a sealed
	// target can never exist without its tamper-evident chain entry (a failed
	// audit append rolls the target back). Matches MintConnectToken.
	if err := v.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(row).Error; err != nil {
			return fmt.Errorf("pam: create target: %w", err)
		}
		return v.auditTx(ctx, tx, in.WorkspaceID, in.Actor, "pam.target.created", row.ID.String(), map[string]any{
			"protocol": row.Protocol,
			"address":  row.Address,
		})
	}); err != nil {
		return nil, err
	}
	return row, nil
}

// GetTarget loads a target scoped to its workspace.
func (v *Vault) GetTarget(ctx context.Context, workspaceID, targetID uuid.UUID) (*models.PAMTarget, error) {
	if workspaceID == uuid.Nil || targetID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id and target_id are required", ErrValidation)
	}
	var row models.PAMTarget
	err := v.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, targetID).
		Take(&row).Error
	switch {
	case err == nil:
		return &row, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, ErrTargetNotFound
	default:
		return nil, fmt.Errorf("pam: load target: %w", err)
	}
}

// ListTargets returns a workspace's privileged targets newest-first. The
// sealed credential envelope and key version are never returned to a list
// caller (only the broker's OpenSecret path decrypts), so the catalog the
// console renders carries connection metadata but no secret material. limit is
// clamped to a sane page size.
func (v *Vault) ListTargets(ctx context.Context, workspaceID uuid.UUID, limit int) ([]models.PAMTarget, error) {
	if workspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var rows []models.PAMTarget
	if err := v.db.WithContext(ctx).
		Select("id", "workspace_id", "name", "protocol", "address", "username", "config", "require_mfa", "lease_ttl_seconds", "secret_key_version", "created_at", "updated_at").
		Where("workspace_id = ?", workspaceID).
		Order("created_at DESC").
		Limit(limit).
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("pam: list targets: %w", err)
	}
	return rows, nil
}

// OpenSecret decrypts a target's credential for in-memory injection by the
// proxy. It performs NO MFA gate — callers that reveal a secret to a human
// (RevealSecret) or honour RequireMFA at connect time enforce step-up; this is
// the low-level open used once a connect token has already authorized the
// session. The returned Secret must never be persisted to disk.
func (v *Vault) OpenSecret(ctx context.Context, target *models.PAMTarget) (Secret, error) {
	if target == nil {
		return Secret{}, fmt.Errorf("%w: target is required", ErrValidation)
	}
	return v.open(ctx, target)
}

// RevealSecret returns a target's credential to a human operator. When the
// target is MFA-gated it requires a valid step-up assertion (stepUpToken)
// bound to subject and the workspace's iam-core tenant. Every reveal — gated or
// not — is recorded in the workspace audit hash chain.
func (v *Vault) RevealSecret(ctx context.Context, workspaceID, targetID uuid.UUID, subject, stepUpToken string) (Secret, error) {
	target, err := v.GetTarget(ctx, workspaceID, targetID)
	if err != nil {
		return Secret{}, err
	}
	if target.RequireMFA {
		if err := v.enforceStepUp(ctx, workspaceID, subject, stepUpToken); err != nil {
			return Secret{}, err
		}
	}
	sec, err := v.open(ctx, target)
	if err != nil {
		return Secret{}, err
	}
	if err := v.audit(ctx, workspaceID, subject, "pam.secret.revealed", target.ID.String(), map[string]any{
		"require_mfa": target.RequireMFA,
	}); err != nil {
		return Secret{}, err
	}
	return sec, nil
}

// RotateSecret re-seals a target with a new credential under the latest DEK and
// stamps SecretRotatedAt. The old ciphertext is overwritten in place.
func (v *Vault) RotateSecret(ctx context.Context, workspaceID, targetID uuid.UUID, newSecret Secret, actor string) error {
	target, err := v.GetTarget(ctx, workspaceID, targetID)
	if err != nil {
		return err
	}
	envelope, keyVersion, err := v.seal(ctx, workspaceID, target.ID, newSecret)
	if err != nil {
		return err
	}
	now := v.now()
	// Re-seal and audit atomically so a rotated credential is never committed
	// without its audit record (and vice versa). Matches MintConnectToken.
	return v.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.
			Model(&models.PAMTarget{}).
			Where("workspace_id = ? AND id = ?", workspaceID, targetID).
			Updates(map[string]any{
				"secret_envelope":    envelope,
				"secret_key_version": keyVersion,
				"secret_rotated_at":  now,
				"updated_at":         now,
			}).Error; err != nil {
			return fmt.Errorf("pam: rotate secret: %w", err)
		}
		return v.auditTx(ctx, tx, workspaceID, actor, "pam.secret.rotated", target.ID.String(), map[string]any{
			"key_version": keyVersion,
		})
	})
}

// enforceStepUp resolves the workspace's iam-core tenant and runs the step-up
// gate. A workspace with no resolvable tenant, or a gate that is not
// configured, fails closed.
func (v *Vault) enforceStepUp(ctx context.Context, workspaceID uuid.UUID, subject, stepUpToken string) error {
	if !v.stepUp.Enabled() {
		return fmt.Errorf("%w: target requires MFA but step-up gate is not configured", ErrStepUpInvalid)
	}
	var ws models.Workspace
	if err := v.db.WithContext(ctx).
		Where("id = ?", workspaceID).
		Take(&ws).Error; err != nil {
		return fmt.Errorf("pam: resolve workspace tenant for step-up: %w", err)
	}
	return v.stepUp.Require(subject, ws.IAMCoreTenantID, stepUpToken)
}

// seal marshals and encrypts a Secret, returning the envelope string and key
// version to persist. An all-empty secret is rejected: a target with no
// credential cannot authenticate to its upstream and almost certainly signals a
// caller bug.
func (v *Vault) seal(ctx context.Context, workspaceID, targetID uuid.UUID, sec Secret) (string, int, error) {
	if v.enc == nil {
		return "", 0, fmt.Errorf("pam: credential encryptor is required")
	}
	if sec == (Secret{}) {
		return "", 0, fmt.Errorf("%w: target secret is empty", ErrValidation)
	}
	plaintext, err := json.Marshal(sec)
	if err != nil {
		return "", 0, fmt.Errorf("pam: marshal secret: %w", err)
	}
	ciphertext, keyVersion, err := v.enc.Encrypt(ctx, workspaceID.String(), plaintext, targetID[:])
	if err != nil {
		return "", 0, fmt.Errorf("pam: seal secret: %w", err)
	}
	return string(ciphertext), keyVersion, nil
}

// open decrypts a target's sealed credential.
func (v *Vault) open(ctx context.Context, target *models.PAMTarget) (Secret, error) {
	if v.enc == nil {
		return Secret{}, fmt.Errorf("pam: credential encryptor is required")
	}
	plaintext, err := v.enc.Decrypt(ctx, target.WorkspaceID.String(), []byte(target.SecretEnvelope), target.ID[:], target.SecretKeyVersion)
	if err != nil {
		return Secret{}, fmt.Errorf("pam: open secret: %w", err)
	}
	var sec Secret
	if err := json.Unmarshal(plaintext, &sec); err != nil {
		return Secret{}, fmt.Errorf("pam: unmarshal secret: %w", err)
	}
	return sec, nil
}

// audit appends one PAM event to the workspace's 1C audit hash chain in its own
// transaction. Use it for standalone events (target create, token mint) whose
// state change has already been committed.
func (v *Vault) audit(ctx context.Context, workspaceID uuid.UUID, actor, action, targetRef string, meta map[string]any) error {
	md, err := marshalMeta(meta)
	if err != nil {
		return err
	}
	return lifecycle.AppendAudit(ctx, v.db, v.now(), lifecycle.AuditInput{
		WorkspaceID: workspaceID,
		Actor:       actor,
		Action:      action,
		TargetRef:   targetRef,
		Metadata:    md,
	})
}

// auditTx appends one PAM event within an existing transaction so the audit
// record is atomic with the state change that produced it. Use it when the
// event and its state change must commit together (e.g. opening a session as a
// connect token is consumed) — never leaving a privileged action without its
// chained audit row.
func (v *Vault) auditTx(ctx context.Context, tx *gorm.DB, workspaceID uuid.UUID, actor, action, targetRef string, meta map[string]any) error {
	md, err := marshalMeta(meta)
	if err != nil {
		return err
	}
	return lifecycle.AppendAuditTx(ctx, tx, v.now(), lifecycle.AuditInput{
		WorkspaceID: workspaceID,
		Actor:       actor,
		Action:      action,
		TargetRef:   targetRef,
		Metadata:    md,
	})
}

// validProtocol reports whether p is a supported PAM wire protocol. It defers
// to models.IsValidPAMProtocol so the CRUD gate, the DB CHECK constraint, and
// the bound gateway listeners all share one source of truth for the protocol
// set (see internal/models/pam.go).
func validProtocol(p string) bool {
	return models.IsValidPAMProtocol(p)
}

// marshalMeta encodes audit metadata, tolerating a nil map (→ "{}").
func marshalMeta(meta map[string]any) (datatypes.JSON, error) {
	if meta == nil {
		return datatypes.JSON([]byte("{}")), nil
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("pam: marshal audit metadata: %w", err)
	}
	return datatypes.JSON(b), nil
}
