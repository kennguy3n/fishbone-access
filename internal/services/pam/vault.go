package pam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// standaloneAuditor appends one audit event in its own transaction. The Vault
// uses it only for the secret-reveal event, whose state change (a read) has
// nothing to commit alongside the audit row; every state-mutating event
// (target create, secret rotate, connect-token mint, session open) instead uses
// auditTx so the audit row commits atomically with that change. In production
// this is the pgxpool adapter's AuditAppender (database.PgxAuditRepo), wired via
// SetAuditor; when nil the Vault falls back to the GORM lifecycle.AppendAudit
// path used by the SQLite unit tests and degraded boots. Both backends append
// to the SAME per-workspace hash chain through the shared auditchain primitives,
// so the standalone event chains correctly regardless of which one is active.
type standaloneAuditor interface {
	AppendAudit(ctx context.Context, now time.Time, in database.AuditInput) error
}

// ErrTargetNotFound is returned when a target does not exist in the workspace.
// A target in another workspace is indistinguishable from a missing one, so
// this never leaks cross-tenant existence.
var ErrTargetNotFound = errors.New("pam: target not found")

// ErrValidation marks a bad caller input (missing workspace, unknown protocol).
var ErrValidation = errors.New("pam: validation error")

// ErrTargetExists is returned when a target with the same workspace-scoped name
// already exists but describes a *different* upstream (protocol or address), so
// the create cannot be treated as an idempotent retry. Re-registering an
// identical target (same name, protocol and address) is instead a no-op that
// returns the existing row, which keeps target registration safely re-runnable
// for bootstrappers. To change an existing target's credential use RotateSecret.
var ErrTargetExists = errors.New("pam: target name already exists")

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
	db      *gorm.DB
	enc     access.CredentialEncryptor
	stepUp  *StepUpGate
	now     func() time.Time
	auditor standaloneAuditor
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

// SetAuditor routes standalone audit appends through a (typically pgxpool)
// AuditAppender instead of the default GORM path. Production wires the pgx
// adapter here so the audit-log table's standalone writes run on pgx; the
// in-transaction appends (auditTx) stay on GORM because they must commit
// atomically with the GORM state change that produced them — the incremental
// GORM→pgx migration starts with the standalone path. A nil argument is
// ignored, leaving the GORM fallback in place.
func (v *Vault) SetAuditor(a standaloneAuditor) {
	if a != nil {
		v.auditor = a
	}
}

// CreateTarget seals the supplied credential and registers a privileged target,
// idempotently: see CreateOrGetTarget. It discards the created flag for the many
// callers that do not need to distinguish a fresh insert from a reuse.
func (v *Vault) CreateTarget(ctx context.Context, in CreateTargetInput) (*models.PAMTarget, error) {
	row, _, err := v.CreateOrGetTarget(ctx, in)
	return row, err
}

// CreateOrGetTarget seals the supplied credential and persists a new target,
// returning created=true. The row id is generated up front and bound as the
// AES-GCM AAD so the sealed envelope is cryptographically tied to this exact row
// and cannot be copied to another.
//
// Registration is strictly idempotent: a target is identified by its
// workspace-scoped name (the uq_pam_targets_name partial unique index).
// Re-registering an IDENTICAL target — same protocol, address, username,
// require_mfa, lease TTL and config — returns the existing row with
// created=false, so a bootstrapper can safely re-run without erroring or
// duplicating. Re-registering the same name with ANY of those fields different
// is a typed conflict (ErrTargetExists → 409), not a silent mutation: a create
// must never update — and possibly downgrade — an existing privileged target
// (e.g. a plain re-POST that omits require_mfa must not flip its MFA gate off).
// Settings and credential changes go through the explicit update / RotateSecret
// paths instead.
func (v *Vault) CreateOrGetTarget(ctx context.Context, in CreateTargetInput) (*models.PAMTarget, bool, error) {
	if v == nil || v.db == nil {
		return nil, false, fmt.Errorf("pam: Vault not initialised")
	}
	if in.WorkspaceID == uuid.Nil {
		return nil, false, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if strings.TrimSpace(in.Name) == "" {
		return nil, false, fmt.Errorf("%w: target name is required", ErrValidation)
	}
	if !validProtocol(in.Protocol) {
		return nil, false, fmt.Errorf("%w: unknown protocol %q", ErrValidation, in.Protocol)
	}
	name := strings.TrimSpace(in.Name)
	address := strings.TrimSpace(in.Address)
	if address == "" {
		return nil, false, fmt.Errorf("%w: target address is required", ErrValidation)
	}

	switch existing, err := v.FindTargetByName(ctx, in.WorkspaceID, name); {
	case err == nil:
		return v.reuseOrConflict(ctx, existing, in, name, address)
	case !errors.Is(err, ErrTargetNotFound):
		return nil, false, err
	}

	id := uuid.New()
	envelope, keyVersion, err := v.seal(ctx, in.WorkspaceID, id, in.Secret)
	if err != nil {
		return nil, false, err
	}

	row := &models.PAMTarget{
		Base:             models.Base{ID: id},
		WorkspaceID:      in.WorkspaceID,
		Name:             name,
		Protocol:         in.Protocol,
		Address:          address,
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
		// Lost a create race against a concurrent registration for the same name:
		// the unique index fired between our existence check and the insert.
		// Re-resolve and apply the same strict-idempotency decision — return the
		// winning row if it is identical, else surface ErrTargetExists — instead
		// of leaking a raw 500.
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			winner, ferr := v.FindTargetByName(ctx, in.WorkspaceID, name)
			if ferr != nil {
				if errors.Is(ferr, ErrTargetNotFound) {
					return nil, false, fmt.Errorf("%w: %q", ErrTargetExists, name)
				}
				return nil, false, ferr
			}
			return v.reuseOrConflict(ctx, winner, in, name, address)
		}
		return nil, false, err
	}
	return row, true, nil
}

// reuseOrConflict applies the strict-idempotency decision when a create's
// workspace-scoped name already exists. It returns the existing row (200,
// created=false) only when that row is IDENTICAL to the request across every
// non-secret field (protocol, address, username, require_mfa, lease TTL and
// config); any difference is a typed conflict (ErrTargetExists → 409). A create
// deliberately never mutates an existing target — re-pointing it at a new
// upstream or flipping its require_mfa gate must be an explicit update, never an
// implicit side effect of a re-POST (which, for value-typed bools, could not
// tell an omitted require_mfa from an intentional false and would silently
// downgrade the gate). The sealed credential is never compared or touched here.
//
// A pure idempotent reuse is intentionally NOT audited — it is a no-op whose
// state was already recorded at create time, and auditing every bootstrapper
// re-run would flood the chain. A denied conflict, however, IS audited: an
// attempt to re-register a privileged target's name against a different upstream
// or with a changed security setting is a security-relevant rejected event that
// must leave a trail.
func (v *Vault) reuseOrConflict(ctx context.Context, existing *models.PAMTarget, in CreateTargetInput, name, address string) (*models.PAMTarget, bool, error) {
	if existing.Protocol == in.Protocol &&
		existing.Address == address &&
		existing.Username == strings.TrimSpace(in.Username) &&
		existing.RequireMFA == in.RequireMFA &&
		existing.LeaseTTLSeconds == int(in.LeaseTTL.Seconds()) &&
		jsonEqual(existing.Config, in.Config) {
		return existing, false, nil
	}
	// Standalone audit: the registration is rejected, so there is no row to
	// commit alongside (same shape as the secret-reveal event). Record only the
	// non-secret field names that differ — never values or secret material — and
	// fail closed if the chain append fails, so a denial is never silently
	// unrecorded.
	if err := v.audit(ctx, in.WorkspaceID, in.Actor, "pam.target.register_denied", existing.ID.String(), map[string]any{
		"name":           name,
		"reason":         "name already registered with different settings",
		"changed_fields": conflictFields(existing, in, address),
	}); err != nil {
		return nil, false, err
	}
	return nil, false, fmt.Errorf("%w: %q", ErrTargetExists, name)
}

// conflictFields lists the non-secret field names whose requested value differs
// from the stored target, so a register_denied audit records WHAT was being
// changed without leaking any values (e.g. config payloads or addresses).
func conflictFields(existing *models.PAMTarget, in CreateTargetInput, address string) []string {
	var f []string
	if existing.Protocol != in.Protocol {
		f = append(f, "protocol")
	}
	if existing.Address != address {
		f = append(f, "address")
	}
	if existing.Username != strings.TrimSpace(in.Username) {
		f = append(f, "username")
	}
	if existing.RequireMFA != in.RequireMFA {
		f = append(f, "require_mfa")
	}
	if existing.LeaseTTLSeconds != int(in.LeaseTTL.Seconds()) {
		f = append(f, "lease_ttl_seconds")
	}
	if !jsonEqual(existing.Config, in.Config) {
		f = append(f, "config")
	}
	return f
}

// jsonEqual compares two JSON columns treating nil and empty as equal so an
// omitted config never looks like a change against a stored empty one. When both
// are non-empty it first tries a byte compare, then falls back to a semantic
// compare so equivalent JSON with different key ordering or whitespace doesn't
// read as a spurious conflict on a faithful re-register.
func jsonEqual(a, b datatypes.JSON) bool {
	switch {
	case len(a) == 0 && len(b) == 0:
		return true
	case len(a) == 0 || len(b) == 0:
		return false
	case bytes.Equal(a, b):
		return true
	}
	var ax, bx any
	if json.Unmarshal(a, &ax) != nil || json.Unmarshal(b, &bx) != nil {
		return false
	}
	return reflect.DeepEqual(ax, bx)
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

// FindTargetByName loads a target by its workspace-scoped name, returning
// ErrTargetNotFound when none exists. Unlike scanning ListTargets — whose
// result set is capped — this is an exact, indexed lookup, so a caller that
// must decide "reuse or create" (e.g. the idempotent scenario seeder) stays
// correct no matter how many targets the workspace already holds. When more
// than one target shares the name, the newest is returned, matching the
// newest-first ordering ListTargets exposes.
func (v *Vault) FindTargetByName(ctx context.Context, workspaceID uuid.UUID, name string) (*models.PAMTarget, error) {
	if workspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("%w: target name is required", ErrValidation)
	}
	var row models.PAMTarget
	err := v.db.WithContext(ctx).
		Where("workspace_id = ? AND name = ?", workspaceID, name).
		Order("created_at DESC").
		Take(&row).Error
	switch {
	case err == nil:
		return &row, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, ErrTargetNotFound
	default:
		return nil, fmt.Errorf("pam: find target by name: %w", err)
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
		Select("id", "workspace_id", "name", "protocol", "address", "username", "config", "require_mfa", "lease_ttl_seconds", "secret_rotated_at", "created_at", "updated_at").
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
// transaction. Use it for standalone events whose state change has already
// committed on its own — today that is only the secret-reveal event (a read,
// with no row to commit alongside). Events that mutate state (target create,
// secret rotate, connect-token mint, session open) use auditTx so the audit row
// commits atomically with that change. This standalone path is the one routed
// through the pgx auditor when SetAuditor has wired one.
func (v *Vault) audit(ctx context.Context, workspaceID uuid.UUID, actor, action, targetRef string, meta map[string]any) error {
	md, err := marshalMeta(meta)
	if err != nil {
		return err
	}
	if v.auditor != nil {
		return v.auditor.AppendAudit(ctx, v.now(), database.AuditInput{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      action,
			TargetRef:   targetRef,
			Metadata:    md,
		})
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
