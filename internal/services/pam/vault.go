package pam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
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
// Registration is idempotent and converging: a target is identified by its
// workspace-scoped name (the uq_pam_targets_name partial unique index).
// Re-registering the SAME upstream (same protocol + address) returns the
// existing row with created=false, reconciling any drift in the mutable,
// non-secret attributes (username, require_mfa, lease TTL, config) to the
// requested desired state and auditing the change — so a bootstrapper can
// re-run, even with an adjusted spec, without erroring, duplicating, or
// silently keeping stale settings. A name already taken by a DIFFERENT upstream
// is a real conflict (ErrTargetExists). Changing an existing target's credential
// is RotateSecret's job, not this path's.
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
		return v.reuseOrReconcile(ctx, existing, in, name, address)
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
		// Lost a create race against a concurrent identical registration: the
		// unique index fired between our existence check and the insert. Re-resolve
		// so the winning row is returned (idempotent, reconciling any drift) — or a
		// genuine upstream conflict surfaces as ErrTargetExists — instead of a 500.
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			winner, ferr := v.FindTargetByName(ctx, in.WorkspaceID, name)
			if ferr != nil {
				if errors.Is(ferr, ErrTargetNotFound) {
					return nil, false, fmt.Errorf("%w: %q", ErrTargetExists, name)
				}
				return nil, false, ferr
			}
			return v.reuseOrReconcile(ctx, winner, in, name, address)
		}
		return nil, false, err
	}
	return row, true, nil
}

// reuseOrReconcile handles a create whose workspace-scoped name already exists.
// When the existing row describes the SAME upstream (protocol + address) the
// registration is idempotent: any drift in the mutable, non-secret attributes
// (username, require_mfa, lease TTL, config) is reconciled to the requested
// desired state and the change is audited, then the row is returned with
// created=false — so a bootstrapper that re-runs with an adjusted spec converges
// instead of either erroring or silently keeping stale settings. A name already
// bound to a DIFFERENT upstream is a real conflict (ErrTargetExists);
// re-pointing a target at a new host/protocol is deliberately not an implicit
// side effect of create. The sealed credential is never touched here — rotating
// it is RotateSecret's job.
func (v *Vault) reuseOrReconcile(ctx context.Context, existing *models.PAMTarget, in CreateTargetInput, name, address string) (*models.PAMTarget, bool, error) {
	if existing.Protocol != in.Protocol || existing.Address != address {
		return nil, false, fmt.Errorf("%w: %q", ErrTargetExists, name)
	}

	desiredUser := strings.TrimSpace(in.Username)
	desiredTTL := int(in.LeaseTTL.Seconds())
	changes := map[string]any{}
	if existing.Username != desiredUser {
		changes["username"] = desiredUser
	}
	if existing.RequireMFA != in.RequireMFA {
		changes["require_mfa"] = in.RequireMFA
	}
	if existing.LeaseTTLSeconds != desiredTTL {
		changes["lease_ttl_seconds"] = desiredTTL
	}
	if !jsonEqual(existing.Config, in.Config) {
		changes["config"] = in.Config
	}
	if len(changes) == 0 {
		return existing, false, nil // already in the desired state — pure reuse
	}

	// Apply the reconcile and its audit entry in one transaction so the
	// tamper-evident chain never diverges from the row. The credential envelope
	// and key version are intentionally untouched.
	if err := v.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.PAMTarget{}).
			Where("workspace_id = ? AND id = ?", existing.WorkspaceID, existing.ID).
			Updates(changes).Error; err != nil {
			return fmt.Errorf("pam: reconcile target: %w", err)
		}
		return v.auditTx(ctx, tx, existing.WorkspaceID, in.Actor, "pam.target.updated", existing.ID.String(), map[string]any{
			"fields": changedColumns(changes),
		})
	}); err != nil {
		return nil, false, err
	}

	updated, err := v.GetTarget(ctx, existing.WorkspaceID, existing.ID)
	if err != nil {
		return nil, false, err
	}
	return updated, false, nil
}

// changedColumns returns the sorted column names touched by a reconcile so the
// audit metadata records WHICH fields converged without leaking config payloads.
func changedColumns(changes map[string]any) []string {
	cols := make([]string, 0, len(changes))
	for c := range changes {
		cols = append(cols, c)
	}
	sort.Strings(cols)
	return cols
}

// jsonEqual compares two JSON columns treating nil and empty as equal so an
// omitted config never looks like a change against a stored empty one.
func jsonEqual(a, b datatypes.JSON) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return bytes.Equal(a, b)
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
