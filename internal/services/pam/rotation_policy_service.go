package pam

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// RotationPolicyService is the CRUD + read API behind the rotation handlers. It
// owns policy validation (which protocols can be rotated, interval floors), the
// derived next_rotation_at schedule, and reading rotation history / dynamic
// credential status for the console.
type RotationPolicyService struct {
	db       *gorm.DB
	vault    *Vault
	registry *ExecutorRegistry
	now      func() time.Time
}

// NewRotationPolicyService wires the service. registry defaults to the real
// executor set when nil so protocol-support validation matches production.
func NewRotationPolicyService(db *gorm.DB, vault *Vault, registry *ExecutorRegistry) *RotationPolicyService {
	if registry == nil {
		registry = NewExecutorRegistry(10 * time.Second)
	}
	return &RotationPolicyService{db: db, vault: vault, registry: registry, now: time.Now}
}

// SetClock overrides the time source (tests).
func (s *RotationPolicyService) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// PolicyInput is the desired rotation configuration for a target.
type PolicyInput struct {
	Mode              string `json:"mode"`
	IntervalSeconds   int64  `json:"interval_seconds"`
	RotateOnCheckin   bool   `json:"rotate_on_checkin"`
	DynamicEnabled    bool   `json:"dynamic_enabled"`
	DynamicTTLSeconds int64  `json:"dynamic_ttl_seconds"`
	Enabled           bool   `json:"enabled"`
}

// GetPolicy returns the target's policy, or nil when none is configured.
func (s *RotationPolicyService) GetPolicy(ctx context.Context, workspaceID, targetID uuid.UUID) (*models.RotationPolicy, error) {
	var p models.RotationPolicy
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND target_id = ?", workspaceID, targetID).
		Take(&p).Error
	switch {
	case err == nil:
		return &p, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, nil
	default:
		return nil, fmt.Errorf("pam: get rotation policy: %w", err)
	}
}

// ListPolicies returns every policy in the workspace, newest first.
func (s *RotationPolicyService) ListPolicies(ctx context.Context, workspaceID uuid.UUID) ([]models.RotationPolicy, error) {
	var out []models.RotationPolicy
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("updated_at DESC").
		Find(&out).Error; err != nil {
		return nil, fmt.Errorf("pam: list rotation policies: %w", err)
	}
	return out, nil
}

// UpsertPolicy validates and stores the target's rotation policy, computing the
// next interval-rotation instant. It is idempotent: re-applying the same input
// updates the single live policy row for the target.
func (s *RotationPolicyService) UpsertPolicy(ctx context.Context, workspaceID, targetID uuid.UUID, in PolicyInput, actor string) (*models.RotationPolicy, error) {
	target, err := s.vault.GetTarget(ctx, workspaceID, targetID)
	if err != nil {
		return nil, err
	}
	if err := s.validate(target, in); err != nil {
		return nil, err
	}

	now := s.now().UTC()
	existing, err := s.GetPolicy(ctx, workspaceID, targetID)
	if err != nil {
		return nil, err
	}

	policy := &models.RotationPolicy{
		WorkspaceID:       workspaceID,
		TargetID:          targetID,
		Mode:              in.Mode,
		IntervalSeconds:   in.IntervalSeconds,
		RotateOnCheckin:   in.RotateOnCheckin,
		DynamicEnabled:    in.DynamicEnabled,
		DynamicTTLSeconds: in.DynamicTTLSeconds,
		Enabled:           in.Enabled,
	}
	if existing != nil {
		policy.Base = existing.Base
		policy.LastRotationAt = existing.LastRotationAt
		policy.LastStatus = existing.LastStatus
		policy.LastError = existing.LastError
	}
	// (Re)compute the next-due instant. Base it off the last rotation when known
	// so re-saving a policy does not reset an in-flight schedule; otherwise
	// schedule the first rotation one interval from now.
	if policy.IntervalRotationActive() {
		base := now
		if policy.LastRotationAt != nil && policy.LastRotationAt.After(base.Add(-policy.Interval())) {
			base = *policy.LastRotationAt
		}
		policy.NextRotationAt = policy.ComputeNextRotation(base)
	} else {
		policy.NextRotationAt = nil
	}

	if existing == nil {
		if err := s.db.WithContext(ctx).Create(policy).Error; err != nil {
			return nil, fmt.Errorf("pam: create rotation policy: %w", err)
		}
	} else {
		policy.ID = existing.ID
		if err := s.db.WithContext(ctx).Save(policy).Error; err != nil {
			return nil, fmt.Errorf("pam: update rotation policy: %w", err)
		}
	}

	if aerr := s.vault.audit(ctx, workspaceID, actor, "pam.rotation_policy.updated", targetID.String(), map[string]any{
		"mode":              policy.Mode,
		"interval_seconds":  policy.IntervalSeconds,
		"rotate_on_checkin": policy.RotateOnCheckin,
		"dynamic_enabled":   policy.DynamicEnabled,
		"enabled":           policy.Enabled,
	}); aerr != nil {
		return nil, fmt.Errorf("pam: audit rotation policy update: %w", aerr)
	}
	return policy, nil
}

// DeletePolicy soft-deletes the target's policy (disabling all automatic
// rotation for the target). It is a no-op when no policy exists.
func (s *RotationPolicyService) DeletePolicy(ctx context.Context, workspaceID, targetID uuid.UUID, actor string) error {
	existing, err := s.GetPolicy(ctx, workspaceID, targetID)
	if err != nil {
		return err
	}
	if existing == nil {
		return nil
	}
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, existing.ID).
		Delete(&models.RotationPolicy{}).Error; err != nil {
		return fmt.Errorf("pam: delete rotation policy: %w", err)
	}
	if aerr := s.vault.audit(ctx, workspaceID, actor, "pam.rotation_policy.deleted", targetID.String(), nil); aerr != nil {
		return fmt.Errorf("pam: audit rotation policy delete: %w", aerr)
	}
	return nil
}

// ListEvents returns the most recent rotation events for a target, newest first.
func (s *RotationPolicyService) ListEvents(ctx context.Context, workspaceID, targetID uuid.UUID, limit int) ([]models.RotationEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []models.RotationEvent
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND target_id = ?", workspaceID, targetID).
		Order("created_at DESC").
		Limit(limit).
		Find(&out).Error; err != nil {
		return nil, fmt.Errorf("pam: list rotation events: %w", err)
	}
	return out, nil
}

// ListActiveDynamicCredentials returns the live ephemeral credentials for a
// target (password omitted — it is never stored).
func (s *RotationPolicyService) ListActiveDynamicCredentials(ctx context.Context, workspaceID, targetID uuid.UUID) ([]models.DynamicCredential, error) {
	var out []models.DynamicCredential
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND target_id = ? AND state = ?",
			workspaceID, targetID, models.DynamicCredentialStateActive).
		Order("created_at DESC").
		Find(&out).Error; err != nil {
		return nil, fmt.Errorf("pam: list dynamic credentials: %w", err)
	}
	return out, nil
}

// RotatableProtocol reports whether interval/checkin rotation is available for a
// protocol (an executor is registered).
func (s *RotationPolicyService) RotatableProtocol(protocol string) bool {
	return s.registry.Supports(protocol)
}

// validate enforces the policy invariants and protocol support.
func (s *RotationPolicyService) validate(target *models.PAMTarget, in PolicyInput) error {
	switch in.Mode {
	case models.RotationModeDisabled, models.RotationModeInterval:
	default:
		return fmt.Errorf("%w: unknown rotation mode %q", ErrValidation, in.Mode)
	}
	if in.Mode == models.RotationModeInterval {
		if !s.registry.Supports(target.Protocol) {
			return fmt.Errorf("%w: interval rotation is not supported for protocol %q", ErrValidation, target.Protocol)
		}
		if time.Duration(in.IntervalSeconds)*time.Second < models.MinRotationInterval {
			return fmt.Errorf("%w: interval must be at least %s", ErrValidation, models.MinRotationInterval)
		}
	}
	if in.RotateOnCheckin && !s.registry.Supports(target.Protocol) {
		return fmt.Errorf("%w: rotate-on-checkin is not supported for protocol %q", ErrValidation, target.Protocol)
	}
	if in.DynamicEnabled {
		if target.Protocol != models.PAMProtocolPostgres && target.Protocol != models.PAMProtocolMySQL {
			return fmt.Errorf("%w: dynamic credentials are only supported for postgres and mysql", ErrValidation)
		}
		if in.DynamicTTLSeconds < 0 {
			return fmt.Errorf("%w: dynamic ttl must not be negative", ErrValidation)
		}
	}
	return nil
}
