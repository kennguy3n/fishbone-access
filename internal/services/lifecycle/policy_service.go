package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// SimulationResult is the combined output of a policy simulation: the impact
// report plus any conflicts with live policies. It is returned by Simulate and
// (the impact half) cached on the draft.
type SimulationResult struct {
	Impact    ImpactReport     `json:"impact"`
	Conflicts []PolicyConflict `json:"conflicts"`
}

// PolicyService owns the policies table and the draft → simulate → promote
// lifecycle. Drafts never touch the data plane: only Promote flips a policy to
// PolicyStateActive, and only active policies are read by impact/conflict scans
// and (in 1B/1E) by the enforcement path.
type PolicyService struct {
	db       *gorm.DB
	impact   *ImpactResolver
	conflict *ConflictDetector
	now      func() time.Time
}

// NewPolicyService wires the policy service to its resolvers.
func NewPolicyService(db *gorm.DB) *PolicyService {
	return &PolicyService{
		db:       db,
		impact:   NewImpactResolver(db),
		conflict: NewConflictDetector(db),
		now:      time.Now,
	}
}

// SetClock overrides the time source (tests).
func (s *PolicyService) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// CreatePolicyInput is the contract for CreatePolicy.
type CreatePolicyInput struct {
	WorkspaceID uuid.UUID
	Name        string
	Definition  json.RawMessage
	Actor       string
}

// CreatePolicy validates the definition and persists a new draft policy
// (version 1, StateDraft). The definition must parse so a malformed policy can
// never enter the system.
func (s *PolicyService) CreatePolicy(ctx context.Context, in CreatePolicyInput) (*models.Policy, error) {
	if in.WorkspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if in.Name == "" {
		return nil, fmt.Errorf("%w: policy name is required", ErrValidation)
	}
	if _, err := ParsePolicyDefinition(in.Definition); err != nil {
		return nil, err
	}

	now := s.now()
	pol := &models.Policy{
		WorkspaceID: in.WorkspaceID,
		Name:        in.Name,
		State:       PolicyStateDraft,
		Version:     1,
		Definition:  datatypes.JSON(in.Definition),
	}
	pol.CreatedAt = now
	pol.UpdatedAt = now

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(pol).Error; err != nil {
			return fmt.Errorf("lifecycle: insert policy: %w", err)
		}
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: in.WorkspaceID,
			Actor:       in.Actor,
			Action:      "policy.created",
			TargetRef:   pol.ID.String(),
		})
	})
	if err != nil {
		return nil, err
	}
	return pol, nil
}

// GetPolicy loads one policy scoped to the workspace.
func (s *PolicyService) GetPolicy(ctx context.Context, workspaceID, policyID uuid.UUID) (*models.Policy, error) {
	var pol models.Policy
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, policyID).
		Take(&pol).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrPolicyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lifecycle: load policy: %w", err)
	}
	return &pol, nil
}

// ListPolicies returns the workspace's policies, newest first.
func (s *PolicyService) ListPolicies(ctx context.Context, workspaceID uuid.UUID) ([]models.Policy, error) {
	var out []models.Policy
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("created_at desc").
		Find(&out).Error; err != nil {
		return nil, fmt.Errorf("lifecycle: list policies: %w", err)
	}
	return out, nil
}

// UpdateDraft replaces a draft policy's definition (and optionally its name).
// Only drafts are editable; an active or archived policy must be superseded by
// a new draft, so editing one returns ErrPolicyNotPromotable.
func (s *PolicyService) UpdateDraft(ctx context.Context, workspaceID, policyID uuid.UUID, name string, def json.RawMessage, actor string) (*models.Policy, error) {
	if _, err := ParsePolicyDefinition(def); err != nil {
		return nil, err
	}
	now := s.now()
	var pol *models.Policy
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		loaded, err := loadPolicyTx(ctx, tx, workspaceID, policyID)
		if err != nil {
			return err
		}
		if loaded.State != PolicyStateDraft {
			return fmt.Errorf("%w: only draft policies can be edited (state=%s)", ErrPolicyNotPromotable, loaded.State)
		}
		updates := map[string]any{
			"definition":   datatypes.JSON(def),
			"draft_impact": nil, // invalidate stale simulation
			"updated_at":   now,
		}
		if name != "" {
			updates["name"] = name
		}
		if err := tx.Model(&models.Policy{}).
			Where("workspace_id = ? AND id = ?", workspaceID, policyID).
			Updates(updates).Error; err != nil {
			return fmt.Errorf("lifecycle: update draft policy: %w", err)
		}
		loaded.Definition = datatypes.JSON(def)
		loaded.DraftImpact = nil
		loaded.UpdatedAt = now
		if name != "" {
			loaded.Name = name
		}
		pol = loaded
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      "policy.draft_updated",
			TargetRef:   policyID.String(),
		})
	})
	if err != nil {
		return nil, err
	}
	return pol, nil
}

// Simulate runs the ImpactResolver + ConflictDetector against the policy's
// current definition WITHOUT changing live authorization. For a draft it caches
// the impact report on DraftImpact. It never mutates the data plane, so it is
// safe to call on any policy at any time.
func (s *PolicyService) Simulate(ctx context.Context, workspaceID, policyID uuid.UUID) (SimulationResult, error) {
	pol, err := s.GetPolicy(ctx, workspaceID, policyID)
	if err != nil {
		return SimulationResult{}, err
	}
	def, err := ParsePolicyDefinition(pol.Definition)
	if err != nil {
		return SimulationResult{}, err
	}
	impact, err := s.impact.ResolveImpact(ctx, workspaceID, def)
	if err != nil {
		return SimulationResult{}, err
	}
	conflicts, err := s.conflict.DetectConflicts(ctx, workspaceID, policyID, def)
	if err != nil {
		return SimulationResult{}, err
	}
	result := SimulationResult{Impact: impact, Conflicts: conflicts}

	if pol.State == PolicyStateDraft {
		if b, err := json.Marshal(impact); err == nil {
			now := s.now()
			if err := s.db.WithContext(ctx).
				Model(&models.Policy{}).
				Where("workspace_id = ? AND id = ?", workspaceID, policyID).
				Updates(map[string]any{"draft_impact": datatypes.JSON(b), "updated_at": now}).Error; err != nil {
				return SimulationResult{}, fmt.Errorf("lifecycle: cache draft impact: %w", err)
			}
		}
	}
	return result, nil
}

// Promote flips a draft policy to active and stamps PromotedAt. It is
// idempotent: promoting an already-active policy is a no-op that returns the
// policy unchanged (so a retried promotion does not bump the version or restamp
// the timestamp). An archived policy cannot be promoted.
func (s *PolicyService) Promote(ctx context.Context, workspaceID, policyID uuid.UUID, actor string) (*models.Policy, error) {
	now := s.now()
	var pol *models.Policy
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		loaded, err := loadPolicyTx(ctx, tx, workspaceID, policyID)
		if err != nil {
			return err
		}
		switch loaded.State {
		case PolicyStateActive:
			pol = loaded // idempotent: already promoted
			return nil
		case PolicyStateArchived:
			return fmt.Errorf("%w: archived policy %s", ErrPolicyNotPromotable, policyID)
		}
		if err := tx.Model(&models.Policy{}).
			Where("workspace_id = ? AND id = ?", workspaceID, policyID).
			Updates(map[string]any{
				"state":       PolicyStateActive,
				"promoted_at": now,
				"updated_at":  now,
			}).Error; err != nil {
			return fmt.Errorf("lifecycle: promote policy: %w", err)
		}
		loaded.State = PolicyStateActive
		loaded.PromotedAt = &now
		loaded.UpdatedAt = now
		pol = loaded
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      "policy.promoted",
			TargetRef:   policyID.String(),
		})
	})
	if err != nil {
		return nil, err
	}
	return pol, nil
}

// Archive flips an active or draft policy to archived (removing it from the
// live authorization set). Idempotent on an already-archived policy.
func (s *PolicyService) Archive(ctx context.Context, workspaceID, policyID uuid.UUID, actor string) (*models.Policy, error) {
	now := s.now()
	var pol *models.Policy
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		loaded, err := loadPolicyTx(ctx, tx, workspaceID, policyID)
		if err != nil {
			return err
		}
		if loaded.State == PolicyStateArchived {
			pol = loaded
			return nil
		}
		if err := tx.Model(&models.Policy{}).
			Where("workspace_id = ? AND id = ?", workspaceID, policyID).
			Updates(map[string]any{"state": PolicyStateArchived, "updated_at": now}).Error; err != nil {
			return fmt.Errorf("lifecycle: archive policy: %w", err)
		}
		loaded.State = PolicyStateArchived
		loaded.UpdatedAt = now
		pol = loaded
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      "policy.archived",
			TargetRef:   policyID.String(),
		})
	})
	if err != nil {
		return nil, err
	}
	return pol, nil
}

// loadPolicyTx loads a policy for update inside a transaction, workspace-scoped.
func loadPolicyTx(ctx context.Context, tx *gorm.DB, workspaceID, policyID uuid.UUID) (*models.Policy, error) {
	var pol models.Policy
	err := tx.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, policyID).
		Take(&pol).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrPolicyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lifecycle: load policy for update: %w", err)
	}
	return &pol, nil
}
