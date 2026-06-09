package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// Service owns the workflows table and the draft → simulate → publish
// lifecycle, mirroring lifecycle.PolicyService. Drafts never execute; only a
// published workflow is run by the engine. Every state change appends to the
// per-workspace audit hash chain via lifecycle.AppendAuditTx, so workflow
// events live in the SAME tamper-evident chain as policy/JML events.
type Service struct {
	db   *gorm.DB
	exec *Executor
	now  func() time.Time
}

// NewService wires the workflow service. The executor it builds is used only
// for dry-run simulation (no side-effecting deps), so Simulate is always safe.
func NewService(db *gorm.DB) *Service {
	return &Service{db: db, exec: NewExecutor(db), now: time.Now}
}

// SetClock overrides the time source (tests). It also re-points the executor's
// clock so persisted runs and audit timestamps stay consistent.
func (s *Service) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
		s.exec.SetClock(now)
	}
}

// forUpdate applies a row-level write lock on Postgres so concurrent
// publish/edit operations on the same workflow serialize instead of both
// reading draft state and both transitioning it. It is a no-op on dialects
// without FOR UPDATE (the SQLite test path serializes writers globally).
//
// Lock ordering: every mutating method here takes the row lock BEFORE the
// per-workspace advisory lock (acquired inside AppendAuditTx). This is
// internally consistent, and cannot deadlock against the policy service: the
// two services lock disjoint row sets (workflows vs policies), so no AB/BA
// cycle can form on the shared advisory key.
func forUpdate(tx *gorm.DB) *gorm.DB {
	if tx.Dialector != nil && tx.Name() == "postgres" {
		return tx.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	return tx
}

// CreateInput is the contract for Create.
type CreateInput struct {
	WorkspaceID uuid.UUID
	Name        string
	Definition  json.RawMessage
	Actor       string
}

// Create validates the workflow document and persists a new draft (version 1,
// StateDraft) with its workflow.created audit row in one transaction. The
// document must parse and validate so a malformed workflow can never enter the
// system.
func (s *Service) Create(ctx context.Context, in CreateInput) (*models.Workflow, error) {
	if in.WorkspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if in.Name == "" {
		return nil, fmt.Errorf("%w: workflow name is required", ErrValidation)
	}
	doc, err := ParseDoc(in.Definition)
	if err != nil {
		return nil, err
	}

	now := s.now()
	wf := &models.Workflow{
		WorkspaceID: in.WorkspaceID,
		Name:        in.Name,
		Trigger:     doc.Trigger,
		State:       StateDraft,
		Version:     1,
		Definition:  datatypes.JSON(in.Definition),
	}
	wf.CreatedAt = now
	wf.UpdatedAt = now

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(wf).Error; err != nil {
			return fmt.Errorf("workflow: insert: %w", err)
		}
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: in.WorkspaceID,
			Actor:       in.Actor,
			Action:      "workflow.created",
			TargetRef:   wf.ID.String(),
		})
	})
	if err != nil {
		return nil, err
	}
	return wf, nil
}

// Get loads one workflow scoped to the workspace. A cross-tenant id is
// invisible (returns ErrNotFound).
func (s *Service) Get(ctx context.Context, workspaceID, id uuid.UUID) (*models.Workflow, error) {
	var wf models.Workflow
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, id).
		Take(&wf).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("workflow: load: %w", err)
	}
	return &wf, nil
}

// List returns the workspace's workflows, newest first.
func (s *Service) List(ctx context.Context, workspaceID uuid.UUID) ([]models.Workflow, error) {
	var out []models.Workflow
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("created_at desc").
		Find(&out).Error; err != nil {
		return nil, fmt.Errorf("workflow: list: %w", err)
	}
	return out, nil
}

// UpdateDraft replaces a draft workflow's definition (and optionally its name)
// and clears the cached simulation, which re-locks the publish gate (the draft
// must be re-simulated after any edit). Only drafts are editable; a published
// or archived workflow must be superseded by a new draft.
func (s *Service) UpdateDraft(ctx context.Context, workspaceID, id uuid.UUID, name string, def json.RawMessage, actor string) (*models.Workflow, error) {
	doc, err := ParseDoc(def)
	if err != nil {
		return nil, err
	}
	now := s.now()
	var wf *models.Workflow
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		loaded, err := loadTx(ctx, tx, workspaceID, id)
		if err != nil {
			return err
		}
		if loaded.State != StateDraft {
			return fmt.Errorf("%w: only draft workflows can be edited (state=%s)", ErrNotEditable, loaded.State)
		}
		updates := map[string]any{
			"definition":       datatypes.JSON(def),
			"trigger":          doc.Trigger,
			"draft_simulation": nil, // invalidate stale dry-run → re-locks publish
			"updated_at":       now,
		}
		if name != "" {
			updates["name"] = name
		}
		if err := tx.Model(&models.Workflow{}).
			Where("workspace_id = ? AND id = ?", workspaceID, id).
			Updates(updates).Error; err != nil {
			return fmt.Errorf("workflow: update draft: %w", err)
		}
		loaded.Definition = datatypes.JSON(def)
		loaded.Trigger = doc.Trigger
		loaded.DraftSimulation = nil
		loaded.UpdatedAt = now
		if name != "" {
			loaded.Name = name
		}
		wf = loaded
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      "workflow.draft_updated",
			TargetRef:   id.String(),
		})
	})
	if err != nil {
		return nil, err
	}
	return wf, nil
}

// Simulate runs the workflow's current definition as a dry-run against a sample
// subject WITHOUT any side effects, returning the "what would happen" plan. For
// a draft it caches the result on DraftSimulation, which unlocks the publish
// gate (test-before-publish). It never mutates the data plane and appends no
// execution audit, so it is safe to call on any workflow at any time.
func (s *Service) Simulate(ctx context.Context, workspaceID, id uuid.UUID, subject Subject) (*RunResult, error) {
	wf, err := s.Get(ctx, workspaceID, id)
	if err != nil {
		return nil, err
	}
	doc, err := ParseDoc(wf.Definition)
	if err != nil {
		return nil, err
	}
	result, err := s.exec.Execute(ctx, RunParams{
		WorkspaceID: workspaceID,
		Workflow:    wf,
		Doc:         doc,
		Subject:     subject,
		Mode:        ModeDryRun,
	})
	if err != nil {
		return nil, err
	}

	if wf.State == StateDraft {
		b, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("workflow: marshal simulation: %w", err)
		}
		now := s.now()
		// Cache under the row lock, but only if the definition we simulated is
		// still current: a concurrent UpdateDraft (which clears DraftSimulation
		// on edit) must not be overwritten with a result computed from the now
		// stale definition, which would falsely unlock the publish gate for an
		// edited-but-unsimulated draft.
		//
		// This transaction takes only the row lock (no AppendAuditTx), so it
		// never acquires the advisory lock and cannot form a lock cycle.
		err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			loaded, err := loadTx(ctx, tx, workspaceID, id)
			if err != nil {
				return err
			}
			if loaded.State != StateDraft || !bytes.Equal([]byte(loaded.Definition), []byte(wf.Definition)) {
				return nil // edited or published since we simulated; leave cache as-is
			}
			return tx.Model(&models.Workflow{}).
				Where("workspace_id = ? AND id = ?", workspaceID, id).
				Updates(map[string]any{"draft_simulation": datatypes.JSON(b), "updated_at": now}).Error
		})
		if err != nil {
			return nil, fmt.Errorf("workflow: cache simulation: %w", err)
		}
	}
	return result, nil
}

// Publish flips a draft workflow to published and stamps PublishedAt. It is
// idempotent: publishing an already-published workflow is a no-op that returns
// it unchanged. An archived workflow cannot be published.
//
// Publishing enforces test-before-publish: the draft must have been simulated
// since its last edit (a non-empty DraftSimulation, which UpdateDraft clears on
// every edit), and that cached dry-run must not have reported failures. Both
// checks run against the locked row so a concurrent edit cannot slip an
// unsimulated definition past the gate.
func (s *Service) Publish(ctx context.Context, workspaceID, id uuid.UUID, actor string) (*models.Workflow, error) {
	now := s.now()
	var wf *models.Workflow
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		loaded, err := loadTx(ctx, tx, workspaceID, id)
		if err != nil {
			return err
		}
		switch loaded.State {
		case StatePublished:
			wf = loaded // idempotent: already published
			return nil
		case StateArchived:
			return fmt.Errorf("%w: archived workflow %s", ErrNotPublishable, id)
		}
		if len(loaded.DraftSimulation) == 0 {
			return fmt.Errorf("%w: draft %s", ErrNotSimulated, id)
		}
		var sim RunResult
		if err := json.Unmarshal(loaded.DraftSimulation, &sim); err != nil {
			return fmt.Errorf("workflow: decode cached simulation: %w", err)
		}
		// A simulation that surfaced a failed step must not be publishable.
		// Re-validate the stored definition too, defending against a row written
		// before a validation rule tightened.
		if sim.Status == StatusFailed {
			return fmt.Errorf("%w: workflow %s", ErrSimulationFailed, id)
		}
		// The cached dry-run must have actually exercised the steps. A
		// non-matching sample (StatusSkipped) only confirms the conditions
		// filtered it out and never plans a single step, so it does not satisfy
		// the test-before-publish guardrail — require a matching simulation (a
		// workflow with no conditions matches every subject).
		if !sim.Matched {
			return fmt.Errorf("%w: workflow %s", ErrSimulationNotMatched, id)
		}
		if _, err := ParseDoc(loaded.Definition); err != nil {
			return err
		}
		if err := tx.Model(&models.Workflow{}).
			Where("workspace_id = ? AND id = ?", workspaceID, id).
			Updates(map[string]any{
				"state":        StatePublished,
				"published_at": now,
				"updated_at":   now,
			}).Error; err != nil {
			return fmt.Errorf("workflow: publish: %w", err)
		}
		loaded.State = StatePublished
		loaded.PublishedAt = &now
		loaded.UpdatedAt = now
		wf = loaded
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      "workflow.published",
			TargetRef:   id.String(),
		})
	})
	if err != nil {
		return nil, err
	}
	return wf, nil
}

// Archive deactivates a workflow so the engine stops executing it. It is
// idempotent: archiving an already-archived workflow is a no-op.
func (s *Service) Archive(ctx context.Context, workspaceID, id uuid.UUID, actor string) (*models.Workflow, error) {
	now := s.now()
	var wf *models.Workflow
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		loaded, err := loadTx(ctx, tx, workspaceID, id)
		if err != nil {
			return err
		}
		if loaded.State == StateArchived {
			wf = loaded // idempotent
			return nil
		}
		if err := tx.Model(&models.Workflow{}).
			Where("workspace_id = ? AND id = ?", workspaceID, id).
			Updates(map[string]any{"state": StateArchived, "updated_at": now}).Error; err != nil {
			return fmt.Errorf("workflow: archive: %w", err)
		}
		loaded.State = StateArchived
		loaded.UpdatedAt = now
		wf = loaded
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      "workflow.archived",
			TargetRef:   id.String(),
		})
	})
	if err != nil {
		return nil, err
	}
	return wf, nil
}

// loadTx loads a workflow row FOR UPDATE within the transaction, scoped to the
// workspace. ErrNotFound when the id matches no row in that workspace.
func loadTx(ctx context.Context, tx *gorm.DB, workspaceID, id uuid.UUID) (*models.Workflow, error) {
	var wf models.Workflow
	err := forUpdate(tx).WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, id).
		Take(&wf).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("workflow: load for update: %w", err)
	}
	return &wf, nil
}
