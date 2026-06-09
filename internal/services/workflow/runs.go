package workflow

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// Run executes a PUBLISHED workflow live for the subject, performing real side
// effects via deps, appending per-step audit, and persisting a WorkflowRun for
// the dashboard. It is fail-closed: a draft or archived workflow cannot run
// (ErrNotRunnable), so an unreviewed automation can never effect changes.
//
// This is the single live-execution entrypoint shared by the manual "run now"
// API and the access-workflow-engine's identity-event job, so both paths run
// the exact same validated code.
func (s *Service) Run(ctx context.Context, workspaceID, id uuid.UUID, subject Subject, actor string, deps StepDeps) (*RunResult, error) {
	wf, err := s.Get(ctx, workspaceID, id)
	if err != nil {
		return nil, err
	}
	if wf.State != StatePublished {
		return nil, fmt.Errorf("%w (state=%s)", ErrNotRunnable, wf.State)
	}
	doc, err := ParseDoc(wf.Definition)
	if err != nil {
		return nil, err
	}
	return s.exec.Execute(ctx, RunParams{
		WorkspaceID: workspaceID,
		Workflow:    wf,
		Doc:         doc,
		Subject:     subject,
		Mode:        ModeLive,
		Actor:       actor,
		Deps:        deps,
	})
}

// ListRuns returns the workspace's workflow runs, newest first, capped at
// limit (a sane default is applied when limit <= 0). Backs the JML dashboard's
// "recent runs" view.
func (s *Service) ListRuns(ctx context.Context, workspaceID uuid.UUID, limit int) ([]models.WorkflowRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []models.WorkflowRun
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("started_at desc").
		Limit(limit).
		Find(&out).Error; err != nil {
		return nil, fmt.Errorf("workflow: list runs: %w", err)
	}
	return out, nil
}

// GetRun loads one workflow run scoped to the workspace (per-step audit view).
func (s *Service) GetRun(ctx context.Context, workspaceID, runID uuid.UUID) (*models.WorkflowRun, error) {
	var run models.WorkflowRun
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, runID).
		Take(&run).Error
	if err != nil {
		return nil, ErrNotFound
	}
	return &run, nil
}
