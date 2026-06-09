package workflow_engine

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/aiclient"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
	"github.com/kennguy3n/fishbone-access/internal/services/workflow"
	"github.com/kennguy3n/fishbone-access/internal/workers"
)

// jmlRunner is the slice of the JML service the processor drives.
type jmlRunner interface {
	HandleEvent(ctx context.Context, workspaceID uuid.UUID, e lifecycle.SCIMEvent) (string, *lifecycle.LeaverResult, error)
}

// provisionRunner is the slice of the provisioning service the processor drives.
type provisionRunner interface {
	Provision(ctx context.Context, workspaceID, requestID uuid.UUID, actor string) (*models.AccessGrant, error)
}

// reviewRunner is the slice of the review service the processor drives.
type reviewRunner interface {
	StartCampaign(ctx context.Context, workspaceID uuid.UUID, name, actor string) (*models.AccessReview, int, error)
	ListItems(ctx context.Context, workspaceID, reviewID uuid.UUID) ([]models.AccessReviewItem, error)
	SubmitDecision(ctx context.Context, workspaceID, reviewID, itemID uuid.UUID, decision, decidedBy, reason string) error
	CompleteCampaign(ctx context.Context, workspaceID, reviewID uuid.UUID, actor string) (lifecycle.ReviewReport, error)
}

// grantLookup loads a grant for the AI review-automation input.
type grantLookup interface {
	GetGrant(ctx context.Context, workspaceID, grantID uuid.UUID) (*models.AccessGrant, error)
}

// workflowExecutor runs a published JML workflow live for a single subject.
// *workflow.Service satisfies it. The processor drives it for the asynchronous
// JobTypeWorkflowRun path; the manual "run now" API calls the same method
// synchronously.
type workflowExecutor interface {
	Run(ctx context.Context, workspaceID, id uuid.UUID, subject workflow.Subject, actor string, deps workflow.StepDeps) (*workflow.RunResult, error)
}

// stepDepsFactory builds the executor's step dependencies for one run, bound to
// the run's workspace + actor. Injected so the processor needs no direct
// knowledge of the concrete lifecycle services or the DB pool.
type stepDepsFactory func(workspaceID uuid.UUID, actor string) workflow.StepDeps

// ProcessorDeps wires the job processor to the lifecycle services, the grant
// lookup, and the AI client. JML, Provisioner, and Reviews are required to
// process their respective job types; Grants and AI back the review sweep (AI
// may be nil/unconfigured → the deterministic fallback defers each item to a
// human).
type ProcessorDeps struct {
	JML         jmlRunner
	Provisioner provisionRunner
	Reviews     reviewRunner
	Grants      grantLookup
	AI          *aiclient.AIClient
	// Workflows + WorkflowDeps back JobTypeWorkflowRun (the no-code JML builder's
	// asynchronous execution path). Both are required together.
	Workflows    workflowExecutor
	WorkflowDeps stepDepsFactory
}

// JobProcessor implements workers.Processor for the workflow job types. It is
// the resumable execution path: each handler is idempotent so a job redelivered
// after a worker restart (or a retry after a transient failure) is safe to run
// again.
type JobProcessor struct {
	jml          jmlRunner
	provisioner  provisionRunner
	reviews      reviewRunner
	grants       grantLookup
	ai           *aiclient.AIClient
	workflows    workflowExecutor
	workflowDeps stepDepsFactory
}

// NewJobProcessor validates its dependencies and returns the processor.
func NewJobProcessor(d ProcessorDeps) (*JobProcessor, error) {
	if d.JML == nil {
		return nil, fmt.Errorf("workflow_engine: JML service is required")
	}
	if d.Provisioner == nil {
		return nil, fmt.Errorf("workflow_engine: Provisioner service is required")
	}
	if d.Reviews == nil {
		return nil, fmt.Errorf("workflow_engine: Reviews service is required")
	}
	if d.Grants == nil {
		return nil, fmt.Errorf("workflow_engine: Grants lookup is required")
	}
	if d.Workflows == nil {
		return nil, fmt.Errorf("workflow_engine: Workflows executor is required")
	}
	if d.WorkflowDeps == nil {
		return nil, fmt.Errorf("workflow_engine: WorkflowDeps factory is required")
	}
	return &JobProcessor{
		jml:          d.JML,
		provisioner:  d.Provisioner,
		reviews:      d.Reviews,
		grants:       d.Grants,
		ai:           d.AI,
		workflows:    d.Workflows,
		workflowDeps: d.WorkflowDeps,
	}, nil
}

// Process implements workers.Processor, dispatching by job type. An unknown type
// returns an error so a misrouted job (a connector job that slipped past the
// queue's type filter) is surfaced rather than silently dropped.
func (p *JobProcessor) Process(ctx context.Context, job workers.Job) error {
	switch job.Type {
	case JobTypeJMLEvent:
		return p.handleJMLEvent(ctx, job)
	case JobTypeProvisionRequest:
		return p.handleProvision(ctx, job)
	case JobTypeReviewSweep:
		return p.handleReviewSweep(ctx, job)
	case JobTypeWorkflowRun:
		return p.handleWorkflowRun(ctx, job)
	default:
		return fmt.Errorf("workflow_engine: job %s: unknown job type %q", job.ID, job.Type)
	}
}

func (p *JobProcessor) handleJMLEvent(ctx context.Context, job workers.Job) error {
	var payload jmlEventPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return fmt.Errorf("workflow_engine: job %s: decode jml payload: %w", job.ID, err)
	}
	workspaceID, err := uuid.Parse(payload.WorkspaceID)
	if err != nil {
		return fmt.Errorf("workflow_engine: job %s: invalid workspace_id: %w", job.ID, err)
	}
	class, leaver, err := p.jml.HandleEvent(ctx, workspaceID, payload.Event)
	if err != nil {
		return fmt.Errorf("workflow_engine: job %s: jml %s: %w", job.ID, class, err)
	}
	if leaver != nil && leaver.Errored {
		// The kill switch ran but at least one layer failed. Return an error so
		// the job retries the leaver cascade (each layer is idempotent), rather
		// than marking it done with a half-disabled user.
		return fmt.Errorf("workflow_engine: job %s: leaver kill switch had layer failures for %s", job.ID, leaver.UserExternalID)
	}
	return nil
}

func (p *JobProcessor) handleProvision(ctx context.Context, job workers.Job) error {
	var payload provisionRequestPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return fmt.Errorf("workflow_engine: job %s: decode provision payload: %w", job.ID, err)
	}
	workspaceID, err := uuid.Parse(payload.WorkspaceID)
	if err != nil {
		return fmt.Errorf("workflow_engine: job %s: invalid workspace_id: %w", job.ID, err)
	}
	requestID, err := uuid.Parse(payload.RequestID)
	if err != nil {
		return fmt.Errorf("workflow_engine: job %s: invalid request_id: %w", job.ID, err)
	}
	if _, err := p.provisioner.Provision(ctx, workspaceID, requestID, payload.Actor); err != nil {
		return fmt.Errorf("workflow_engine: job %s: provision request %s: %w", job.ID, requestID, err)
	}
	return nil
}

// handleReviewSweep runs one certification campaign end to end: it snapshots the
// workspace's live grants, asks the AI review-automation skill to recommend a
// disposition per grant, and applies a CONSERVATIVE mapping — only a confident
// "certify" is auto-applied; revoke / escalate / manual_review / any degraded
// (fallback) recommendation is ESCALATED to a human. The sweep never
// auto-revokes standing access from an AI suggestion. Per-item failures are
// logged and leave the item pending (i.e. surfaced to humans); the job only
// fails (and retries) if the campaign cannot be started or completed.
func (p *JobProcessor) handleReviewSweep(ctx context.Context, job workers.Job) error {
	var payload reviewSweepPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return fmt.Errorf("workflow_engine: job %s: decode review payload: %w", job.ID, err)
	}
	workspaceID, err := uuid.Parse(payload.WorkspaceID)
	if err != nil {
		return fmt.Errorf("workflow_engine: job %s: invalid workspace_id: %w", job.ID, err)
	}

	review, count, err := p.reviews.StartCampaign(ctx, workspaceID, payload.CampaignName, payload.Actor)
	if err != nil {
		return fmt.Errorf("workflow_engine: job %s: start review campaign: %w", job.ID, err)
	}
	logger.Infof(ctx, "workflow_engine: review sweep %s started campaign %s with %d items", job.ID, review.ID, count)

	items, err := p.reviews.ListItems(ctx, workspaceID, review.ID)
	if err != nil {
		return fmt.Errorf("workflow_engine: job %s: list review items: %w", job.ID, err)
	}
	for i := range items {
		p.decideReviewItem(ctx, workspaceID, review.ID, items[i], payload.Actor, payload.WorkspaceAITier)
	}

	if _, err := p.reviews.CompleteCampaign(ctx, workspaceID, review.ID, payload.Actor); err != nil {
		return fmt.Errorf("workflow_engine: job %s: complete review campaign: %w", job.ID, err)
	}
	return nil
}

// decideReviewItem asks the AI to recommend a disposition for one grant and
// applies the conservative mapping. Errors are logged and leave the item pending
// rather than failing the whole sweep.
func (p *JobProcessor) decideReviewItem(ctx context.Context, workspaceID, reviewID uuid.UUID, item models.AccessReviewItem, actor, tier string) {
	grant, err := p.grants.GetGrant(ctx, workspaceID, item.GrantID)
	if err != nil {
		logger.Warnf(ctx, "workflow_engine: review item %s: load grant %s failed, leaving pending: %v", item.ID, item.GrantID, err)
		return
	}

	rec := aiclient.AutomateReviewWithFallback(ctx, p.ai, tier, aiclient.ReviewAutomationInput{
		Role:        grant.Role,
		ResourceRef: grant.ResourceRef,
	})

	decision := lifecycle.ReviewDecisionEscalate
	reason := rec.Reason
	if rec.Decision == aiclient.ReviewDecisionCertify && !rec.Degraded {
		decision = lifecycle.ReviewDecisionCertify
	} else if reason == "" {
		reason = "escalated for human review"
	}

	if err := p.reviews.SubmitDecision(ctx, workspaceID, reviewID, item.ID, decision, actor, reason); err != nil {
		logger.Warnf(ctx, "workflow_engine: review item %s: submit %q failed, leaving pending: %v", item.ID, decision, err)
	}
}

// handleWorkflowRun executes a published JML workflow live for the payload's
// subject. It builds the step dependencies bound to the run's workspace + actor
// and drives the same Service.Run the manual API uses. A run that completes but
// has step failures returns an error so the job retries (every step is
// idempotent); Service.Run also persists a workflow_runs row for the dashboard.
func (p *JobProcessor) handleWorkflowRun(ctx context.Context, job workers.Job) error {
	var payload workflowRunPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return fmt.Errorf("workflow_engine: job %s: decode workflow-run payload: %w", job.ID, err)
	}
	workspaceID, err := uuid.Parse(payload.WorkspaceID)
	if err != nil {
		return fmt.Errorf("workflow_engine: job %s: invalid workspace_id: %w", job.ID, err)
	}
	workflowID, err := uuid.Parse(payload.WorkflowID)
	if err != nil {
		return fmt.Errorf("workflow_engine: job %s: invalid workflow_id: %w", job.ID, err)
	}
	deps := p.workflowDeps(workspaceID, payload.Actor)
	result, err := p.workflows.Run(ctx, workspaceID, workflowID, payload.Subject, payload.Actor, deps)
	if err != nil {
		return fmt.Errorf("workflow_engine: job %s: run workflow %s: %w", job.ID, workflowID, err)
	}
	if result != nil && result.Status == workflow.StatusFailed {
		return fmt.Errorf("workflow_engine: job %s: workflow %s run %s had step failures", job.ID, workflowID, result.RunID)
	}
	return nil
}

// Ensure JobProcessor satisfies the worker contract at compile time.
var _ workers.Processor = (*JobProcessor)(nil)
