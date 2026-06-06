package workflow_engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/aiclient"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// Enqueuer is the subset of the worker queue the engine needs to schedule
// resumable work. *workers.PostgresQueue satisfies it. Defined here so the
// engine package does not depend on a concrete queue and can be unit-tested with
// an in-memory fake.
type Enqueuer interface {
	Enqueue(ctx context.Context, workspaceID, connectorID uuid.UUID, jobType string, payload []byte) (string, error)
}

// requestCreator / requestApprover / requestDenier / requestGetter are the
// slices of the lifecycle request service the engine drives. Splitting them out
// keeps the dependency explicit and the engine testable without the full
// service.
type requestService interface {
	CreateRequest(ctx context.Context, in lifecycle.CreateAccessRequestInput) (*models.AccessRequest, error)
	GetRequest(ctx context.Context, workspaceID, requestID uuid.UUID) (*models.AccessRequest, error)
	ApproveRequest(ctx context.Context, workspaceID, requestID uuid.UUID, actor, reason string) error
	DenyRequest(ctx context.Context, workspaceID, requestID uuid.UUID, actor, reason string) error
}

// workflowRouter routes a created request to a lane (and auto-approves the
// low-risk lane). *lifecycle.WorkflowService satisfies it.
type workflowRouter interface {
	ExecuteWorkflow(ctx context.Context, workspaceID uuid.UUID, req *models.AccessRequest, actor string) (lifecycle.WorkflowDecision, error)
}

// Deps wires the engine to the lifecycle services, the AI client, the approval
// store, and the queue. requests, workflow, and queue are required; ai may be
// nil/unconfigured (the engine then always uses the deterministic fallback
// risk score); approvals is required to gate human-approval lanes.
type Deps struct {
	Requests  requestService
	Workflow  workflowRouter
	AI        *aiclient.AIClient
	Approvals *ApprovalStore
	Queue     Enqueuer
}

// Engine is the workflow orchestrator. It is safe for concurrent use: it holds
// no mutable state, delegating persistence to the lifecycle services and the
// queue.
type Engine struct {
	requests  requestService
	workflow  workflowRouter
	ai        *aiclient.AIClient
	approvals *ApprovalStore
	queue     Enqueuer
}

// NewEngine validates its dependencies and returns the engine.
func NewEngine(d Deps) (*Engine, error) {
	if d.Requests == nil {
		return nil, fmt.Errorf("workflow_engine: Requests service is required")
	}
	if d.Workflow == nil {
		return nil, fmt.Errorf("workflow_engine: Workflow service is required")
	}
	if d.Approvals == nil {
		return nil, fmt.Errorf("workflow_engine: Approvals store is required")
	}
	if d.Queue == nil {
		return nil, fmt.Errorf("workflow_engine: Queue is required")
	}
	return &Engine{
		requests:  d.Requests,
		workflow:  d.Workflow,
		ai:        d.AI,
		approvals: d.Approvals,
		queue:     d.Queue,
	}, nil
}

// SubmitInput describes a new access request to route through the engine.
type SubmitInput struct {
	WorkspaceID   uuid.UUID
	RequesterID   string
	TargetUserID  string
	ConnectorID   *uuid.UUID
	ResourceRef   string
	Role          string
	Justification string
	// ResourceTags feed the AI risk model; a "sensitive" tag also forces the
	// security-review lane independent of the numeric score.
	ResourceTags []string
	// DurationHours is the requested access window (0 = indefinite); longer
	// windows raise risk.
	DurationHours int
	// WorkspaceAITier selects the per-workspace LLM tier ("" → default,
	// "deterministic" → skip the LLM entirely).
	WorkspaceAITier string
	// FailClosed makes an unreachable AI agent yield the HIGH fail-closed score
	// (→ security_review) instead of the medium fail-safe default. Use it for
	// privileged resources whose policy says "block when we cannot assess".
	FailClosed bool
	ExpiresAt  *time.Time
}

// SubmitResult reports the outcome of routing a submitted request.
type SubmitResult struct {
	Request *models.AccessRequest
	// Decision is the workflow lane chosen from the (AI) risk assessment.
	Decision lifecycle.WorkflowDecision
	// Risk is the assessment used to route the request.
	Risk aiclient.RiskAssessment
	// Provisioning is true when the request auto-approved and a provisioning job
	// was enqueued. False means it is parked awaiting the approval chain.
	Provisioning bool
	// ProvisionJobID is the enqueued provisioning job id (empty unless
	// Provisioning).
	ProvisionJobID string
}

// SubmitRequest assesses risk via the AI agent (deterministic fallback when
// unavailable), creates the access request with the resulting risk level +
// factors, and routes it through the workflow service. A low-risk request
// auto-approves and the engine enqueues a provisioning job; a medium/high or
// sensitive request is parked in StateRequested for its approval chain.
func (e *Engine) SubmitRequest(ctx context.Context, in SubmitInput) (*SubmitResult, error) {
	if in.WorkspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", lifecycle.ErrValidation)
	}

	risk := aiclient.AssessRiskWithFallback(ctx, e.ai, in.WorkspaceAITier, aiclient.RiskAssessmentInput{
		Role:               in.Role,
		ResourceExternalID: in.ResourceRef,
		ResourceTags:       in.ResourceTags,
		DurationHours:      in.DurationHours,
		Justification:      in.Justification,
	}, in.FailClosed)

	factors := ensureSensitiveFactor(risk.Factors, in.ResourceTags)

	req, err := e.requests.CreateRequest(ctx, lifecycle.CreateAccessRequestInput{
		WorkspaceID:   in.WorkspaceID,
		RequesterID:   in.RequesterID,
		TargetUserID:  in.TargetUserID,
		ConnectorID:   in.ConnectorID,
		ResourceRef:   in.ResourceRef,
		Role:          in.Role,
		Justification: in.Justification,
		RiskLevel:     risk.Score,
		RiskFactors:   factors,
		ExpiresAt:     in.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}

	decision, err := e.workflow.ExecuteWorkflow(ctx, in.WorkspaceID, req, in.RequesterID)
	if err != nil {
		return nil, err
	}

	res := &SubmitResult{Request: req, Decision: decision, Risk: risk}
	if !decision.Approved {
		// Parked for human approval; the approval chain (Approve/Deny) drives it
		// forward. Nothing to provision yet.
		return res, nil
	}

	jobID, err := e.enqueueProvision(ctx, in.WorkspaceID, req, in.RequesterID)
	if err != nil {
		// The request is approved in the FSM; surface the enqueue failure so the
		// caller can retry. Re-running SubmitRequest is not idempotent, but a
		// caller can enqueue provisioning directly via EnqueueProvision once the
		// queue recovers — the approved request is durable.
		return res, fmt.Errorf("workflow_engine: enqueue provisioning for approved request %s: %w", req.ID, err)
	}
	res.Provisioning = true
	res.ProvisionJobID = jobID
	return res, nil
}

// ApproveInput records one approver's approval of a parked request.
type ApproveInput struct {
	WorkspaceID  uuid.UUID
	RequestID    uuid.UUID
	Approver     string
	ApproverRole string
	Reason       string
}

// ApproveResult reports the chain state after recording an approval and whether
// the approval completed the chain (flipping the request to approved + enqueuing
// provisioning).
type ApproveResult struct {
	Chain          ChainState
	Approved       bool
	ProvisionJobID string
}

// Approve records an approver's decision and, once the request's approval chain
// is satisfied, transitions it requested → approved and enqueues provisioning.
// It is idempotent: re-approving by the same approver does not double-count, and
// calling Approve again after the chain is already satisfied will not re-enqueue
// provisioning for an already-approved request (the FSM rejects the second
// requested → approved transition, which the engine treats as a no-op).
func (e *Engine) Approve(ctx context.Context, in ApproveInput) (*ApproveResult, error) {
	req, err := e.requests.GetRequest(ctx, in.WorkspaceID, in.RequestID)
	if err != nil {
		return nil, err
	}
	decision, err := lifecycle.ResolveDecision(req)
	if err != nil {
		return nil, err
	}
	required := RequiredApprovals(decision.StepType)

	if err := e.approvals.Record(ctx, in.WorkspaceID, in.RequestID, in.Approver, in.ApproverRole, ApprovalDecisionApprove, in.Reason); err != nil {
		return nil, err
	}
	chain, err := e.approvals.State(ctx, in.WorkspaceID, in.RequestID, required)
	if err != nil {
		return nil, err
	}

	res := &ApproveResult{Chain: chain}
	if !chain.Satisfied() {
		return res, nil
	}

	// Chain satisfied: approve the request through the FSM. Only act when the
	// request is still in StateRequested so a redelivered/duplicate approval
	// does not try to re-approve (and re-provision) an already-moving request.
	if req.State != lifecycle.StateRequested {
		res.Approved = true
		return res, nil
	}
	if err := e.requests.ApproveRequest(ctx, in.WorkspaceID, in.RequestID, in.Approver, "approval chain satisfied: "+in.Reason); err != nil {
		return nil, err
	}
	res.Approved = true

	// Reload so the provisioning enqueue carries the post-approval state.
	approved, err := e.requests.GetRequest(ctx, in.WorkspaceID, in.RequestID)
	if err != nil {
		return res, err
	}
	jobID, err := e.enqueueProvision(ctx, in.WorkspaceID, approved, in.Approver)
	if err != nil {
		return res, fmt.Errorf("workflow_engine: enqueue provisioning for approved request %s: %w", in.RequestID, err)
	}
	res.ProvisionJobID = jobID
	return res, nil
}

// Deny records an approver's denial and rejects the request (requested →
// denied). A single denial is terminal regardless of prior approvals.
func (e *Engine) Deny(ctx context.Context, in ApproveInput) error {
	if _, err := e.requests.GetRequest(ctx, in.WorkspaceID, in.RequestID); err != nil {
		return err
	}
	if err := e.approvals.Record(ctx, in.WorkspaceID, in.RequestID, in.Approver, in.ApproverRole, ApprovalDecisionDeny, in.Reason); err != nil {
		return err
	}
	if err := e.requests.DenyRequest(ctx, in.WorkspaceID, in.RequestID, in.Approver, defaultReason(in.Reason, "denied by approver")); err != nil {
		// A deny on a request that already left StateRequested is a no-op, not an
		// error: the decision is recorded for audit and the request is terminal.
		if errors.Is(err, lifecycle.ErrInvalidStateTransition) {
			logger.Warnf(ctx, "workflow_engine: deny on non-pending request %s ignored: %v", in.RequestID, err)
			return nil
		}
		return err
	}
	return nil
}

// IngestSCIMEvent enqueues a normalized SCIM event for asynchronous JML
// processing. Routing it through the queue (rather than calling the JML service
// inline) makes lifecycle automation resumable: the event survives a worker
// restart and is retried with back-off until it succeeds or dead-letters.
func (e *Engine) IngestSCIMEvent(ctx context.Context, workspaceID uuid.UUID, event lifecycle.SCIMEvent) (string, error) {
	if workspaceID == uuid.Nil {
		return "", fmt.Errorf("%w: workspace_id is required", lifecycle.ErrValidation)
	}
	payload, err := mustMarshal(jmlEventPayload{WorkspaceID: workspaceID.String(), Event: event})
	if err != nil {
		return "", err
	}
	connectorID := uuid.Nil
	if event.ConnectorID != nil {
		connectorID = *event.ConnectorID
	}
	return e.queue.Enqueue(ctx, workspaceID, connectorID, JobTypeJMLEvent, payload)
}

// ScheduleReviewSweep enqueues a scheduled access-certification sweep for a
// workspace. The sweep job (handled by JobProcessor) starts a campaign,
// auto-decides each item via the AI review-automation skill, and completes the
// campaign — falling back to manual review when the agent is unavailable.
func (e *Engine) ScheduleReviewSweep(ctx context.Context, workspaceID uuid.UUID, campaignName, actor, workspaceAITier string) (string, error) {
	if workspaceID == uuid.Nil {
		return "", fmt.Errorf("%w: workspace_id is required", lifecycle.ErrValidation)
	}
	if campaignName == "" {
		campaignName = fmt.Sprintf("scheduled-review-%s", time.Now().UTC().Format("2006-01-02"))
	}
	payload, err := mustMarshal(reviewSweepPayload{
		WorkspaceID:     workspaceID.String(),
		CampaignName:    campaignName,
		Actor:           defaultReason(actor, "workflow-engine"),
		WorkspaceAITier: workspaceAITier,
	})
	if err != nil {
		return "", err
	}
	return e.queue.Enqueue(ctx, workspaceID, uuid.Nil, JobTypeReviewSweep, payload)
}

// EnqueueProvision enqueues a provisioning job for an already-approved request.
// Exposed so a caller can drive provisioning after recovering from a transient
// enqueue failure in SubmitRequest/Approve.
func (e *Engine) EnqueueProvision(ctx context.Context, workspaceID uuid.UUID, requestID uuid.UUID, actor string) (string, error) {
	req, err := e.requests.GetRequest(ctx, workspaceID, requestID)
	if err != nil {
		return "", err
	}
	return e.enqueueProvision(ctx, workspaceID, req, actor)
}

func (e *Engine) enqueueProvision(ctx context.Context, workspaceID uuid.UUID, req *models.AccessRequest, actor string) (string, error) {
	payload, err := mustMarshal(provisionRequestPayload{
		WorkspaceID: workspaceID.String(),
		RequestID:   req.ID.String(),
		Actor:       defaultReason(actor, "workflow-engine"),
	})
	if err != nil {
		return "", err
	}
	connectorID := uuid.Nil
	if req.ConnectorID != nil {
		connectorID = *req.ConnectorID
	}
	return e.queue.Enqueue(ctx, workspaceID, connectorID, JobTypeProvisionRequest, payload)
}

// ensureSensitiveFactor appends the sensitive_resource risk factor (which forces
// the security-review lane) when the caller tagged the resource sensitive but
// the AI did not already flag it, de-duplicating so the factor appears once.
func ensureSensitiveFactor(factors []string, tags []string) []string {
	sensitive := false
	for _, t := range tags {
		if equalFoldTrim(t, "sensitive") || equalFoldTrim(t, lifecycle.SensitiveResourceRiskFactor) {
			sensitive = true
			break
		}
	}
	if !sensitive {
		return factors
	}
	for _, f := range factors {
		if equalFoldTrim(f, lifecycle.SensitiveResourceRiskFactor) {
			return factors
		}
	}
	return append(factors, lifecycle.SensitiveResourceRiskFactor)
}

func defaultReason(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func equalFoldTrim(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
