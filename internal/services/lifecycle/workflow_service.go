package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// Workflow step types — the lanes a freshly-created request can be routed into.
const (
	// WorkflowStepAutoApprove self-services low-risk requests: the workflow
	// approves them immediately with no human in the loop.
	WorkflowStepAutoApprove = "auto_approve"
	// WorkflowStepManagerApproval parks the request in StateRequested awaiting
	// a manager decision (the fail-safe default for medium / unknown risk).
	WorkflowStepManagerApproval = "manager_approval"
	// WorkflowStepSecurityReview parks the request awaiting a security-team
	// decision (high risk, or any request that touches a sensitive resource).
	WorkflowStepSecurityReview = "security_review"
)

// Risk-score buckets understood by the router. They match the values written
// to models.AccessRequest.RiskLevel.
const (
	RiskLow    = "low"
	RiskMedium = "medium"
	RiskHigh   = "high"
)

// SensitiveResourceRiskFactor is the RiskFactors entry that forces escalation
// to security_review regardless of the numeric risk score.
const SensitiveResourceRiskFactor = "sensitive_resource"

// RequestApprover is the subset of AccessRequestService that WorkflowService
// needs. Defining it here keeps the dependency loose and lets tests stub the
// approver without the full request service.
type RequestApprover interface {
	ApproveRequest(ctx context.Context, workspaceID, requestID uuid.UUID, actor, reason string) error
}

// WorkflowService is the built-in, risk-based routing layer (simple mode). It
// decides what happens to a request after it enters StateRequested: low-risk
// requests are auto-approved through the RequestApprover; medium / high / and
// sensitive-resource requests are parked for human approval.
type WorkflowService struct {
	requestSvc RequestApprover
}

// NewWorkflowService returns a service that drives approvals through approver
// (typically an *AccessRequestService).
func NewWorkflowService(approver RequestApprover) *WorkflowService {
	return &WorkflowService{requestSvc: approver}
}

// WorkflowDecision is the outcome of routing a request: the chosen lane plus a
// human-readable reason. Approved reports whether ExecuteWorkflow actually
// approved the request (true only for the auto_approve lane).
type WorkflowDecision struct {
	StepType string `json:"step_type"`
	Reason   string `json:"reason"`
	Approved bool   `json:"approved"`
}

// Route maps (riskLevel, riskFactors) to a workflow lane. It is pure: no DB, no
// side effects, fully unit-testable.
//
//	factors contains "sensitive_resource" → security_review (forced)
//	risk = "high"                         → security_review
//	risk = "low"                          → auto_approve
//	risk = "medium" / unknown / empty     → manager_approval (fail-safe)
func Route(riskLevel string, riskFactors []string) WorkflowDecision {
	for _, f := range riskFactors {
		if strings.EqualFold(strings.TrimSpace(f), SensitiveResourceRiskFactor) {
			return WorkflowDecision{StepType: WorkflowStepSecurityReview, Reason: "risk_factor=sensitive_resource → security_review"}
		}
	}
	switch strings.TrimSpace(strings.ToLower(riskLevel)) {
	case RiskLow:
		return WorkflowDecision{StepType: WorkflowStepAutoApprove, Reason: "risk=low → auto_approve"}
	case RiskHigh:
		return WorkflowDecision{StepType: WorkflowStepSecurityReview, Reason: "risk=high → security_review"}
	case RiskMedium:
		return WorkflowDecision{StepType: WorkflowStepManagerApproval, Reason: "risk=medium → manager_approval"}
	default:
		return WorkflowDecision{StepType: WorkflowStepManagerApproval, Reason: "risk=unknown → manager_approval (fail-safe)"}
	}
}

// ResolveDecision routes the request without taking any action. It decodes the
// request's persisted RiskLevel + RiskFactors and returns the lane.
func ResolveDecision(req *models.AccessRequest) (WorkflowDecision, error) {
	if req == nil {
		return WorkflowDecision{}, fmt.Errorf("%w: request is required", ErrValidation)
	}
	return Route(req.RiskLevel, decodeRiskFactors(req.RiskFactors)), nil
}

// ExecuteWorkflow routes the request and, for the auto_approve lane, approves it
// through the RequestApprover (which performs the requested → approved FSM
// transition + history + audit). For the manager_approval and security_review
// lanes the request is left in StateRequested for a human to act on; the
// returned decision tells the caller which queue to surface it in.
func (s *WorkflowService) ExecuteWorkflow(ctx context.Context, workspaceID uuid.UUID, req *models.AccessRequest, actor string) (WorkflowDecision, error) {
	decision, err := ResolveDecision(req)
	if err != nil {
		return WorkflowDecision{}, err
	}
	if decision.StepType == WorkflowStepAutoApprove {
		if err := s.requestSvc.ApproveRequest(ctx, workspaceID, req.ID, actor, "auto-approved: "+decision.Reason); err != nil {
			return WorkflowDecision{}, err
		}
		decision.Approved = true
	}
	return decision, nil
}

// decodeRiskFactors safely decodes AccessRequest.RiskFactors into a []string.
// Empty / malformed payloads decode to nil.
func decodeRiskFactors(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var factors []string
	if err := json.Unmarshal(raw, &factors); err != nil {
		return nil
	}
	return factors
}
