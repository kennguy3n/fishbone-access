package lifecycle

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
	"github.com/kennguy3n/fishbone-access/internal/pkg/aiclient"
)

// Risk recommendations — the routing-facing verdict surfaced to the UI and
// persisted on every AccessRiskVerdict. They are derived deterministically on
// the Go side from the normalized risk band + factors (recommendationFor), so a
// malformed or absent model recommendation can never drive an authorization
// decision: the model influences the SCORE, the control plane decides the
// recommendation.
const (
	// RecommendationAutoApprove marks a low-risk, policy-eligible request the
	// workflow may fast-track (auto-approve). Only an AI-derived (non-degraded)
	// low score reaches this; the fail-open fallback never does.
	RecommendationAutoApprove = "auto_approve_eligible"
	// RecommendationNeedsReview parks the request for a human manager
	// (medium / unknown risk, and the fail-open default).
	RecommendationNeedsReview = "needs_review"
	// RecommendationHighRisk forces a security reviewer + step-up MFA and is
	// never auto-approved (high risk, or any sensitive-resource request).
	RecommendationHighRisk = "high_risk"
)

// RequiresStepUp reports whether approving the request requires step-up MFA: it
// is true exactly when the request's persisted risk maps to the high_risk
// recommendation (a high score, or any sensitive-resource factor). High-risk
// elevations always require a human approver whose token carries satisfied MFA;
// the gate is fail-CLOSED — a nil request (no verdict to read) also requires
// step-up rather than waving the approval through.
func RequiresStepUp(req *models.AccessRequest) bool {
	if req == nil {
		return true
	}
	return recommendationFor(req.RiskLevel, decodeRiskFactors(req.RiskFactors)) == RecommendationHighRisk
}

// Risk-verdict provenance recorded on AccessRiskVerdict.Source.
const (
	RiskVerdictSourceAIAgent  = "ai_agent"
	RiskVerdictSourceFallback = "fallback"
)

// recommendationFor maps a normalized risk band + factors to the routing-facing
// recommendation. It is defined in terms of Route so the recommendation and the
// workflow lane can never disagree: auto_approve lane → auto_approve_eligible,
// security_review lane → high_risk, everything else → needs_review.
func recommendationFor(score string, factors []string) string {
	switch Route(score, factors).StepType {
	case WorkflowStepAutoApprove:
		return RecommendationAutoApprove
	case WorkflowStepSecurityReview:
		return RecommendationHighRisk
	default:
		return RecommendationNeedsReview
	}
}

// RiskReviewInput carries the model-input signals for a synchronous risk review.
// WorkspaceID and RequestID identify the (workspace-scoped) request; Role,
// ResourceRef, Justification mirror what was requested. ResourceTags and
// DurationHours are advisory signals fed to the model — they can only RAISE the
// assessed risk (a "sensitive" tag forces security_review), never lower it, so
// accepting them from the caller cannot be used to dodge review.
type RiskReviewInput struct {
	WorkspaceID   uuid.UUID
	RequestID     uuid.UUID
	Actor         string
	Role          string
	ResourceRef   string
	Justification string
	ResourceTags  []string
	DurationHours int
}

// RiskReviewResult is the outcome of ReviewRequest: the persisted verdict plus
// the request reloaded in its post-review state (ai_reviewed).
type RiskReviewResult struct {
	Verdict *models.AccessRiskVerdict
	Request *models.AccessRequest
}

// RiskReviewService bakes the AI risk assessment into the synchronous elevation
// request flow as a first-class, audited gate. For every submitted request it
// asks the access-ai-agent risk-assessment skill (server-side, Bonsai-8B via
// aiclient) for a structured verdict, persists the verdict + the exact model
// inputs + the model's rationale for audit, and moves the request through the
// audited requested → ai_reviewed transition — all atomically.
//
// The gate is fail-OPEN for this advisory score: an unreachable agent yields a
// "medium / needs_review" fallback (never auto_approve_eligible) so a model
// outage routes to a human instead of blocking or rubber-stamping the request.
// It never trusts a client-supplied risk level; the verdict is derived solely
// from the agent (or the fail-open fallback) and the resource signals.
type RiskReviewService struct {
	db       *gorm.DB
	requests *AccessRequestService
	ai       *aiclient.AIClient
	now      func() time.Time
}

// NewRiskReviewService wires the service to the shared pool, the request service
// (whose TransitionInTx flips state inside the verdict transaction), and the AI
// client. ai must be non-nil; pass an unconfigured client (aiclient.NewAIClient
// ("", nil, "")) to force the deterministic fail-open path when no agent is
// configured.
func NewRiskReviewService(db *gorm.DB, requests *AccessRequestService, ai *aiclient.AIClient) *RiskReviewService {
	return &RiskReviewService{db: db, requests: requests, ai: ai, now: time.Now}
}

// SetClock overrides the time source. Intended for tests that pin timestamps.
func (s *RiskReviewService) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// ReviewRequest assesses the request's risk via the AI agent (fail-open
// fallback when unreachable), then, in a single transaction: appends the
// risk-assessed audit event with the full verdict metadata, persists an
// immutable AccessRiskVerdict row (score, recommendation, factors, rationale,
// the exact model inputs, and the degraded flag), writes the AI-derived risk
// level + factors back onto the request, and transitions it
// requested → ai_reviewed (which records its own history + audit row). The
// request must currently be in StateRequested; the FSM gate rejects anything
// else with ErrInvalidStateTransition.
func (s *RiskReviewService) ReviewRequest(ctx context.Context, in RiskReviewInput) (*RiskReviewResult, error) {
	if in.WorkspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if in.RequestID == uuid.Nil {
		return nil, fmt.Errorf("%w: request_id is required", ErrValidation)
	}

	aiTier := s.resolveAITier(ctx, in.WorkspaceID)

	// Advisory scoring is fail-OPEN: a model outage must route to a human, not
	// block the request, so failClosed=false (→ medium/needs_review fallback).
	assessment := aiclient.AssessRiskWithFallback(ctx, s.ai, aiTier, aiclient.RiskAssessmentInput{
		Role:               in.Role,
		ResourceExternalID: in.ResourceRef,
		ResourceTags:       in.ResourceTags,
		DurationHours:      in.DurationHours,
		Justification:      in.Justification,
	}, false)

	// A "sensitive" resource tag forces the security-review lane independent of
	// the model's numeric score (it can only raise risk), de-duplicated.
	factors := withSensitiveFactor(assessment.Factors, in.ResourceTags)
	score := assessment.Score
	recommendation := recommendationFor(score, factors)
	source := RiskVerdictSourceAIAgent
	if assessment.Degraded {
		source = RiskVerdictSourceFallback
	}

	factorsJSON, err := json.Marshal(factors)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: marshal risk factors: %w", err)
	}
	inputsJSON, err := json.Marshal(map[string]any{
		"role":           in.Role,
		"resource_ref":   in.ResourceRef,
		"resource_tags":  in.ResourceTags,
		"duration_hours": in.DurationHours,
		"justification":  in.Justification,
		"ai_tier":        aiTier,
	})
	if err != nil {
		return nil, fmt.Errorf("lifecycle: marshal risk inputs: %w", err)
	}

	verdict := &models.AccessRiskVerdict{
		WorkspaceID:    in.WorkspaceID,
		RequestID:      in.RequestID,
		Score:          score,
		Recommendation: recommendation,
		Factors:        datatypes.JSON(factorsJSON),
		Rationale:      assessment.Reason,
		Inputs:         datatypes.JSON(inputsJSON),
		Source:         source,
		Degraded:       assessment.Degraded,
	}

	now := s.now()
	var updated *models.AccessRequest
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Record the AI verdict in the tamper-evident hash chain first, with the
		// full structured metadata, so the audit log carries the score even if a
		// later step in this tx fails (it would roll back together — this just
		// fixes a deterministic chain order: risk_assessed then ai_reviewed).
		meta, merr := json.Marshal(map[string]any{
			"score":          score,
			"recommendation": recommendation,
			"factors":        factors,
			"degraded":       assessment.Degraded,
			"source":         source,
		})
		if merr != nil {
			return fmt.Errorf("lifecycle: marshal audit metadata: %w", merr)
		}
		if aerr := appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: in.WorkspaceID,
			Actor:       in.Actor,
			Action:      "access_request.risk_assessed",
			TargetRef:   in.RequestID.String(),
			Metadata:    datatypes.JSON(meta),
		}); aerr != nil {
			return aerr
		}

		verdict.CreatedAt = now
		verdict.UpdatedAt = now
		if cerr := tx.WithContext(ctx).Create(verdict).Error; cerr != nil {
			return fmt.Errorf("lifecycle: insert risk verdict: %w", cerr)
		}

		// Persist the AI-derived risk onto the request (workspace-scoped) so the
		// workflow router and the UI read the model's verdict, never the client's.
		if uerr := tx.WithContext(ctx).
			Model(&models.AccessRequest{}).
			Where("workspace_id = ? AND id = ?", in.WorkspaceID, in.RequestID).
			Updates(map[string]any{
				"risk_level":   score,
				"risk_factors": datatypes.JSON(factorsJSON),
				"updated_at":   now,
			}).Error; uerr != nil {
			return fmt.Errorf("lifecycle: persist risk on request: %w", uerr)
		}

		// Audited transition requested → ai_reviewed; reason carries the verdict
		// summary so the state-history trail is self-describing.
		req, terr := s.requests.TransitionInTx(ctx, tx, in.WorkspaceID, in.RequestID, StateAIReviewed, in.Actor,
			fmt.Sprintf("AI risk review: %s / %s", score, recommendation))
		if terr != nil {
			return terr
		}
		updated = req
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &RiskReviewResult{Verdict: verdict, Request: updated}, nil
}

// LatestVerdict returns the operative (most recent) risk verdict for a request,
// or ErrRequestNotFound when the request has no verdict in this workspace. It is
// workspace-scoped so a cross-tenant request id is invisible.
func (s *RiskReviewService) LatestVerdict(ctx context.Context, workspaceID, requestID uuid.UUID) (*models.AccessRiskVerdict, error) {
	var v models.AccessRiskVerdict
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND request_id = ?", workspaceID, requestID).
		Order("created_at desc, id desc").
		Limit(1).
		Take(&v).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrRequestNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lifecycle: load risk verdict: %w", err)
	}
	return &v, nil
}

// ListAnomalyFlags returns the anomaly flags surfaced against a request, newest
// first. Workspace-scoped.
func (s *RiskReviewService) ListAnomalyFlags(ctx context.Context, workspaceID, requestID uuid.UUID) ([]models.AccessRequestAnomalyFlag, error) {
	var out []models.AccessRequestAnomalyFlag
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND request_id = ?", workspaceID, requestID).
		Order("created_at desc, id desc").
		Find(&out).Error; err != nil {
		return nil, fmt.Errorf("lifecycle: list anomaly flags: %w", err)
	}
	return out, nil
}

// RecordApprovalAnomalies feeds a just-approved elevation to the
// anomaly-detection skill and persists any returned observations as advisory
// flags on the request (which surface on the request detail and, being
// workspace-scoped + grant-linked, inside access reviews). It is fail-OPEN and
// advisory: an unreachable agent yields no flags (the absence of a signal, not
// a synthetic one) and a flag never changes the request's FSM state, so this
// can never block or reverse an approval. grantID is optional (nil before
// provisioning). Errors persisting a flag are returned so the caller can log
// them, but they never propagate to the approval decision.
func (s *RiskReviewService) RecordApprovalAnomalies(ctx context.Context, workspaceID uuid.UUID, req *models.AccessRequest, grantID *uuid.UUID) error {
	if req == nil {
		return fmt.Errorf("%w: request is required", ErrValidation)
	}
	aiTier := s.resolveAITier(ctx, workspaceID)
	grantRef := ""
	if grantID != nil {
		grantRef = grantID.String()
	}
	events := aiclient.DetectAnomaliesWithFallback(ctx, s.ai, aiTier, aiclient.AnomalyDetectionInput{
		GrantID:     grantRef,
		Role:        req.Role,
		ResourceRef: req.ResourceRef,
	})
	if len(events) == 0 {
		return nil
	}
	now := s.now()
	rows := make([]models.AccessRequestAnomalyFlag, 0, len(events))
	for _, e := range events {
		if strings.TrimSpace(e.Kind) == "" {
			continue
		}
		row := models.AccessRequestAnomalyFlag{
			WorkspaceID: workspaceID,
			RequestID:   req.ID,
			GrantID:     grantID,
			Kind:        e.Kind,
			Severity:    e.Severity,
			Reason:      e.Reason,
			Confidence:  e.Confidence,
		}
		row.CreatedAt = now
		row.UpdatedAt = now
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return nil
	}
	if err := s.db.WithContext(ctx).Create(&rows).Error; err != nil {
		return fmt.Errorf("lifecycle: insert anomaly flags: %w", err)
	}
	return nil
}

// resolveAITier maps the workspace's plan to the AI tier the agent uses to pick
// a model via the shared aiclient.TierForPlan mapping. A failed lookup passes an
// empty plan, which fails safe to the deterministic tier rather than guessing a
// higher one.
func (s *RiskReviewService) resolveAITier(ctx context.Context, workspaceID uuid.UUID) string {
	var ws models.Workspace
	if err := s.db.WithContext(ctx).
		Select("plan").
		Where("id = ?", workspaceID).
		Take(&ws).Error; err != nil {
		return aiclient.TierForPlan("")
	}
	return aiclient.TierForPlan(ws.Plan)
}

// withSensitiveFactor appends the sensitive_resource risk factor (which forces
// the security-review lane) when the caller tagged the resource sensitive but
// the model did not already flag it, de-duplicated so the factor appears once.
// Mirrors the async workflow engine's ensureSensitiveFactor so the synchronous
// and asynchronous lanes treat a sensitive tag identically.
func withSensitiveFactor(factors, tags []string) []string {
	sensitive := false
	for _, t := range tags {
		if strings.EqualFold(strings.TrimSpace(t), "sensitive") ||
			strings.EqualFold(strings.TrimSpace(t), SensitiveResourceRiskFactor) {
			sensitive = true
			break
		}
	}
	if !sensitive {
		return factors
	}
	for _, f := range factors {
		if strings.EqualFold(strings.TrimSpace(f), SensitiveResourceRiskFactor) {
			return factors
		}
	}
	out := make([]string, len(factors), len(factors)+1)
	copy(out, factors)
	return append(out, SensitiveResourceRiskFactor)
}
