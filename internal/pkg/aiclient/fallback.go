package aiclient

import (
	"context"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// Skill names registered by the Python agent (cmd/access-ai-agent/main.py
// SKILLS table). Exported so callers reference the canonical strings rather
// than hand-typed literals.
const (
	SkillAccessRiskAssessment   = "access_risk_assessment"
	SkillAccessReviewAutomation = "access_review_automation"
	SkillAccessAnomalyDetection = "access_anomaly_detection"
	SkillConnectorSetup         = "connector_setup_assistant"
	SkillPolicyRecommendation   = "policy_recommendation"
	SkillPAMSessionRisk         = "pam_session_risk_assessment"
	SkillPAMBehavioural         = "pam_behavioural_analytics"
)

// Risk-score vocabulary, shared with lifecycle.WorkflowService routing.
const (
	RiskLow    = "low"
	RiskMedium = "medium"
	RiskHigh   = "high"
)

// DefaultRiskScore is the fail-safe risk score used when the agent is
// unreachable and the caller has NOT requested fail-closed. "medium" routes the
// request to manager_approval — a human in the loop — rather than auto-approving
// or hard-denying on a transient AI outage.
const DefaultRiskScore = RiskMedium

// FailClosedRiskScore is the score returned on agent unavailability when the
// caller requests fail-closed. "high" forces security_review so a privileged
// request cannot proceed without elevated human approval while AI is down.
const FailClosedRiskScore = RiskHigh

// aiUnavailableFactor is appended to the risk factors of a fallback result so
// downstream audit and UI can distinguish an AI-derived score from a degraded
// one.
const aiUnavailableFactor = "ai_unavailable"

// RiskAssessmentInput is the payload for the access_risk_assessment skill.
type RiskAssessmentInput struct {
	Role               string   `json:"role"`
	ResourceExternalID string   `json:"resource_external_id"`
	ResourceTags       []string `json:"resource_tags,omitempty"`
	DurationHours      int      `json:"duration_hours,omitempty"`
	Justification      string   `json:"justification,omitempty"`
}

// RiskAssessment is the normalized result of a risk scoring call.
type RiskAssessment struct {
	// Score is one of low/medium/high.
	Score string
	// Factors is the structured list of contributing signals.
	Factors []string
	// Reason is a short human-readable rationale.
	Reason string
	// Degraded is true when the assessment is a fallback (agent unreachable),
	// not a real AI/deterministic-agent response.
	Degraded bool
}

// AssessRisk invokes the access_risk_assessment skill and normalizes the
// response. It returns the raw error (including ErrAIUnconfigured) so callers
// that need to distinguish outcomes can; most callers should prefer
// AssessRiskWithFallback.
func AssessRisk(ctx context.Context, c *AIClient, workspaceAITier string, in RiskAssessmentInput) (RiskAssessment, error) {
	resp, err := c.InvokeSkillForTier(ctx, SkillAccessRiskAssessment, workspaceAITier, in)
	if err != nil {
		return RiskAssessment{}, err
	}
	score := normalizeScore(resp.RiskScore)
	return RiskAssessment{
		Score:   score,
		Factors: resp.RiskFactors,
		Reason:  resp.Reason,
	}, nil
}

// AssessRiskWithFallback never errors: on any agent failure it returns a
// degraded assessment whose score is DefaultRiskScore (fail-safe →
// manager_approval) or, when failClosed is true, FailClosedRiskScore
// (fail-closed → security_review). This is the helper the workflow engine wires
// at request-creation so an unreachable agent degrades the control plane
// gracefully instead of blocking privileged decisions.
func AssessRiskWithFallback(ctx context.Context, c *AIClient, workspaceAITier string, in RiskAssessmentInput, failClosed bool) RiskAssessment {
	res, err := AssessRisk(ctx, c, workspaceAITier, in)
	if err == nil {
		return res
	}
	logger.Warnf(ctx, "aiclient: risk assessment fallback (failClosed=%t): %v", failClosed, err)
	score := DefaultRiskScore
	if failClosed {
		score = FailClosedRiskScore
	}
	return RiskAssessment{
		Score:    score,
		Factors:  []string{aiUnavailableFactor},
		Reason:   "ai agent unavailable; applied fail-" + failModeName(failClosed) + " default",
		Degraded: true,
	}
}

// ReviewAutomationInput is the payload for the access_review_automation skill.
type ReviewAutomationInput struct {
	Role            string   `json:"role"`
	ResourceRef     string   `json:"resource_ref"`
	LastUsedDays    int      `json:"last_used_days,omitempty"`
	UsageEventCount int      `json:"usage_event_count,omitempty"`
	RiskFactors     []string `json:"risk_factors,omitempty"`
}

// ReviewRecommendation is the normalized result of a review-automation call.
type ReviewRecommendation struct {
	// Decision is one of certify / revoke / escalate / manual_review.
	Decision string
	Reason   string
	Degraded bool
}

// Review decisions surfaced by the access_review_automation skill, plus the
// fail-safe fallback.
const (
	ReviewDecisionCertify = "certify"
	ReviewDecisionRevoke  = "revoke"
	ReviewDecisionManual  = "manual_review"
)

// AutomateReviewWithFallback returns a per-grant review recommendation. On agent
// failure it falls back to "manual_review" — never an automatic revoke or
// certify — so a degraded AI can never silently tear down or rubber-stamp
// access; a human decides.
func AutomateReviewWithFallback(ctx context.Context, c *AIClient, workspaceAITier string, in ReviewAutomationInput) ReviewRecommendation {
	resp, err := c.InvokeSkillForTier(ctx, SkillAccessReviewAutomation, workspaceAITier, in)
	if err != nil {
		logger.Warnf(ctx, "aiclient: review automation fallback: %v", err)
		return ReviewRecommendation{Decision: ReviewDecisionManual, Reason: "ai agent unavailable; deferring to human review", Degraded: true}
	}
	decision := resp.Decision
	if decision == "" {
		decision = ReviewDecisionManual
	}
	return ReviewRecommendation{Decision: decision, Reason: resp.Reason}
}

// AnomalyDetectionInput is the payload for the access_anomaly_detection skill.
type AnomalyDetectionInput struct {
	GrantID      string   `json:"grant_id"`
	Role         string   `json:"role"`
	ResourceRef  string   `json:"resource_ref"`
	UsageRegions []string `json:"usage_regions,omitempty"`
	UsageHours   []int    `json:"usage_hours,omitempty"`
	LastUsedDays int      `json:"last_used_days,omitempty"`
}

// DetectAnomaliesWithFallback returns the agent's anomaly observations. Anomaly
// detection is advisory (it never blocks a decision), so the fallback is an
// empty slice — the absence of a signal, not a synthetic one.
func DetectAnomaliesWithFallback(ctx context.Context, c *AIClient, workspaceAITier string, in AnomalyDetectionInput) []AnomalyEvent {
	resp, err := c.InvokeSkillForTier(ctx, SkillAccessAnomalyDetection, workspaceAITier, in)
	if err != nil {
		logger.Warnf(ctx, "aiclient: anomaly detection fallback (empty): %v", err)
		return nil
	}
	return resp.Anomalies
}

// SessionRiskInput is the payload for the pam_session_risk_assessment skill.
type SessionRiskInput struct {
	UserExternalID string   `json:"user_external_id"`
	TargetRef      string   `json:"target_ref"`
	Commands       []string `json:"commands,omitempty"`
	SourceIP       string   `json:"source_ip,omitempty"`
}

// SessionRisk is the normalized result of a PAM session-risk call.
type SessionRisk struct {
	Score          string
	Factors        []string
	Recommendation string
	Degraded       bool
}

// AssessSessionRiskWithFallback scores a privileged session. On agent failure it
// returns DefaultRiskScore / FailClosedRiskScore per failClosed, mirroring
// AssessRiskWithFallback so PAM session gating degrades consistently.
func AssessSessionRiskWithFallback(ctx context.Context, c *AIClient, workspaceAITier string, in SessionRiskInput, failClosed bool) SessionRisk {
	resp, err := c.InvokeSkillForTier(ctx, SkillPAMSessionRisk, workspaceAITier, in)
	if err != nil {
		logger.Warnf(ctx, "aiclient: session risk fallback (failClosed=%t): %v", failClosed, err)
		score := DefaultRiskScore
		if failClosed {
			score = FailClosedRiskScore
		}
		return SessionRisk{Score: score, Factors: []string{aiUnavailableFactor}, Recommendation: "ai agent unavailable; manual review advised", Degraded: true}
	}
	return SessionRisk{Score: normalizeScore(resp.RiskScore), Factors: resp.RiskFactors, Recommendation: resp.Recommendation}
}

// BehaviourSession is one privileged-session summary in a BehaviourAnalyticsInput.
type BehaviourSession struct {
	StartHour    int    `json:"start_hour,omitempty"`
	DurationMin  int    `json:"duration_minutes,omitempty"`
	CommandCount int    `json:"command_count,omitempty"`
	Target       string `json:"target,omitempty"`
}

// BehaviourBaseline is the user's normal-behaviour reference that the analytics
// skill compares recent sessions against.
type BehaviourBaseline struct {
	Targets         []string `json:"targets,omitempty"`
	AvgCommandCount float64  `json:"avg_command_count,omitempty"`
}

// BehaviourAnalyticsInput is the payload for the pam_behavioural_analytics skill.
type BehaviourAnalyticsInput struct {
	UserExternalID string             `json:"user_external_id"`
	Sessions       []BehaviourSession `json:"sessions,omitempty"`
	Baseline       *BehaviourBaseline `json:"baseline,omitempty"`
}

// AnalyzeBehaviourWithFallback returns behavioural anomalies for a privileged
// user's recent sessions. Like anomaly detection it is advisory (it never blocks
// a decision), so the fallback is an empty slice — the absence of a signal, not
// a synthetic one.
func AnalyzeBehaviourWithFallback(ctx context.Context, c *AIClient, workspaceAITier string, in BehaviourAnalyticsInput) []AnomalyEvent {
	resp, err := c.InvokeSkillForTier(ctx, SkillPAMBehavioural, workspaceAITier, in)
	if err != nil {
		logger.Warnf(ctx, "aiclient: behavioural analytics fallback (empty): %v", err)
		return nil
	}
	return resp.Anomalies
}

// PolicyRecommendationInput is the payload for the policy_recommendation skill.
type PolicyRecommendationInput struct {
	WorkspaceID string   `json:"workspace_id"`
	Resource    string   `json:"resource,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	Context     string   `json:"context,omitempty"`
}

// RecommendPolicyWithFallback returns the agent's policy explanation/rationale.
// Policy recommendation is advisory, so the fallback is an empty string.
func RecommendPolicyWithFallback(ctx context.Context, c *AIClient, workspaceAITier string, in PolicyRecommendationInput) string {
	resp, err := c.InvokeSkillForTier(ctx, SkillPolicyRecommendation, workspaceAITier, in)
	if err != nil {
		logger.Warnf(ctx, "aiclient: policy recommendation fallback (empty): %v", err)
		return ""
	}
	return resp.Explanation
}

// normalizeScore lowercases and validates a risk score against the
// low/medium/high vocabulary, coercing anything else to DefaultRiskScore so a
// malformed agent response can never produce an out-of-band score that the
// router would treat as "unknown".
func normalizeScore(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case RiskLow:
		return RiskLow
	case RiskMedium:
		return RiskMedium
	case RiskHigh:
		return RiskHigh
	default:
		return DefaultRiskScore
	}
}

func failModeName(failClosed bool) string {
	if failClosed {
		return "closed"
	}
	return "safe"
}
