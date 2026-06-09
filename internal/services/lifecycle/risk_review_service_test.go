package lifecycle

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/aiclient"
)

// agentResponse is the subset of the agent's SkillResponse envelope the mock
// transport emits. Mocking the aiclient transport (rather than the agent
// process) keeps these tests hermetic; a real external agent is impractical in
// a unit test, which is the documented reason a mock is allowed here.
type agentResponse struct {
	RiskScore   string   `json:"risk_score,omitempty"`
	RiskFactors []string `json:"risk_factors,omitempty"`
	Reason      string   `json:"reason,omitempty"`
}

// mockAgent returns an AIClient pointed at an httptest server that replies to
// /a2a/invoke with the supplied responder. A nil responder makes the server
// return 500 so the client's error path (→ fail-open fallback) is exercised.
func mockAgent(t *testing.T, responder func() agentResponse) *aiclient.AIClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if responder == nil {
			http.Error(w, "agent down", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(responder())
	}))
	t.Cleanup(srv.Close)
	return aiclient.NewAIClient(srv.URL, nil, "")
}

func newRiskReview(t *testing.T, ai *aiclient.AIClient) (*RiskReviewService, *AccessRequestService) {
	t.Helper()
	db := newTestDB(t)
	reqSvc := NewAccessRequestService(db)
	return NewRiskReviewService(db, reqSvc, ai), reqSvc
}

func seedRequested(t *testing.T, reqSvc *AccessRequestService, ws uuid.UUID, role string) *models.AccessRequest {
	t.Helper()
	req, err := reqSvc.CreateRequest(context.Background(), CreateAccessRequestInput{
		WorkspaceID: ws, RequesterID: "u", ResourceRef: "app:db", Role: role,
	})
	if err != nil {
		t.Fatalf("seed request: %v", err)
	}
	return req
}

// TestReviewRequestPersistsVerdictAndTransitions proves a real (non-degraded)
// AI verdict is persisted with the score/recommendation/rationale and the
// request is moved requested → ai_reviewed with history + audit.
func TestReviewRequestPersistsVerdictAndTransitions(t *testing.T) {
	ai := mockAgent(t, func() agentResponse {
		return agentResponse{RiskScore: "low", RiskFactors: []string{"baseline_low_risk"}, Reason: "looks fine"}
	})
	svc, reqSvc := newRiskReview(t, ai)
	db := reqSvc.db
	ws := seedWorkspace(t, db, "tenant-a")
	req := seedRequested(t, reqSvc, ws, "reader")
	ctx := context.Background()

	res, err := svc.ReviewRequest(ctx, RiskReviewInput{
		WorkspaceID: ws, RequestID: req.ID, Actor: "u", Role: "reader", ResourceRef: "app:db",
	})
	if err != nil {
		t.Fatalf("ReviewRequest: %v", err)
	}
	if res.Verdict.Score != "low" {
		t.Fatalf("score = %q, want low", res.Verdict.Score)
	}
	if res.Verdict.Recommendation != RecommendationAutoApprove {
		t.Fatalf("recommendation = %q, want %q", res.Verdict.Recommendation, RecommendationAutoApprove)
	}
	if res.Verdict.Degraded {
		t.Fatal("verdict should not be degraded for a healthy agent")
	}
	if res.Verdict.Source != RiskVerdictSourceAIAgent {
		t.Fatalf("source = %q, want %q", res.Verdict.Source, RiskVerdictSourceAIAgent)
	}
	if res.Verdict.Rationale != "looks fine" {
		t.Fatalf("rationale = %q, want model reason", res.Verdict.Rationale)
	}
	if res.Request.State != StateAIReviewed {
		t.Fatalf("state = %q, want ai_reviewed", res.Request.State)
	}

	// Verdict row persisted and inputs captured.
	latest, err := svc.LatestVerdict(ctx, ws, req.ID)
	if err != nil {
		t.Fatalf("LatestVerdict: %v", err)
	}
	if latest.ID != res.Verdict.ID {
		t.Fatalf("latest verdict id mismatch")
	}
	if len(latest.Inputs) == 0 {
		t.Fatal("verdict inputs not persisted")
	}

	// History shows requested → ai_reviewed.
	hist, _ := reqSvc.History(ctx, ws, req.ID)
	sawAIReviewed := false
	for _, h := range hist {
		if h.ToState == StateAIReviewed && h.FromState == StateRequested {
			sawAIReviewed = true
		}
	}
	if !sawAIReviewed {
		t.Fatalf("missing requested→ai_reviewed history: %+v", hist)
	}

	// Audit chain carries both the risk_assessed and the ai_reviewed events.
	var assessed, reviewed int64
	db.Model(&models.AuditEvent{}).Where("workspace_id = ? AND action = ?", ws, "access_request.risk_assessed").Count(&assessed)
	db.Model(&models.AuditEvent{}).Where("workspace_id = ? AND action = ?", ws, "access_request.ai_reviewed").Count(&reviewed)
	if assessed != 1 || reviewed != 1 {
		t.Fatalf("audit events: risk_assessed=%d ai_reviewed=%d, want 1/1", assessed, reviewed)
	}
}

// TestReviewRequestFailOpenFallback proves an unreachable agent yields a
// degraded medium / needs_review verdict (never auto_approve) so a model outage
// routes to a human instead of blocking or rubber-stamping.
func TestReviewRequestFailOpenFallback(t *testing.T) {
	svc, reqSvc := newRiskReview(t, mockAgent(t, nil)) // 500 → fail-open
	db := reqSvc.db
	ws := seedWorkspace(t, db, "tenant-a")
	req := seedRequested(t, reqSvc, ws, "reader")

	res, err := svc.ReviewRequest(context.Background(), RiskReviewInput{
		WorkspaceID: ws, RequestID: req.ID, Actor: "u", Role: "reader", ResourceRef: "app:db",
	})
	if err != nil {
		t.Fatalf("ReviewRequest: %v", err)
	}
	if res.Verdict.Score != aiclient.RiskMedium {
		t.Fatalf("fallback score = %q, want medium", res.Verdict.Score)
	}
	if res.Verdict.Recommendation != RecommendationNeedsReview {
		t.Fatalf("fallback recommendation = %q, want needs_review", res.Verdict.Recommendation)
	}
	if !res.Verdict.Degraded {
		t.Fatal("fallback verdict must be flagged degraded")
	}
	if res.Verdict.Source != RiskVerdictSourceFallback {
		t.Fatalf("source = %q, want fallback", res.Verdict.Source)
	}
	if res.Verdict.Recommendation == RecommendationAutoApprove {
		t.Fatal("fail-open must never auto-approve")
	}
}

// TestReviewRequestMalformedScoreNormalized proves an out-of-band model score
// can never write an out-of-band verdict: the aiclient normalizes an unknown
// score to medium, and the persisted recommendation follows the normalized
// band (needs_review), not the raw model output.
func TestReviewRequestMalformedScoreNormalized(t *testing.T) {
	ai := mockAgent(t, func() agentResponse {
		return agentResponse{RiskScore: "CATASTROPHIC", RiskFactors: []string{"garbage"}, Reason: "?"}
	})
	svc, reqSvc := newRiskReview(t, ai)
	db := reqSvc.db
	ws := seedWorkspace(t, db, "tenant-a")
	req := seedRequested(t, reqSvc, ws, "reader")

	res, err := svc.ReviewRequest(context.Background(), RiskReviewInput{
		WorkspaceID: ws, RequestID: req.ID, Actor: "u", Role: "reader", ResourceRef: "app:db",
	})
	if err != nil {
		t.Fatalf("ReviewRequest: %v", err)
	}
	if res.Verdict.Score != aiclient.RiskMedium {
		t.Fatalf("malformed score normalized to %q, want medium", res.Verdict.Score)
	}
	if res.Verdict.Recommendation != RecommendationNeedsReview {
		t.Fatalf("recommendation = %q, want needs_review", res.Verdict.Recommendation)
	}
}

// TestReviewRequestSensitiveTagForcesHighRisk proves a "sensitive" resource tag
// forces high_risk regardless of the model's numeric score (the tag can only
// raise risk), so the request requires a human + step-up.
func TestReviewRequestSensitiveTagForcesHighRisk(t *testing.T) {
	ai := mockAgent(t, func() agentResponse {
		return agentResponse{RiskScore: "low", RiskFactors: nil, Reason: "model says low"}
	})
	svc, reqSvc := newRiskReview(t, ai)
	db := reqSvc.db
	ws := seedWorkspace(t, db, "tenant-a")
	req := seedRequested(t, reqSvc, ws, "reader")

	res, err := svc.ReviewRequest(context.Background(), RiskReviewInput{
		WorkspaceID: ws, RequestID: req.ID, Actor: "u", Role: "reader", ResourceRef: "app:db",
		ResourceTags: []string{"sensitive"},
	})
	if err != nil {
		t.Fatalf("ReviewRequest: %v", err)
	}
	if res.Verdict.Recommendation != RecommendationHighRisk {
		t.Fatalf("recommendation = %q, want high_risk", res.Verdict.Recommendation)
	}
	reloaded, _ := reqSvc.GetRequest(context.Background(), ws, req.ID)
	if !RequiresStepUp(reloaded) {
		t.Fatal("sensitive-tagged request must require step-up")
	}
}

// TestReviewRequestRejectsNonRequestedState proves the gate is FSM-guarded: a
// request already past requested cannot be re-reviewed into ai_reviewed.
func TestReviewRequestRejectsNonRequestedState(t *testing.T) {
	svc, reqSvc := newRiskReview(t, mockAgent(t, func() agentResponse {
		return agentResponse{RiskScore: "low"}
	}))
	db := reqSvc.db
	ws := seedWorkspace(t, db, "tenant-a")
	req := seedRequested(t, reqSvc, ws, "reader")
	ctx := context.Background()
	if err := reqSvc.ApproveRequest(ctx, ws, req.ID, "mgr", "ok"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	_, err := svc.ReviewRequest(ctx, RiskReviewInput{
		WorkspaceID: ws, RequestID: req.ID, Actor: "u", Role: "reader", ResourceRef: "app:db",
	})
	if err == nil {
		t.Fatal("expected illegal-transition error reviewing an approved request")
	}
}

// TestReviewRequestCrossTenantIsolation proves a verdict and the transition are
// workspace-scoped: reviewing with the wrong workspace id finds no request.
func TestReviewRequestCrossTenantIsolation(t *testing.T) {
	svc, reqSvc := newRiskReview(t, mockAgent(t, func() agentResponse {
		return agentResponse{RiskScore: "low"}
	}))
	db := reqSvc.db
	wsA := seedWorkspace(t, db, "tenant-a")
	wsB := seedWorkspace(t, db, "tenant-b")
	req := seedRequested(t, reqSvc, wsA, "reader")

	_, err := svc.ReviewRequest(context.Background(), RiskReviewInput{
		WorkspaceID: wsB, RequestID: req.ID, Actor: "attacker", Role: "reader", ResourceRef: "app:db",
	})
	if err == nil {
		t.Fatal("expected not-found reviewing tenant-a's request as tenant-b")
	}
	// tenant-b sees no verdict for the id either.
	if _, verr := svc.LatestVerdict(context.Background(), wsB, req.ID); verr == nil {
		t.Fatal("tenant-b must not see tenant-a's verdict")
	}
}

// TestRecordApprovalAnomaliesPersistsFlags proves approved elevations are fed to
// the anomaly skill and any observations are persisted as advisory flags.
func TestRecordApprovalAnomaliesPersistsFlags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"anomalies": []map[string]any{
				{"kind": "off_hours_access", "severity": "medium", "reason": "3am login", "confidence": 0.8},
				{"kind": "", "reason": "dropped (no kind)"},
			},
		})
	}))
	t.Cleanup(srv.Close)
	ai := aiclient.NewAIClient(srv.URL, nil, "")
	svc, reqSvc := newRiskReview(t, ai)
	db := reqSvc.db
	ws := seedWorkspace(t, db, "tenant-a")
	req := seedRequested(t, reqSvc, ws, "reader")

	if err := svc.RecordApprovalAnomalies(context.Background(), ws, req, nil); err != nil {
		t.Fatalf("RecordApprovalAnomalies: %v", err)
	}
	flags, err := svc.ListAnomalyFlags(context.Background(), ws, req.ID)
	if err != nil {
		t.Fatalf("ListAnomalyFlags: %v", err)
	}
	if len(flags) != 1 {
		t.Fatalf("flags = %d, want 1 (the kind-less one is dropped)", len(flags))
	}
	if flags[0].Kind != "off_hours_access" || flags[0].Severity != "medium" {
		t.Fatalf("unexpected flag: %+v", flags[0])
	}
}

// TestRecordApprovalAnomaliesFailOpen proves an unreachable anomaly agent yields
// no flags (advisory, fail-open) and never errors the approval.
func TestRecordApprovalAnomaliesFailOpen(t *testing.T) {
	svc, reqSvc := newRiskReview(t, mockAgent(t, nil)) // 500
	db := reqSvc.db
	ws := seedWorkspace(t, db, "tenant-a")
	req := seedRequested(t, reqSvc, ws, "reader")

	if err := svc.RecordApprovalAnomalies(context.Background(), ws, req, nil); err != nil {
		t.Fatalf("anomaly hook must be fail-open, got %v", err)
	}
	flags, _ := svc.ListAnomalyFlags(context.Background(), ws, req.ID)
	if len(flags) != 0 {
		t.Fatalf("flags = %d, want 0 on agent outage", len(flags))
	}
}
