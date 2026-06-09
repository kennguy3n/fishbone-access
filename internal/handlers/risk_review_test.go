package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/aiclient"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// mockAgentClient points an AIClient at an httptest server returning a fixed
// risk score, so the handler tests exercise the real risk-review path without a
// live agent (mocking the transport is the documented test-only escape hatch).
func mockAgentClient(t *testing.T, score string) *aiclient.AIClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"risk_score": score, "reason": "mock " + score})
	}))
	t.Cleanup(srv.Close)
	return aiclient.NewAIClient(srv.URL, nil, "")
}

// TestCreateRequestRunsAIReviewAndReturnsVerdict proves the synchronous create
// flow scores the request server-side, returns the verdict, and leaves the
// request in ai_reviewed (medium → parked for manager approval).
func TestCreateRequestRunsAIReviewAndReturnsVerdict(t *testing.T) {
	deps := lifecycleTestDeps(t)
	deps.AI = mockAgentClient(t, "medium")
	r := NewRouter(deps)

	w := do(t, r, http.MethodPost, "/api/v1/access-requests", "tok-a", map[string]any{
		"target_user_id": "ext-user",
		"resource_ref":   "app:db",
		"role":           "reader",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d, body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Request  models.AccessRequest       `json:"request"`
		Risk     models.AccessRiskVerdict   `json:"risk"`
		Workflow lifecycle.WorkflowDecision `json:"workflow"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Request.State != lifecycle.StateAIReviewed {
		t.Fatalf("state = %q, want ai_reviewed", resp.Request.State)
	}
	if resp.Risk.Score != "medium" || resp.Risk.Recommendation != lifecycle.RecommendationNeedsReview {
		t.Fatalf("verdict = %+v, want medium/needs_review", resp.Risk)
	}
	if resp.Workflow.Approved {
		t.Fatal("medium request must not auto-approve")
	}
}

// TestCreateRequestSelfServiceDefaultsTarget proves an omitted target_user_id
// is a self-service elevation: the service defaults the target to the
// authenticated requester (derived from the token, never the body).
func TestCreateRequestSelfServiceDefaultsTarget(t *testing.T) {
	deps := lifecycleTestDeps(t)
	deps.AI = mockAgentClient(t, "low")
	r := NewRouter(deps)

	w := do(t, r, http.MethodPost, "/api/v1/access-requests", "tok-a", map[string]any{
		"resource_ref": "app:db",
		"role":         "reader",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d, body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Request models.AccessRequest `json:"request"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Request.RequesterID != "user-a" || resp.Request.TargetUserID != "user-a" {
		t.Fatalf("requester/target = %q/%q, want user-a/user-a",
			resp.Request.RequesterID, resp.Request.TargetUserID)
	}
}

// TestCreateRequestRequiresRole proves role is mandatory: the service contract
// requires it, so the handler rejects a roleless body with 400 rather than
// failing deeper in the create transaction.
func TestCreateRequestRequiresRole(t *testing.T) {
	deps := lifecycleTestDeps(t)
	r := NewRouter(deps)

	w := do(t, r, http.MethodPost, "/api/v1/access-requests", "tok-a", map[string]any{
		"resource_ref": "app:db",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("create without role = %d, want 400, body=%s", w.Code, w.Body.String())
	}
}

// TestHighRiskApprovalRequiresStepUp proves a high-risk request (forced via a
// sensitive resource tag) is rejected 403 without step-up MFA and approved with
// it — the AI recommendation never silently auto-approves a high-risk request.
func TestHighRiskApprovalRequiresStepUp(t *testing.T) {
	deps := lifecycleTestDeps(t)
	// No AI configured → fail-open medium; the sensitive tag forces high_risk.
	r := NewRouter(deps)

	w := do(t, r, http.MethodPost, "/api/v1/access-requests", "tok-a", map[string]any{
		"target_user_id": "ext-user",
		"resource_ref":   "app:db",
		"role":           "reader",
		"resource_tags":  []string{"sensitive"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d, body=%s", w.Code, w.Body.String())
	}
	var created struct {
		Request models.AccessRequest `json:"request"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	id := created.Request.ID.String()

	// Approve without MFA → 403 (fail-closed step-up gate).
	w = do(t, r, http.MethodPost, "/api/v1/access-requests/"+id+"/approve", "tok-a", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("approve without MFA = %d, want 403, body=%s", w.Code, w.Body.String())
	}

	// Approve with step-up MFA → 200.
	w = do(t, r, http.MethodPost, "/api/v1/access-requests/"+id+"/approve", "tok-a-mfa", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("approve with MFA = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var approved struct {
		Request models.AccessRequest `json:"request"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &approved); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if approved.Request.State != lifecycle.StateApproved {
		t.Fatalf("state = %q, want approved", approved.Request.State)
	}
}

// TestMediumRiskApprovalNoStepUp proves a non-high-risk request approves without
// step-up MFA (the gate only bites high_risk).
func TestMediumRiskApprovalNoStepUp(t *testing.T) {
	deps := lifecycleTestDeps(t)
	deps.AI = mockAgentClient(t, "medium")
	r := NewRouter(deps)

	w := do(t, r, http.MethodPost, "/api/v1/access-requests", "tok-a", map[string]any{
		"target_user_id": "ext-user",
		"resource_ref":   "app:db",
		"role":           "reader",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d, body=%s", w.Code, w.Body.String())
	}
	var created struct {
		Request models.AccessRequest `json:"request"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)

	w = do(t, r, http.MethodPost, "/api/v1/access-requests/"+created.Request.ID.String()+"/approve", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("medium approve without MFA = %d, want 200, body=%s", w.Code, w.Body.String())
	}
}
