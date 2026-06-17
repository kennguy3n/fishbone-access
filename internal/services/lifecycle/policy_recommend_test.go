package lifecycle

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/pkg/aiclient"
)

// A configured recommender returns the agent's explanation string and forwards
// the resource/roles/context the operator supplied.
func TestPolicyRecommendReturnsExplanation(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")

	var gotPayload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotPayload, _ = body["payload"].(map[string]any)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"explanation": "grant read-only; scope to prod-db role"})
	}))
	t.Cleanup(srv.Close)

	svc := NewPolicyService(db)
	svc.SetRecommender(aiclient.NewAIClient(srv.URL, nil, ""))

	rec := svc.Recommend(context.Background(), ws, PolicyRecommendationInput{
		Resource: "app:prod-db",
		Roles:    []string{"dba", "oncall"},
		Context:  "quarterly access review",
	})
	if rec != "grant read-only; scope to prod-db role" {
		t.Fatalf("recommendation = %q; want the agent explanation", rec)
	}
	if gotPayload["resource"] != "app:prod-db" {
		t.Fatalf("resource forwarded = %v; want app:prod-db", gotPayload["resource"])
	}
	if gotPayload["workspace_id"] != ws.String() {
		t.Fatalf("workspace_id forwarded = %v; want %s", gotPayload["workspace_id"], ws.String())
	}
	roles, ok := gotPayload["roles"].([]any)
	if !ok || len(roles) != 2 {
		t.Fatalf("roles forwarded = %v; want 2", gotPayload["roles"])
	}
}

// With no recommender configured, Recommend is a fail-open no-op: empty string,
// no panic, no agent dependency.
func TestPolicyRecommendUnconfiguredReturnsEmpty(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")

	svc := NewPolicyService(db) // no SetRecommender
	if rec := svc.Recommend(context.Background(), ws, PolicyRecommendationInput{Resource: "x"}); rec != "" {
		t.Fatalf("want empty recommendation when unconfigured, got %q", rec)
	}

	// An explicitly-unconfigured client (empty baseURL) is also a no-op.
	svc.SetRecommender(aiclient.NewAIClient("", nil, ""))
	if rec := svc.Recommend(context.Background(), ws, PolicyRecommendationInput{Resource: "x"}); rec != "" {
		t.Fatalf("want empty recommendation for unconfigured client, got %q", rec)
	}
}

// An agent outage degrades to an empty advisory rather than an error.
func TestPolicyRecommendAgentOutageEmpty(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	svc := NewPolicyService(db)
	svc.SetRecommender(aiclient.NewAIClient(srv.URL, nil, ""))
	if rec := svc.Recommend(context.Background(), ws, PolicyRecommendationInput{Resource: "x"}); rec != "" {
		t.Fatalf("want empty recommendation on agent outage, got %q", rec)
	}
}
