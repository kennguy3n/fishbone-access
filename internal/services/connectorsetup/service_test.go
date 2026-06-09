package connectorsetup

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/aiclient"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"

	// Populate the registry so CapabilityDescriptorFor resolves real providers.
	_ "github.com/kennguy3n/fishbone-access/internal/services/access/connectors/all"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("auto-migrate: %v", err)
	}
	return db
}

func seedWorkspace(t *testing.T, db *gorm.DB) uuid.UUID {
	t.Helper()
	ws := &models.Workspace{Name: "acme", IAMCoreTenantID: "acme", Plan: "base"}
	if err := db.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	return ws.ID
}

// countAudit returns the number of audit events recorded for the workspace with
// the setup-suggested action.
func countSetupAudit(t *testing.T, db *gorm.DB, ws uuid.UUID) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND action = ?", ws, auditActionSetupSuggested).
		Count(&n).Error; err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

// TestSuggestFailOpenWhenAgentUnconfigured asserts the assistant is fail-OPEN:
// with no agent configured it returns a degraded manual plan (never an error),
// and the degraded suggestion + its audit entry are still persisted.
func TestSuggestFailOpenWhenAgentUnconfigured(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db)
	svc := NewService(db, aiclient.NewAIClient("", nil, "")) // unconfigured

	res, err := svc.Suggest(context.Background(), SuggestInput{
		WorkspaceID: ws,
		Actor:       "admin@acme",
		Provider:    "okta",
		AdminIntent: "sync employees",
	})
	if err != nil {
		t.Fatalf("Suggest returned error on fail-open path: %v", err)
	}
	if !res.Plan.Degraded {
		t.Error("expected degraded plan when agent unconfigured")
	}
	if len(res.Plan.Steps) == 0 {
		t.Error("degraded plan must still carry manual steps")
	}

	var row models.ConnectorSetupSuggestion
	if err := db.First(&row, "id = ?", res.SuggestionID).Error; err != nil {
		t.Fatalf("suggestion not persisted: %v", err)
	}
	if !row.Degraded || row.Provider != "okta" || row.Actor != "admin@acme" {
		t.Errorf("persisted row mismatch: %+v", row)
	}
	if row.WorkspaceID != ws {
		t.Errorf("suggestion workspace = %v, want %v", row.WorkspaceID, ws)
	}
	if n := countSetupAudit(t, db, ws); n != 1 {
		t.Errorf("expected 1 audit event, got %d", n)
	}
}

// TestSuggestTransportErrorFailsOpen asserts a 5xx / transport failure from the
// agent also degrades gracefully rather than erroring.
func TestSuggestTransportErrorFailsOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	db := newTestDB(t)
	ws := seedWorkspace(t, db)
	svc := NewService(db, aiclient.NewAIClient(srv.URL, nil, ""))

	res, err := svc.Suggest(context.Background(), SuggestInput{
		WorkspaceID: ws,
		Actor:       "admin@acme",
		Provider:    "microsoft",
	})
	if err != nil {
		t.Fatalf("Suggest errored on agent 500 instead of failing open: %v", err)
	}
	if !res.Plan.Degraded {
		t.Error("expected degraded plan on agent 500")
	}
}

// TestSuggestSuccessPersistsPlan asserts the happy path: the agent's structured
// plan is returned verbatim, not degraded, and persisted with provenance.
func TestSuggestSuccessPersistsPlan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"explanation": "Register an Entra app and grant Graph read scopes.",
			"reason":      "strategy=microsoft",
			"strategy":    "microsoft",
			"model_used":  true,
			"steps": []map[string]interface{}{
				{
					"step":              1,
					"title":             "Register the application",
					"description":       "Create an app registration.",
					"required_scopes":   []string{"User.Read.All"},
					"estimated_minutes": 10,
				},
			},
		})
	}))
	defer srv.Close()

	db := newTestDB(t)
	ws := seedWorkspace(t, db)
	svc := NewService(db, aiclient.NewAIClient(srv.URL, nil, ""))

	res, err := svc.Suggest(context.Background(), SuggestInput{
		WorkspaceID: ws,
		Actor:       "admin@acme",
		Provider:    "microsoft",
		AdminIntent: "onboard staff",
	})
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if res.Plan.Degraded {
		t.Error("plan should not be degraded on a successful agent response")
	}
	if res.Plan.Strategy != "microsoft" || !res.Plan.ModelUsed {
		t.Errorf("unexpected plan provenance: %+v", res.Plan)
	}
	if len(res.Plan.Steps) != 1 || res.Plan.Steps[0].Title != "Register the application" {
		t.Errorf("plan steps not decoded from agent: %+v", res.Plan.Steps)
	}

	var row models.ConnectorSetupSuggestion
	if err := db.First(&row, "id = ?", res.SuggestionID).Error; err != nil {
		t.Fatalf("suggestion not persisted: %v", err)
	}
	if row.Degraded || !row.ModelUsed || row.Strategy != "microsoft" {
		t.Errorf("persisted provenance mismatch: %+v", row)
	}
	// The persisted plan JSON round-trips to the same steps.
	var persisted aiclient.ConnectorSetupPlan
	if err := json.Unmarshal(row.Plan, &persisted); err != nil {
		t.Fatalf("persisted plan not valid JSON: %v", err)
	}
	if len(persisted.Steps) != 1 {
		t.Errorf("persisted plan steps = %d, want 1", len(persisted.Steps))
	}
}

// TestSuggestUnknownProviderRejected asserts an unregistered provider is a
// validation error (not a degraded plan) so the wizard can't be pointed at a
// connector the binary doesn't ship.
func TestSuggestUnknownProviderRejected(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db)
	svc := NewService(db, aiclient.NewAIClient("", nil, ""))

	_, err := svc.Suggest(context.Background(), SuggestInput{
		WorkspaceID: ws,
		Provider:    "totally-not-a-connector",
	})
	if err == nil {
		t.Fatal("expected validation error for unknown provider")
	}
}

// TestSuggestRequiresWorkspace asserts the assistant is never invoked unscoped.
func TestSuggestRequiresWorkspace(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, aiclient.NewAIClient("", nil, ""))
	if _, err := svc.Suggest(context.Background(), SuggestInput{Provider: "okta"}); err == nil {
		t.Fatal("expected validation error for missing workspace")
	}
}
