package handlers

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

// complianceTestDeps builds a router with tokens that exercise the export
// gate's two independent fail-closed checks (permission scope + step-up MFA)
// plus a plain read token and a second tenant for isolation.
func complianceTestDeps(t *testing.T) Deps {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, ten := range []string{"tenant-a", "tenant-b"} {
		if err := db.Create(&models.Workspace{Name: ten, IAMCoreTenantID: ten}).Error; err != nil {
			t.Fatalf("seed workspace %s: %v", ten, err)
		}
	}
	ready := &atomic.Bool{}
	ready.Store(true)
	return Deps{
		Validator: mapValidator{byToken: map[string]*iamcore.Claims{
			// read-only token: no export scope, no MFA.
			"tok-a": {Subject: "user-a", TenantID: "tenant-a"},
			"tok-b": {Subject: "user-b", TenantID: "tenant-b"},
			// export scope but NO MFA -> must be blocked by RequireMFA.
			"tok-a-scope": {Subject: "user-a", TenantID: "tenant-a", Scopes: []string{"compliance.export"}},
			// MFA but NO export scope -> must be blocked by RequirePermission.
			"tok-a-mfa": {Subject: "user-a", TenantID: "tenant-a", MFASatisfied: true},
			// both -> allowed.
			"tok-a-export": {Subject: "user-a", TenantID: "tenant-a", Scopes: []string{"compliance.export"}, MFASatisfied: true},
		}},
		DB:        db,
		Encryptor: crypto.PassthroughEncryptor{},
		Ready:     ready,
	}
}

func TestExportPackAuthzGate(t *testing.T) {
	r := NewRouter(complianceTestDeps(t))
	body := map[string]any{"framework": "SOC 2"}

	// No token at all -> 401 from Auth.
	if w := do(t, r, http.MethodPost, "/api/v1/compliance/export", "", body); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", w.Code)
	}
	// Authenticated, no scope, no MFA -> 403 (permission checked first).
	if w := do(t, r, http.MethodPost, "/api/v1/compliance/export", "tok-a", body); w.Code != http.StatusForbidden {
		t.Fatalf("no scope: got %d body=%s, want 403", w.Code, w.Body.String())
	}
	// Scope but no MFA -> 403 from RequireMFA.
	if w := do(t, r, http.MethodPost, "/api/v1/compliance/export", "tok-a-scope", body); w.Code != http.StatusForbidden {
		t.Fatalf("scope no mfa: got %d, want 403", w.Code)
	}
	// MFA but no scope -> 403 from RequirePermission.
	if w := do(t, r, http.MethodPost, "/api/v1/compliance/export", "tok-a-mfa", body); w.Code != http.StatusForbidden {
		t.Fatalf("mfa no scope: got %d, want 403", w.Code)
	}
	// Both gates satisfied -> 200 and a zip with the content digest header.
	w := do(t, r, http.MethodPost, "/api/v1/compliance/export", "tok-a-export", body)
	if w.Code != http.StatusOK {
		t.Fatalf("export: got %d body=%s, want 200", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Evidence-Pack-Digest") == "" {
		t.Fatalf("expected content-digest header on export")
	}
	if ct := w.Header().Get("Content-Disposition"); ct == "" {
		t.Fatalf("expected attachment disposition")
	}
}

func TestCampaignCrossTenantIsolationHandler(t *testing.T) {
	r := NewRouter(complianceTestDeps(t))

	// tenant-a starts a campaign.
	w := do(t, r, http.MethodPost, "/api/v1/compliance/campaigns", "tok-a", map[string]any{"name": "Q1"})
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("start campaign: got %d body=%s", w.Code, w.Body.String())
	}
	var created struct {
		Campaign struct {
			ID string `json:"id"`
		} `json:"campaign"`
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal campaign: %v", err)
	}
	id := created.Campaign.ID
	if id == "" {
		id = created.ID
	}
	if id == "" {
		t.Fatalf("no campaign id in response: %s", w.Body.String())
	}

	// tenant-b must NOT be able to read tenant-a's campaign -> 404.
	if w := do(t, r, http.MethodGet, "/api/v1/compliance/campaigns/"+id, "tok-b", nil); w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant read: got %d, want 404", w.Code)
	}
}
