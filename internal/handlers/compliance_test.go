package handlers

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
)

// complianceTestDeps builds a router with the RBAC tier wired and tokens that
// exercise the export gate's two independent fail-closed checks (the
// compliance.export permission, resolved from workspace role membership, and
// step-up MFA). Because AuthzMiddleware is fail-closed, every caller must be a
// seeded workspace member; the member's role decides whether it holds
// compliance.export (auditor does, operator does not), while MFA is carried on
// the token. A second tenant is seeded for the isolation test.
func complianceTestDeps(t *testing.T) Deps {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	wsByTenant := map[string]uuid.UUID{}
	for _, ten := range []string{"tenant-a", "tenant-b"} {
		ws := models.Workspace{Name: ten, IAMCoreTenantID: ten}
		if err := db.Create(&ws).Error; err != nil {
			t.Fatalf("seed workspace %s: %v", ten, err)
		}
		wsByTenant[ten] = ws.ID
	}
	seedMember := func(tenant, user string, role authz.WorkspaceRole) {
		if err := db.Create(&models.WorkspaceMember{
			WorkspaceID: wsByTenant[tenant], UserID: user, Role: string(role),
		}).Error; err != nil {
			t.Fatalf("seed member %s/%s: %v", tenant, user, err)
		}
	}
	// user-a: operator (NO compliance.export); user-aud: auditor (HAS it).
	seedMember("tenant-a", "user-a", authz.RoleOperator)
	seedMember("tenant-a", "user-aud", authz.RoleAuditor)
	seedMember("tenant-b", "user-b", authz.RoleOperator)

	ready := &atomic.Bool{}
	ready.Store(true)
	return Deps{
		Validator: mapValidator{byToken: map[string]*iamcore.Claims{
			// operator, no MFA — lacks compliance.export.
			"tok-a": {Subject: "user-a", TenantID: "tenant-a"},
			"tok-b": {Subject: "user-b", TenantID: "tenant-b"},
			// operator WITH MFA -> still blocked by RequirePermission (no perm).
			"tok-a-mfa": {Subject: "user-a", TenantID: "tenant-a", MFASatisfied: true},
			// auditor (has compliance.export) but NO MFA -> blocked by RequireMFA.
			"tok-perm": {Subject: "user-aud", TenantID: "tenant-a"},
			// auditor WITH MFA -> both gates satisfied.
			"tok-export": {Subject: "user-aud", TenantID: "tenant-a", MFASatisfied: true},
		}},
		DB:        db,
		Encryptor: crypto.PassthroughEncryptor{},
		Ready:     ready,
		RBAC:      authz.NewRBACService(db, 0),
	}
}

func TestExportPackAuthzGate(t *testing.T) {
	r := NewRouter(complianceTestDeps(t))
	body := map[string]any{"framework": "SOC 2"}

	// No token at all -> 401 from Auth.
	if w := do(t, r, http.MethodPost, "/api/v1/compliance/export", "", body); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", w.Code)
	}
	// Authenticated, no permission, no MFA -> 403 (permission checked first).
	if w := do(t, r, http.MethodPost, "/api/v1/compliance/export", "tok-a", body); w.Code != http.StatusForbidden {
		t.Fatalf("no perm: got %d body=%s, want 403", w.Code, w.Body.String())
	}
	// Permission but no MFA -> 403 from RequireMFA.
	if w := do(t, r, http.MethodPost, "/api/v1/compliance/export", "tok-perm", body); w.Code != http.StatusForbidden {
		t.Fatalf("perm no mfa: got %d, want 403", w.Code)
	}
	// MFA but no permission -> 403 from RequirePermission.
	if w := do(t, r, http.MethodPost, "/api/v1/compliance/export", "tok-a-mfa", body); w.Code != http.StatusForbidden {
		t.Fatalf("mfa no perm: got %d, want 403", w.Code)
	}
	// Both gates satisfied -> 200 and a zip with the content digest header.
	w := do(t, r, http.MethodPost, "/api/v1/compliance/export", "tok-export", body)
	if w.Code != http.StatusOK {
		t.Fatalf("export: got %d body=%s, want 200", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Evidence-Pack-Digest") == "" {
		t.Fatalf("expected content-digest header on export")
	}
	if ct := w.Header().Get("Content-Disposition"); ct == "" {
		t.Fatalf("expected attachment disposition")
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("expected Content-Type application/zip, got %q", ct)
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
