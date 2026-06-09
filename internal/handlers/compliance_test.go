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
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
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
	// The export gate is RBAC-enforced (middleware.RequirePermission resolves
	// the caller's workspace role, not a raw token scope), so wire the RBAC
	// tier and seed memberships. user-a is a plain operator (a member, so the
	// un-permissioned campaign routes admit them, but WITHOUT compliance.export
	// so the export permission gate denies them); user-auditor carries the
	// compliance-scoped read+export permission.
	wsA := workspaceIDByTenant(t, db, "tenant-a")
	wsB := workspaceIDByTenant(t, db, "tenant-b")
	rbac := authz.NewRBACService(db, 0)
	seedMember(t, rbac, wsA, "user-a", authz.RoleOperator)
	seedMember(t, rbac, wsA, "user-auditor", authz.RoleAuditor)
	seedMember(t, rbac, wsB, "user-b", authz.RoleOperator)

	ready := &atomic.Bool{}
	ready.Store(true)
	return Deps{
		Validator: mapValidator{byToken: map[string]*iamcore.Claims{
			// operator member, no MFA: denied export (role lacks compliance.export).
			"tok-a": {Subject: "user-a", TenantID: "tenant-a"},
			"tok-b": {Subject: "user-b", TenantID: "tenant-b"},
			// holds compliance.export (auditor) but NO MFA -> blocked by RequireMFA.
			"tok-auditor": {Subject: "user-auditor", TenantID: "tenant-a"},
			// MFA but role lacks compliance.export -> blocked by RequirePermission.
			"tok-a-mfa": {Subject: "user-a", TenantID: "tenant-a", MFASatisfied: true},
			// auditor (compliance.export) + MFA -> allowed.
			"tok-a-export": {Subject: "user-auditor", TenantID: "tenant-a", MFASatisfied: true},
		}},
		DB:        db,
		Encryptor: crypto.PassthroughEncryptor{},
		Ready:     ready,
		RBAC:      rbac,
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
	// Has compliance.export but no MFA -> 403 from RequireMFA.
	if w := do(t, r, http.MethodPost, "/api/v1/compliance/export", "tok-auditor", body); w.Code != http.StatusForbidden {
		t.Fatalf("perm no mfa: got %d, want 403", w.Code)
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
