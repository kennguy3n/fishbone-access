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
	// user-a: operator (PermReviewRead+Respond, but NO compliance.read /
	// compliance.export / review.start); user-aud: auditor (compliance.read +
	// compliance.export, review.read, but NO review.start); user-adm: admin
	// (holds the campaign-management review.start/complete/admin perms).
	seedMember("tenant-a", "user-a", authz.RoleOperator)
	seedMember("tenant-a", "user-aud", authz.RoleAuditor)
	seedMember("tenant-a", "user-adm", authz.RoleAdmin)
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
			// admin -> holds review.start/complete/admin for campaign management.
			"tok-adm": {Subject: "user-adm", TenantID: "tenant-a"},
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

// TestRbacMeReflectsRole asserts the self-scoped /rbac/me endpoint the UI
// mirrors returns the caller's resolved role + permission set: an auditor holds
// compliance.export, an operator does not. This is the source the evidence-pack
// export button reads to decide whether to enable itself, so a regression here
// would silently mis-gate the affordance.
func TestRbacMeReflectsRole(t *testing.T) {
	r := NewRouter(complianceTestDeps(t))

	read := func(token string) (string, map[string]bool) {
		w := do(t, r, http.MethodGet, "/api/v1/rbac/me", token, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("rbac/me %s: got %d body=%s, want 200", token, w.Code, w.Body.String())
		}
		var out struct {
			Role        string   `json:"role"`
			Permissions []string `json:"permissions"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("unmarshal rbac/me: %v", err)
		}
		set := map[string]bool{}
		for _, p := range out.Permissions {
			set[p] = true
		}
		return out.Role, set
	}

	if role, perms := read("tok-export"); role != "auditor" || !perms["compliance.export"] {
		t.Fatalf("auditor: role=%q hasExport=%v, want auditor/true", role, perms["compliance.export"])
	}
	if role, perms := read("tok-a"); role != "operator" || perms["compliance.export"] {
		t.Fatalf("operator: role=%q hasExport=%v, want operator/false", role, perms["compliance.export"])
	}
}

func TestCampaignCrossTenantIsolationHandler(t *testing.T) {
	r := NewRouter(complianceTestDeps(t))

	// tenant-a starts a campaign (admin holds review.start).
	w := do(t, r, http.MethodPost, "/api/v1/compliance/campaigns", "tok-adm", map[string]any{"name": "Q1"})
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

// TestComplianceReadAuthzGate locks in the read-side permission model:
//
//   - The evidence-dashboard surface (evidence stream, coverage, chain verify)
//     requires compliance.read, which the auditor holds but the operator does
//     NOT — so an operator is 403'd off the tamper-evident chain while an
//     auditor reads it (200).
//   - Certification-campaign reads mirror the /access-reviews gating
//     (PermReviewRead), which the operator DOES hold, so a campaign reviewer
//     who is an operator can still reach their worklist (the campaign list is
//     readable; 200).
//
// This is the fail-closed gate that distinguishes the compliance/auditor view
// from the reviewer worklist; a regression that drops either gate would expose
// the chain to plain members or lock reviewers out of their queue.
func TestComplianceReadAuthzGate(t *testing.T) {
	r := NewRouter(complianceTestDeps(t))

	// Evidence dashboard reads require compliance.read. (coverage needs a
	// framework query; the others take none.)
	for _, path := range []string{
		"/api/v1/compliance/evidence",
		"/api/v1/compliance/coverage?framework=SOC%202",
		"/api/v1/compliance/chain/verify",
	} {
		// operator lacks compliance.read -> 403.
		if w := do(t, r, http.MethodGet, path, "tok-a", nil); w.Code != http.StatusForbidden {
			t.Fatalf("operator %s: got %d body=%s, want 403", path, w.Code, w.Body.String())
		}
		// auditor holds compliance.read -> 200.
		if w := do(t, r, http.MethodGet, path, "tok-export", nil); w.Code != http.StatusOK {
			t.Fatalf("auditor %s: got %d body=%s, want 200", path, w.Code, w.Body.String())
		}
	}

	// Campaign list mirrors review.read, which the operator holds -> 200
	// (a reviewer who is an operator must reach their worklist).
	if w := do(t, r, http.MethodGet, "/api/v1/compliance/campaigns", "tok-a", nil); w.Code != http.StatusOK {
		t.Fatalf("operator campaign list: got %d body=%s, want 200", w.Code, w.Body.String())
	}
	// Starting a campaign requires review.start, which the operator lacks -> 403.
	if w := do(t, r, http.MethodPost, "/api/v1/compliance/campaigns", "tok-a", map[string]any{"name": "X"}); w.Code != http.StatusForbidden {
		t.Fatalf("operator campaign start: got %d body=%s, want 403", w.Code, w.Body.String())
	}
}
