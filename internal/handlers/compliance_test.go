package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
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
	// Every compliance route is RBAC-enforced (middleware.RequirePermission
	// resolves the caller's workspace role, not a raw token scope), so wire the
	// RBAC tier and seed memberships spanning the role gradient:
	//   - user-a (operator): a member, but the RBAC model excludes operators
	//     from compliance entirely — no compliance.read/manage/export.
	//   - user-auditor (auditor): read-only compliance — compliance.read +
	//     compliance.export, but NOT compliance.manage (cannot drive campaigns).
	//   - user-admin (admin): full compliance surface incl. compliance.manage.
	//   - user-b (auditor in tenant-b): holds compliance.read in its own
	//     workspace so cross-tenant reads exercise tenant isolation (404), not
	//     the permission gate (403).
	wsA := workspaceIDByTenant(t, db, "tenant-a")
	wsB := workspaceIDByTenant(t, db, "tenant-b")
	rbac := authz.NewRBACService(db, 0)
	seedMember(t, rbac, wsA, "user-a", authz.RoleOperator)
	seedMember(t, rbac, wsA, "user-auditor", authz.RoleAuditor)
	seedMember(t, rbac, wsA, "user-admin", authz.RoleAdmin)
	seedMember(t, rbac, wsB, "user-b", authz.RoleAuditor)

	ready := &atomic.Bool{}
	ready.Store(true)
	return Deps{
		Validator: mapValidator{byToken: map[string]*iamcore.Claims{
			// operator member, no MFA: excluded from compliance entirely.
			"tok-a": {Subject: "user-a", TenantID: "tenant-a"},
			// auditor in tenant-b: holds compliance.read in its own workspace.
			"tok-b": {Subject: "user-b", TenantID: "tenant-b"},
			// holds compliance.export (auditor) but NO MFA -> blocked by RequireMFA.
			"tok-auditor": {Subject: "user-auditor", TenantID: "tenant-a"},
			// MFA but role lacks compliance.export -> blocked by RequirePermission.
			"tok-a-mfa": {Subject: "user-a", TenantID: "tenant-a", MFASatisfied: true},
			// auditor (compliance.export) + MFA -> allowed.
			"tok-a-export": {Subject: "user-auditor", TenantID: "tenant-a", MFASatisfied: true},
			// admin: holds compliance.manage -> may drive campaigns.
			"tok-admin": {Subject: "user-admin", TenantID: "tenant-a"},
		}},
		DB:                 db,
		Encryptor:          crypto.PassthroughEncryptor{},
		ConnectorEncryptor: access.PassthroughEncryptor{},
		Ready:              ready,
		RBAC:               rbac,
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

	// tenant-a starts a campaign (admin holds compliance.manage).
	w := do(t, r, http.MethodPost, "/api/v1/compliance/campaigns", "tok-admin", map[string]any{"name": "Q1"})
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
	// (user-b is an auditor in tenant-b, so it clears the compliance.read gate;
	// the 404 therefore proves tenant isolation, not a missing permission.)
	if w := do(t, r, http.MethodGet, "/api/v1/compliance/campaigns/"+id, "tok-b", nil); w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant read: got %d, want 404", w.Code)
	}
}

// TestComplianceRoutesRBACGate proves every compliance route fails closed
// against the RBAC model: an operator (excluded from compliance) is 403'd on
// the read surface, and the read-only auditor — who can read and export — is
// still 403'd on the campaign write surface, which requires compliance.manage.
func TestComplianceRoutesRBACGate(t *testing.T) {
	r := NewRouter(complianceTestDeps(t))

	// --- Read surface: operator excluded, auditor admitted. ---------------
	readRoutes := []string{
		"/api/v1/compliance/evidence",
		"/api/v1/compliance/coverage",
		"/api/v1/compliance/chain/verify",
		"/api/v1/compliance/campaigns",
	}
	for _, route := range readRoutes {
		// operator lacks compliance.read -> 403.
		if w := do(t, r, http.MethodGet, route, "tok-a", nil); w.Code != http.StatusForbidden {
			t.Fatalf("operator GET %s: got %d body=%s, want 403", route, w.Code, w.Body.String())
		}
		// auditor holds compliance.read -> not 403 (200, or 4xx other than 403).
		if w := do(t, r, http.MethodGet, route, "tok-auditor", nil); w.Code == http.StatusForbidden {
			t.Fatalf("auditor GET %s: got 403, want allowed by read gate", route)
		}
	}

	// --- Write surface: operator AND read-only auditor both excluded. -----
	// startCampaign / overdue-enforce need no path params, so they reach the
	// permission gate directly.
	writeRoutes := []string{
		"/api/v1/compliance/campaigns",
		"/api/v1/compliance/campaigns/overdue-enforce",
	}
	for _, route := range writeRoutes {
		if w := do(t, r, http.MethodPost, route, "tok-a", map[string]any{}); w.Code != http.StatusForbidden {
			t.Fatalf("operator POST %s: got %d body=%s, want 403", route, w.Code, w.Body.String())
		}
		// auditor has compliance.read+export but NOT compliance.manage -> 403.
		if w := do(t, r, http.MethodPost, route, "tok-auditor", map[string]any{}); w.Code != http.StatusForbidden {
			t.Fatalf("auditor POST %s: got %d body=%s, want 403 (lacks compliance.manage)", route, w.Code, w.Body.String())
		}
	}

	// admin holds compliance.manage -> campaign start is admitted past the gate.
	if w := do(t, r, http.MethodPost, "/api/v1/compliance/campaigns", "tok-admin", map[string]any{"name": "Q2"}); w.Code == http.StatusForbidden {
		t.Fatalf("admin start campaign: got 403, want admitted by manage gate")
	}
}

// TestVerifyChainEndpointFullVsIncremental proves the verify route serves a
// full verification with no params and switches to the incremental consistency
// verify when handed an anchor (from_seq + from_hash), and that a half-anchor
// is a 400.
func TestVerifyChainEndpointFullVsIncremental(t *testing.T) {
	deps := complianceTestDeps(t)
	wsA := workspaceIDByTenant(t, deps.DB, "tenant-a")
	for i := 0; i < 4; i++ {
		if err := lifecycle.AppendAudit(t.Context(), deps.DB, time.Now(), lifecycle.AuditInput{
			WorkspaceID: wsA, Actor: "auditor", Action: "policy.promoted", TargetRef: "p",
		}); err != nil {
			t.Fatalf("seed audit row: %v", err)
		}
	}
	r := NewRouter(deps)

	// The head anchor a client would persist after a full verify. (RBAC seeding
	// also appends audit rows, so the head seq is not just our 4 — read it.)
	var head models.AuditEvent
	if err := deps.DB.Where("workspace_id = ?", wsA).Order("chain_seq desc").Limit(1).
		Take(&head).Error; err != nil {
		t.Fatalf("read head: %v", err)
	}

	// Full verify (no params): auditor holds compliance.read.
	w := do(t, r, http.MethodGet, "/api/v1/compliance/chain/verify", "tok-auditor", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("full verify: got %d body=%s", w.Code, w.Body.String())
	}
	var full struct {
		OK     bool `json:"ok"`
		Length int  `json:"length"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &full); err != nil {
		t.Fatalf("unmarshal full: %v", err)
	}
	if !full.OK || int64(full.Length) != head.ChainSeq {
		t.Fatalf("full verify body: %+v (head seq %d)", full, head.ChainSeq)
	}

	// Incremental verify with the head anchor and no new rows -> consistent, 0 verified.
	url := fmt.Sprintf("/api/v1/compliance/chain/verify?from_seq=%d&from_hash=%s", head.ChainSeq, head.ChainHash)
	w = do(t, r, http.MethodGet, url, "tok-auditor", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("incremental verify: got %d body=%s", w.Code, w.Body.String())
	}
	var cons struct {
		OK       bool   `json:"ok"`
		Status   string `json:"status"`
		Verified int    `json:"verified"`
		HeadSeq  int64  `json:"head_seq"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &cons); err != nil {
		t.Fatalf("unmarshal cons: %v", err)
	}
	if !cons.OK || cons.Status != "consistent" || cons.Verified != 0 || cons.HeadSeq != head.ChainSeq {
		t.Fatalf("incremental body: %+v", cons)
	}

	// Half-anchor (from_seq without from_hash) -> 400.
	w = do(t, r, http.MethodGet, "/api/v1/compliance/chain/verify?from_seq=2", "tok-auditor", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("half-anchor: got %d body=%s, want 400", w.Code, w.Body.String())
	}
}
