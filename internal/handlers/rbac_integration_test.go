package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/middleware"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
	"github.com/kennguy3n/fishbone-access/internal/services/mfa"
)

func ctxBg() context.Context { return context.Background() }

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

// doWithHeaders is do() plus arbitrary request headers (used to attach the
// step-up MFA assertion header).
func doWithHeaders(t *testing.T, r http.Handler, method, path, token string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// rbacStepUpSecret is a fixed base32 TOTP secret used to mint step-up codes in
// these tests. Test fixture only — not a credential.
const rbacStepUpSecret = "JBSWY3DPEHPK3PXP"

// rbacTestEnv wires a router with RBAC + step-up MFA fully installed, two
// tenants, and a representative membership matrix, so the tests exercise the
// real Auth → ResolveTenant → RequireTenant → AuthzMiddleware → RequirePermission
// chain end to end (the lifecycle harness deliberately leaves RBAC nil).
type rbacTestEnv struct {
	router http.Handler
	db     *gorm.DB
	wsA    uuid.UUID
	wsB    uuid.UUID
}

func newRBACTestEnv(t *testing.T) rbacTestEnv {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	for _, ten := range []string{"tenant-a", "tenant-b"} {
		if err := db.Create(&models.Workspace{Name: ten, IAMCoreTenantID: ten}).Error; err != nil {
			t.Fatalf("seed workspace %s: %v", ten, err)
		}
	}
	wsA := workspaceIDByTenant(t, db, "tenant-a")
	wsB := workspaceIDByTenant(t, db, "tenant-b")

	rbac := authz.NewRBACService(db, 0)
	seedMember(t, rbac, wsA, "user-owner", authz.RoleOwner)
	seedMember(t, rbac, wsA, "user-admin", authz.RoleAdmin)
	seedMember(t, rbac, wsA, "user-auditor", authz.RoleAuditor)
	seedMember(t, rbac, wsB, "user-b-owner", authz.RoleOwner)
	// user-stranger carries a valid tenant-a token but has NO membership row.

	totpVerifier, err := mfa.NewTOTPMFAVerifier(db)
	if err != nil {
		t.Fatalf("totp verifier: %v", err)
	}
	// Enrolled step-up secret for the tenant-a owner.
	if err := db.Create(&models.UserTOTPSecret{
		WorkspaceID: wsA, UserID: "user-owner", Secret: rbacStepUpSecret, Verified: true,
	}).Error; err != nil {
		t.Fatalf("seed totp secret: %v", err)
	}

	ready := &atomic.Bool{}
	ready.Store(true)
	deps := Deps{
		Validator: mapValidator{byToken: map[string]*iamcore.Claims{
			"tok-owner":    {Subject: "user-owner", TenantID: "tenant-a", MFASatisfied: true},
			"tok-admin":    {Subject: "user-admin", TenantID: "tenant-a", MFASatisfied: true},
			"tok-auditor":  {Subject: "user-auditor", TenantID: "tenant-a"},
			"tok-stranger": {Subject: "user-stranger", TenantID: "tenant-a"},
			"tok-b-owner":  {Subject: "user-b-owner", TenantID: "tenant-b"},
		}},
		DB:        db,
		Encryptor: crypto.PassthroughEncryptor{},
		Ready:     ready,
		RBAC:      rbac,
		// Composite verifier with only the TOTP leg wired; a 6-digit code routes
		// to it. Exercises the production step-up path.
		StepUpMFA: mfa.NewCompositeMFAVerifier(nil, totpVerifier),
	}
	return rbacTestEnv{router: NewRouter(deps), db: db, wsA: wsA, wsB: wsB}
}

func workspaceIDByTenant(t *testing.T, db *gorm.DB, tenant string) uuid.UUID {
	t.Helper()
	var ws models.Workspace
	if err := db.Where("iam_core_tenant_id = ?", tenant).First(&ws).Error; err != nil {
		t.Fatalf("lookup workspace %s: %v", tenant, err)
	}
	return ws.ID
}

func seedMember(t *testing.T, rbac *authz.RBACService, ws uuid.UUID, userID string, role authz.WorkspaceRole) {
	t.Helper()
	if err := rbac.UpsertMember(ctxBg(), ws, userID, role, "system-test"); err != nil {
		t.Fatalf("seed member %s/%s: %v", ws, userID, err)
	}
}

// TestRBACNonMemberFailsClosed proves a holder of a valid tenant token who has
// no membership row is denied (403) at AuthzMiddleware — the fail-closed core.
func TestRBACNonMemberFailsClosed(t *testing.T) {
	env := newRBACTestEnv(t)
	w := do(t, env.router, http.MethodGet, "/api/v1/policies", "tok-stranger", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-member GET = %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// TestRBACAuditorReadAllowedWriteDenied proves a fine-grained permission split:
// the auditor holds policy.read but not policy.write.
func TestRBACAuditorReadAllowedWriteDenied(t *testing.T) {
	env := newRBACTestEnv(t)
	if w := do(t, env.router, http.MethodGet, "/api/v1/policies", "tok-auditor", nil); w.Code != http.StatusOK {
		t.Fatalf("auditor GET policies = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	body := map[string]any{"name": "p", "definition": map[string]any{}}
	if w := do(t, env.router, http.MethodPost, "/api/v1/policies", "tok-auditor", body); w.Code != http.StatusForbidden {
		t.Fatalf("auditor POST policies = %d, want 403", w.Code)
	}
}

func TestRBACListRolesRequiresMembership(t *testing.T) {
	env := newRBACTestEnv(t)
	if w := do(t, env.router, http.MethodGet, "/api/v1/rbac/roles", "tok-owner", nil); w.Code != http.StatusOK {
		t.Fatalf("owner GET rbac/roles = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if w := do(t, env.router, http.MethodGet, "/api/v1/rbac/roles", "tok-stranger", nil); w.Code != http.StatusForbidden {
		t.Fatalf("non-member GET rbac/roles = %d, want 403", w.Code)
	}
}

// TestRBACManageGate proves rbac.manage is required to mutate members: the
// auditor (rbac.read only) may list but not assign.
func TestRBACManageGate(t *testing.T) {
	env := newRBACTestEnv(t)
	if w := do(t, env.router, http.MethodGet, "/api/v1/rbac/members", "tok-auditor", nil); w.Code != http.StatusOK {
		t.Fatalf("auditor GET members = %d, want 200", w.Code)
	}
	w := do(t, env.router, http.MethodPut, "/api/v1/rbac/members/new-user", "tok-auditor", map[string]any{"role": "operator"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("auditor PUT member = %d, want 403", w.Code)
	}
}

func TestRBACOwnerAssignsMember(t *testing.T) {
	env := newRBACTestEnv(t)
	w := do(t, env.router, http.MethodPut, "/api/v1/rbac/members/new-user", "tok-owner", map[string]any{"role": "operator"})
	if w.Code != http.StatusOK {
		t.Fatalf("owner PUT member = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	// The new member is now visible in the workspace listing.
	got := do(t, env.router, http.MethodGet, "/api/v1/rbac/members", "tok-owner", nil)
	if got.Code != http.StatusOK {
		t.Fatalf("list members = %d", got.Code)
	}
	if !contains(got.Body.String(), "new-user") {
		t.Fatalf("new member not in listing: %s", got.Body.String())
	}
}

// TestRBACOwnerEscalationForbidden proves the row-conditional rule the flat
// permission cannot express: an admin (who holds rbac.manage) still cannot mint
// an owner.
func TestRBACOwnerEscalationForbidden(t *testing.T) {
	env := newRBACTestEnv(t)
	w := do(t, env.router, http.MethodPut, "/api/v1/rbac/members/someone", "tok-admin", map[string]any{"role": "owner"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("admin promote-to-owner = %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// TestRBACMembersCrossTenantIsolation proves the member listing is workspace
// scoped: tenant-a's owner never sees tenant-b's members and vice versa.
func TestRBACMembersCrossTenantIsolation(t *testing.T) {
	env := newRBACTestEnv(t)
	a := do(t, env.router, http.MethodGet, "/api/v1/rbac/members", "tok-owner", nil)
	if contains(a.Body.String(), "user-b-owner") {
		t.Fatalf("tenant-a sees tenant-b member: %s", a.Body.String())
	}
	b := do(t, env.router, http.MethodGet, "/api/v1/rbac/members", "tok-b-owner", nil)
	if contains(b.Body.String(), "user-owner") || contains(b.Body.String(), "user-auditor") {
		t.Fatalf("tenant-b sees tenant-a members: %s", b.Body.String())
	}
}

// TestStepUpPromoteRequiresAssertion proves the highest-risk route demands a
// fresh step-up assertion even for an owner with the session MFA claim.
func TestStepUpPromoteRequiresAssertion(t *testing.T) {
	env := newRBACTestEnv(t)
	path := "/api/v1/policies/" + uuid.NewString() + "/promote"
	w := do(t, env.router, http.MethodPost, path, "tok-owner", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("promote without assertion = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// TestStepUpPromoteReplayDeniedAtHTTP proves single-use enforcement end to end:
// a valid code clears the step-up gate once, then the same code is rejected.
func TestStepUpPromoteReplayDeniedAtHTTP(t *testing.T) {
	env := newRBACTestEnv(t)
	path := "/api/v1/policies/" + uuid.NewString() + "/promote"
	code, err := totp.GenerateCode(rbacStepUpSecret, time.Now())
	if err != nil {
		t.Fatalf("gen code: %v", err)
	}

	first := doWithHeaders(t, env.router, http.MethodPost, path, "tok-owner", nil, map[string]string{middleware.StepUpAssertionHeader: code})
	// Step-up passed (the missing policy yields a 4xx from the handler, but NOT
	// the 400 "assertion required" nor the 403 "verification failed").
	if first.Code == http.StatusBadRequest || first.Code == http.StatusForbidden {
		t.Fatalf("valid step-up code rejected: status=%d body=%s", first.Code, first.Body.String())
	}

	replay := doWithHeaders(t, env.router, http.MethodPost, path, "tok-owner", nil, map[string]string{middleware.StepUpAssertionHeader: code})
	if replay.Code != http.StatusForbidden {
		t.Fatalf("replayed step-up code = %d, want 403; body=%s", replay.Code, replay.Body.String())
	}
}

// TestStepUpPromoteBadCodeDenied proves a wrong code is rejected at the gate.
func TestStepUpPromoteBadCodeDenied(t *testing.T) {
	env := newRBACTestEnv(t)
	path := "/api/v1/policies/" + uuid.NewString() + "/promote"
	w := doWithHeaders(t, env.router, http.MethodPost, path, "tok-owner", nil, map[string]string{middleware.StepUpAssertionHeader: "000000"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("bad step-up code = %d, want 403", w.Code)
	}
}
