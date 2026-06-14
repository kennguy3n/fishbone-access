package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"github.com/kennguy3n/fishbone-access/internal/services/access"
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

// rbacStepUpDEK is a fixed base64-encoded 32-byte key backing the AES-GCM
// encryptor that seals the enrolled step-up secret at rest. Test fixture only.
const rbacStepUpDEK = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

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
	seedMember(t, rbac, wsA, "user-operator", authz.RoleOperator)
	seedMember(t, rbac, wsA, "user-auditor", authz.RoleAuditor)
	seedMember(t, rbac, wsB, "user-b-owner", authz.RoleOwner)
	// user-stranger carries a valid tenant-a token but has NO membership row.

	totpEnc, err := crypto.NewAESGCMEncryptor(rbacStepUpDEK)
	if err != nil {
		t.Fatalf("totp encryptor: %v", err)
	}
	totpVerifier, err := mfa.NewTOTPMFAVerifier(db, totpEnc)
	if err != nil {
		t.Fatalf("totp verifier: %v", err)
	}
	// Enrolled step-up secret for the tenant-a owner, sealed at rest exactly as
	// an enrollment writer would via the verifier's SealTOTPSecret.
	sealedSecret, err := totpVerifier.SealTOTPSecret(wsA, "user-owner", rbacStepUpSecret)
	if err != nil {
		t.Fatalf("seal totp secret: %v", err)
	}
	if err := db.Create(&models.UserTOTPSecret{
		WorkspaceID: wsA, UserID: "user-owner", Secret: sealedSecret, Verified: true,
	}).Error; err != nil {
		t.Fatalf("seed totp secret: %v", err)
	}

	ready := &atomic.Bool{}
	ready.Store(true)
	deps := Deps{
		Validator: mapValidator{byToken: map[string]*iamcore.Claims{
			"tok-owner":    {Subject: "user-owner", TenantID: "tenant-a", MFASatisfied: true},
			"tok-admin":    {Subject: "user-admin", TenantID: "tenant-a", MFASatisfied: true},
			"tok-operator": {Subject: "user-operator", TenantID: "tenant-a"},
			"tok-auditor":  {Subject: "user-auditor", TenantID: "tenant-a"},
			"tok-stranger": {Subject: "user-stranger", TenantID: "tenant-a"},
			"tok-b-owner":  {Subject: "user-b-owner", TenantID: "tenant-b"},
		}},
		DB:                 db,
		Encryptor:          crypto.PassthroughEncryptor{},
		ConnectorEncryptor: access.PassthroughEncryptor{},
		Ready:              ready,
		RBAC:               rbac,
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

// TestRBACWorkflowGating proves the workflow routes honor the workflow.read
// / workflow.edit split: a read-only auditor may list workflows but cannot
// author one or fire the emergency-offboard kill switch, while an edit-holder
// (admin) clears the permission gate. This guards the separation of duties the
// RBAC model defines for the workflow engine.
func TestRBACWorkflowGating(t *testing.T) {
	env := newRBACTestEnv(t)

	// Auditor holds workflow.read → list is allowed.
	if w := do(t, env.router, http.MethodGet, "/api/v1/workflows", "tok-auditor", nil); w.Code != http.StatusOK {
		t.Fatalf("auditor GET workflows = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	// Auditor lacks workflow.edit → authoring and the kill switch are denied at
	// the permission gate (before any handler logic runs).
	body := map[string]any{"name": "wf", "definition": map[string]any{}}
	if w := do(t, env.router, http.MethodPost, "/api/v1/workflows", "tok-auditor", body); w.Code != http.StatusForbidden {
		t.Fatalf("auditor POST workflows = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if w := do(t, env.router, http.MethodPost, "/api/v1/emergency-offboard", "tok-auditor", map[string]any{"user_external_id": "x", "reason": "y"}); w.Code != http.StatusForbidden {
		t.Fatalf("auditor POST emergency-offboard = %d, want 403; body=%s", w.Code, w.Body.String())
	}

	// Admin holds workflow.edit → the permission gate admits the request (the
	// create then succeeds; the point is it is NOT a 403 from RequirePermission).
	if w := do(t, env.router, http.MethodPost, "/api/v1/workflows", "tok-admin", body); w.Code == http.StatusForbidden {
		t.Fatalf("admin POST workflows = 403, want the permission gate to admit it; body=%s", w.Body.String())
	}
}

// TestRBACPAMTargetGating proves the PAM target routes honor the
// pam.target.read / pam.target.write split. Registering a target binds a sealed
// credential to the workspace, so it is a privileged write: a standard operator
// holds pam.target.read (may list) but not pam.target.write (may not register),
// while an admin holds the write permission and clears the gate. This closes the
// ungated-target-creation gap the review flagged at integration — before this,
// any workspace member could register a target with a credential.
func TestRBACPAMTargetGating(t *testing.T) {
	// A real (test) DEK so newPAMHandlers builds a working vault that can seal
	// the target credential; it is read at NewRouter time inside newRBACTestEnv.
	t.Setenv("ACCESS_CREDENTIAL_DEK", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	env := newRBACTestEnv(t)

	body := map[string]any{
		"name": "db", "protocol": "postgres", "address": "db:5432",
		"secret": map[string]any{"password": "pw"},
	}

	// Operator holds pam.target.read → listing targets is allowed.
	if w := do(t, env.router, http.MethodGet, "/api/v1/pam/targets", "tok-operator", nil); w.Code != http.StatusOK {
		t.Fatalf("operator GET pam/targets = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	// Operator lacks pam.target.write → registering a target is denied at the
	// permission gate (before the vault ever seals a credential).
	if w := do(t, env.router, http.MethodPost, "/api/v1/pam/targets", "tok-operator", body); w.Code != http.StatusForbidden {
		t.Fatalf("operator POST pam/targets = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	// Auditor is read-only across the board → target registration is denied too.
	if w := do(t, env.router, http.MethodPost, "/api/v1/pam/targets", "tok-auditor", body); w.Code != http.StatusForbidden {
		t.Fatalf("auditor POST pam/targets = %d, want 403; body=%s", w.Code, w.Body.String())
	}

	// Admin holds pam.target.write → the gate admits the registration and it
	// succeeds (201), proving the gate is a permission split, not a blanket deny.
	if w := do(t, env.router, http.MethodPost, "/api/v1/pam/targets", "tok-admin", body); w.Code != http.StatusCreated {
		t.Fatalf("admin POST pam/targets = %d, want 201; body=%s", w.Code, w.Body.String())
	}
}

// TestRBACConnectorGating proves the connector routes honor the
// connector.read / connector.manage split. An operator holds connector.read so
// the catalogue list is allowed, but lacks connector.manage so creating a
// connector is denied at the permission gate. A compliance auditor holds
// neither connector permission, so even the read surface is fully closed. An
// admin holds connector.manage, so the mutation gate admits the request. This
// closes the separation-of-duties gap the review flagged for the connector
// fabric.
func TestRBACConnectorGating(t *testing.T) {
	env := newRBACTestEnv(t)

	// Operator holds connector.read → catalogue list is allowed.
	if w := do(t, env.router, http.MethodGet, "/api/v1/connectors", "tok-operator", nil); w.Code != http.StatusOK {
		t.Fatalf("operator GET connectors = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	// Operator lacks connector.manage → creating a connector is denied at the
	// permission gate (before any handler logic runs).
	body := map[string]any{"provider": "microsoft", "display_name": "x"}
	if w := do(t, env.router, http.MethodPost, "/api/v1/connectors", "tok-operator", body); w.Code != http.StatusForbidden {
		t.Fatalf("operator POST connectors = %d, want 403; body=%s", w.Code, w.Body.String())
	}

	// Auditor holds neither connector permission → even the read surface is
	// fully closed.
	if w := do(t, env.router, http.MethodGet, "/api/v1/connectors", "tok-auditor", nil); w.Code != http.StatusForbidden {
		t.Fatalf("auditor GET connectors = %d, want 403; body=%s", w.Code, w.Body.String())
	}

	// Admin holds connector.manage → the mutation gate admits the request (the
	// point is it is NOT a 403 from RequirePermission).
	if w := do(t, env.router, http.MethodPost, "/api/v1/connectors", "tok-admin", body); w.Code == http.StatusForbidden {
		t.Fatalf("admin POST connectors = 403, want the permission gate to admit it; body=%s", w.Body.String())
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

// TestRBACMyPermissions proves /rbac/permissions returns the caller's resolved
// role + the exact permission set the per-route RequirePermission gates enforce
// (so the UI can gate affordances honestly), and that it fails closed for a
// non-member like every other tenant-scoped route.
func TestRBACMyPermissions(t *testing.T) {
	env := newRBACTestEnv(t)

	w := do(t, env.router, http.MethodGet, "/api/v1/rbac/permissions", "tok-auditor", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("auditor GET rbac/permissions = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Role        string   `json:"role"`
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v; body=%s", err, w.Body.String())
	}
	if got.Role != string(authz.RoleAuditor) {
		t.Fatalf("role = %q, want %q", got.Role, authz.RoleAuditor)
	}
	// The payload must equal the authoritative resolved set exactly — the same
	// set AuthzMiddleware seeds and RequirePermission checks against.
	want := authz.PermissionsForRole(authz.RoleAuditor)
	if len(got.Permissions) != len(want) {
		t.Fatalf("permission count = %d, want %d; got=%v", len(got.Permissions), len(want), got.Permissions)
	}
	for _, p := range got.Permissions {
		if !want.Has(authz.Permission(p)) {
			t.Fatalf("unexpected permission %q in resolved set %v", p, got.Permissions)
		}
	}
	// The compliance-export affordance the UI gates on is present for an auditor.
	if !contains(w.Body.String(), string(authz.PermComplianceExport)) {
		t.Fatalf("auditor should resolve %s; body=%s", authz.PermComplianceExport, w.Body.String())
	}

	// Fail closed: a valid token with no membership row is denied at AuthzMiddleware.
	if s := do(t, env.router, http.MethodGet, "/api/v1/rbac/permissions", "tok-stranger", nil); s.Code != http.StatusForbidden {
		t.Fatalf("non-member GET rbac/permissions = %d, want 403", s.Code)
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

// TestRBACDeleteOwnerEscalationForbidden proves the delete path enforces the
// same row-conditional rule as assignment: an admin (who holds rbac.manage)
// cannot remove an owner, even when a co-owner remains so the last-owner guard
// is not what is doing the rejecting. Without the guard this would be a 204.
func TestRBACDeleteOwnerEscalationForbidden(t *testing.T) {
	env := newRBACTestEnv(t)
	// Owner mints a co-owner so two owners exist.
	if w := do(t, env.router, http.MethodPut, "/api/v1/rbac/members/co-owner", "tok-owner", map[string]any{"role": "owner"}); w.Code != http.StatusOK {
		t.Fatalf("owner mint co-owner = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	// Admin cannot delete an owner — fails closed with 403.
	if w := do(t, env.router, http.MethodDelete, "/api/v1/rbac/members/co-owner", "tok-admin", nil); w.Code != http.StatusForbidden {
		t.Fatalf("admin delete owner = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	// The co-owner must still be present.
	got := do(t, env.router, http.MethodGet, "/api/v1/rbac/members", "tok-owner", nil)
	if !contains(got.Body.String(), "co-owner") {
		t.Fatalf("co-owner should survive forbidden delete: %s", got.Body.String())
	}
	// An owner can remove the co-owner.
	if w := do(t, env.router, http.MethodDelete, "/api/v1/rbac/members/co-owner", "tok-owner", nil); w.Code != http.StatusNoContent {
		t.Fatalf("owner delete co-owner = %d, want 204; body=%s", w.Code, w.Body.String())
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
