package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// pamTestDeps builds a router-ready Deps with two tenants and a token matrix
// covering the live-session-control authorization combinations: a plain
// operator, an operator with the pam.takeover permission but no step-up MFA,
// and a fully-authorized operator (permission + MFA).
func pamTestDeps(t *testing.T) Deps {
	t.Helper()
	// A real (test) DEK so the vault seals credentials through the same
	// AES-256-GCM path production uses; newPAMHandlers reads this at router
	// build time, so it must be set before NewRouter.
	t.Setenv("ACCESS_CREDENTIAL_DEK", base64.StdEncoding.EncodeToString(make([]byte, 32)))
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
			"tok-a":          {Subject: "user-a", TenantID: "tenant-a"},
			"tok-a-mfa":      {Subject: "user-a", TenantID: "tenant-a", MFASatisfied: true},
			"tok-a-perm":     {Subject: "user-a", TenantID: "tenant-a", Scopes: []string{"pam.takeover"}},
			"tok-a-perm-mfa": {Subject: "user-a", TenantID: "tenant-a", Scopes: []string{"pam.takeover"}, MFASatisfied: true},
			"tok-b-perm-mfa": {Subject: "user-b", TenantID: "tenant-b", Scopes: []string{"pam.takeover"}, MFASatisfied: true},
		}},
		DB:                 db,
		Encryptor:          crypto.PassthroughEncryptor{},
		ConnectorEncryptor: access.PassthroughEncryptor{},
		Ready:              ready,
	}
}

// seedActiveSession creates a target + active session directly so the control
// endpoints have something to act on, returning the session id and workspace.
func seedActiveSession(t *testing.T, deps Deps, tenant string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	var ws models.Workspace
	if err := deps.DB.Where("iam_core_tenant_id = ?", tenant).Take(&ws).Error; err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	target := &models.PAMTarget{
		WorkspaceID: ws.ID, Name: "box", Protocol: models.PAMProtocolSSH, Address: "h:22",
	}
	target.ID = uuid.New()
	if err := deps.DB.Create(target).Error; err != nil {
		t.Fatalf("seed target: %v", err)
	}
	session := &models.PAMSession{
		WorkspaceID: ws.ID, TargetID: target.ID, Subject: "alice",
		Protocol: models.PAMProtocolSSH, State: models.PAMSessionActive,
	}
	session.ID = uuid.New()
	if err := deps.DB.Create(session).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return session.ID, ws.ID
}

func TestPauseRequiresPermission(t *testing.T) {
	deps := pamTestDeps(t)
	r := NewRouter(deps)
	sid, _ := seedActiveSession(t, deps, "tenant-a")

	// No permission → 403.
	w := do(t, r, http.MethodPost, "/api/v1/pam/sessions/"+sid.String()+"/pause", "tok-a", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("pause without permission: want 403, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestPauseRequiresMFA(t *testing.T) {
	deps := pamTestDeps(t)
	r := NewRouter(deps)
	sid, _ := seedActiveSession(t, deps, "tenant-a")

	// Permission but no step-up MFA → 403.
	w := do(t, r, http.MethodPost, "/api/v1/pam/sessions/"+sid.String()+"/pause", "tok-a-perm", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("pause without MFA: want 403, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestPauseAndTerminateAuthorizedAudited(t *testing.T) {
	deps := pamTestDeps(t)
	r := NewRouter(deps)
	sid, ws := seedActiveSession(t, deps, "tenant-a")

	// Permission + MFA → 200.
	w := do(t, r, http.MethodPost, "/api/v1/pam/sessions/"+sid.String()+"/pause", "tok-a-perm-mfa", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("authorized pause: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	var reloaded models.PAMSession
	if err := deps.DB.Where("id = ?", sid).Take(&reloaded).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reloaded.Paused {
		t.Fatal("session not marked paused")
	}

	// Terminate.
	w = do(t, r, http.MethodPost, "/api/v1/pam/sessions/"+sid.String()+"/terminate", "tok-a-perm-mfa", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("authorized terminate: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	if err := deps.DB.Where("id = ?", sid).Take(&reloaded).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.State != models.PAMSessionTerminated {
		t.Fatalf("session not terminated: %q", reloaded.State)
	}

	// Both control actions are audited under the acting workspace.
	var pauseAudit, termAudit int64
	deps.DB.Model(&models.AuditEvent{}).Where("workspace_id = ? AND action = ?", ws, "pam.session.paused").Count(&pauseAudit)
	deps.DB.Model(&models.AuditEvent{}).Where("workspace_id = ? AND action = ?", ws, "pam.session.terminated").Count(&termAudit)
	if pauseAudit < 1 || termAudit < 1 {
		t.Fatalf("control actions not audited: pause=%d terminate=%d", pauseAudit, termAudit)
	}
}

func TestSessionControlCrossTenantIsolation(t *testing.T) {
	deps := pamTestDeps(t)
	r := NewRouter(deps)
	sid, _ := seedActiveSession(t, deps, "tenant-a")

	// tenant-b is fully authorized for ITS OWN workspace but the session lives
	// in tenant-a; the workspace scoping must hide it (404), not act on it.
	w := do(t, r, http.MethodPost, "/api/v1/pam/sessions/"+sid.String()+"/terminate", "tok-b-perm-mfa", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant terminate: want 404, got %d (%s)", w.Code, w.Body.String())
	}

	// The session is untouched.
	var reloaded models.PAMSession
	if err := deps.DB.Where("id = ?", sid).Take(&reloaded).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.State != models.PAMSessionActive {
		t.Fatalf("cross-tenant call mutated session: %q", reloaded.State)
	}
}

// TestLeaseEndpointsHappyPath drives the lease state machine through the HTTP
// surface: request → approve → revoke, asserting the derived state on each
// response.
func TestLeaseEndpointsHappyPath(t *testing.T) {
	deps := pamTestDeps(t)
	r := NewRouter(deps)

	// Seed a target via the API.
	w := do(t, r, http.MethodPost, "/api/v1/pam/targets", "tok-a-perm-mfa", map[string]any{
		"name": "db", "protocol": "postgres", "address": "db:5432",
		"secret": map[string]any{"password": "pw"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create target: want 201, got %d (%s)", w.Code, w.Body.String())
	}
	var target models.PAMTarget
	if err := json.Unmarshal(w.Body.Bytes(), &target); err != nil {
		t.Fatalf("decode target: %v", err)
	}

	// Request a lease.
	w = do(t, r, http.MethodPost, "/api/v1/pam/leases", "tok-a", map[string]any{
		"target_id": target.ID.String(), "subject": "user-a", "ttl_seconds": 1800, "reason": "deploy",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("request lease: want 201, got %d (%s)", w.Code, w.Body.String())
	}
	var lease models.PAMLease
	if err := json.Unmarshal(w.Body.Bytes(), &lease); err != nil {
		t.Fatalf("decode lease: %v", err)
	}
	if lease.State != models.PAMLeaseStateRequested {
		t.Fatalf("want requested, got %q", lease.State)
	}

	// Approve and revoke are step-up-MFA gated: a token without satisfied MFA is
	// rejected before the state machine runs.
	w = do(t, r, http.MethodPost, "/api/v1/pam/leases/"+lease.ID.String()+"/approve", "tok-a", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("approve without MFA: want 403, got %d (%s)", w.Code, w.Body.String())
	}

	// Approve (with step-up MFA).
	w = do(t, r, http.MethodPost, "/api/v1/pam/leases/"+lease.ID.String()+"/approve", "tok-a-mfa", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("approve lease: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &lease); err != nil {
		t.Fatalf("decode lease: %v", err)
	}
	if lease.State != models.PAMLeaseStateApproved {
		t.Fatalf("want approved, got %q", lease.State)
	}

	// Revoke (step-up MFA gated).
	w = do(t, r, http.MethodPost, "/api/v1/pam/leases/"+lease.ID.String()+"/revoke", "tok-a-mfa", map[string]any{"reason": "done"})
	if w.Code != http.StatusOK {
		t.Fatalf("revoke lease: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &lease); err != nil {
		t.Fatalf("decode lease: %v", err)
	}
	if lease.State != models.PAMLeaseStateRevoked {
		t.Fatalf("want revoked, got %q", lease.State)
	}
}
