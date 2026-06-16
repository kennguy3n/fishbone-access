package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
)

// discoveryTestEnv wires a router with RBAC fully installed, two tenants, and a
// role matrix covering the discovery RBAC surface end to end:
//   - an admin (read+write target) → can scan/onboard/edit policy,
//   - an operator (read-only target) → can browse but not mutate,
//   - a second-tenant admin → proves cross-tenant isolation.
type discoveryTestEnv struct {
	router http.Handler
	db     *gorm.DB
}

func newDiscoveryTestEnv(t *testing.T) discoveryTestEnv {
	t.Helper()
	t.Setenv("ACCESS_CREDENTIAL_DEK", base64.StdEncoding.EncodeToString(make([]byte, 32)))
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
	seedMember(t, rbac, wsA, "user-admin", authz.RoleAdmin)
	seedMember(t, rbac, wsA, "user-operator", authz.RoleOperator)
	seedMember(t, rbac, wsB, "user-b-admin", authz.RoleAdmin)

	ready := &atomic.Bool{}
	ready.Store(true)
	deps := Deps{
		Validator: mapValidator{byToken: map[string]*iamcore.Claims{
			"tok-admin":    {Subject: "user-admin", TenantID: "tenant-a", MFASatisfied: true},
			"tok-operator": {Subject: "user-operator", TenantID: "tenant-a"},
			"tok-b-admin":  {Subject: "user-b-admin", TenantID: "tenant-b", MFASatisfied: true},
		}},
		DB:                 db,
		Encryptor:          crypto.PassthroughEncryptor{},
		ConnectorEncryptor: access.PassthroughEncryptor{},
		Ready:              ready,
		RBAC:               rbac,
	}
	return discoveryTestEnv{router: NewRouter(deps), db: db}
}

func seedDiscoveredAsset(t *testing.T, db *gorm.DB, tenant, externalID string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ws := workspaceIDByTenant(t, db, tenant)
	now := time.Now().UTC()
	asset := &models.DiscoveredAsset{
		WorkspaceID: ws,
		Source:      models.DiscoverySourceAgentSweep,
		ExternalID:  externalID,
		Name:        "10.0.0.5",
		Protocol:    "ssh",
		Address:     "10.0.0.5:22",
		Status:      models.DiscoveryStatusUnmanaged,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}
	asset.ID = uuid.New()
	if err := db.Create(asset).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	return asset.ID, ws
}

func TestDiscoverySummaryRejectsUnknownToken(t *testing.T) {
	env := newDiscoveryTestEnv(t)
	w := do(t, env.router, http.MethodGet, "/api/v1/discovery/summary", "tok-unknown", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown token: want 401, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestDiscoveryListAssetsReadOnlyAllowed(t *testing.T) {
	env := newDiscoveryTestEnv(t)
	seedDiscoveredAsset(t, env.db, "tenant-a", "host:10.0.0.5:22")

	// Operator (read-only) can browse the inventory.
	w := do(t, env.router, http.MethodGet, "/api/v1/discovery/assets", "tok-operator", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list assets: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	var body struct {
		Assets []models.DiscoveredAsset `json:"assets"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Assets) != 1 {
		t.Fatalf("assets = %d, want 1", len(body.Assets))
	}
}

func TestDiscoveryOnboardRequiresWritePermission(t *testing.T) {
	env := newDiscoveryTestEnv(t)
	assetID, _ := seedDiscoveredAsset(t, env.db, "tenant-a", "host:10.0.0.5:22")

	// Operator holds pam.target.read but not write → 403.
	w := do(t, env.router, http.MethodPost, "/api/v1/discovery/assets/"+assetID.String()+"/onboard", "tok-operator", map[string]any{
		"username": "root", "password": "pw",
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("onboard read-only: want 403, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestDiscoveryOnboardCreatesTarget(t *testing.T) {
	env := newDiscoveryTestEnv(t)
	assetID, ws := seedDiscoveredAsset(t, env.db, "tenant-a", "host:10.0.0.5:22")

	w := do(t, env.router, http.MethodPost, "/api/v1/discovery/assets/"+assetID.String()+"/onboard", "tok-admin", map[string]any{
		"username": "root", "password": "hunter2", "require_mfa": true,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("onboard: want 201, got %d (%s)", w.Code, w.Body.String())
	}
	var target models.PAMTarget
	if err := json.Unmarshal(w.Body.Bytes(), &target); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if target.Address != "10.0.0.5:22" || target.Protocol != models.PAMProtocolSSH {
		t.Fatalf("target prefilled wrong: %+v", target)
	}

	// The discovered asset is now managed and linked to the new target.
	var got models.DiscoveredAsset
	if err := env.db.Where("workspace_id = ? AND id = ?", ws, assetID).Take(&got).Error; err != nil {
		t.Fatalf("reload asset: %v", err)
	}
	if got.Status != models.DiscoveryStatusManaged || got.TargetID == nil {
		t.Fatalf("asset not managed: %+v", got)
	}
}

// TestDiscoveryDispositionEchoesNormalizedStatus proves the disposition handler
// returns the status the engine actually persisted (trimmed), not the raw
// request body, so a client syncing its cache from the response can't drift.
func TestDiscoveryDispositionEchoesNormalizedStatus(t *testing.T) {
	env := newDiscoveryTestEnv(t)
	ws := workspaceIDByTenant(t, env.db, "tenant-a")
	now := time.Now().UTC()
	acct := &models.DiscoveredAccount{
		WorkspaceID: ws,
		TargetID:    uuid.New(),
		Username:    "postgres",
		Source:      models.DiscoverySourceDBAccounts,
		Status:      models.DiscoveryStatusOrphan,
		CanLogin:    true,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}
	acct.ID = uuid.New()
	if err := env.db.Create(acct).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}

	w := do(t, env.router, http.MethodPost, "/api/v1/discovery/accounts/"+acct.ID.String()+"/disposition", "tok-admin", map[string]any{
		"status": "  ignored  ",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("disposition: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != models.DiscoveryStatusIgnored {
		t.Fatalf("response status = %q, want %q (untrimmed echo)", body.Status, models.DiscoveryStatusIgnored)
	}
	var got models.DiscoveredAccount
	if err := env.db.Where("id = ?", acct.ID).Take(&got).Error; err != nil {
		t.Fatalf("reload account: %v", err)
	}
	if got.Status != body.Status {
		t.Fatalf("DB status %q diverged from response %q", got.Status, body.Status)
	}
}

func TestDiscoveryCrossTenantIsolation(t *testing.T) {
	env := newDiscoveryTestEnv(t)
	assetID, _ := seedDiscoveredAsset(t, env.db, "tenant-a", "host:10.0.0.5:22")

	// tenant-b admin cannot see tenant-a's asset.
	w := do(t, env.router, http.MethodGet, "/api/v1/discovery/assets/"+assetID.String(), "tok-b-admin", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get: want 404, got %d (%s)", w.Code, w.Body.String())
	}

	// nor onboard it.
	w = do(t, env.router, http.MethodPost, "/api/v1/discovery/assets/"+assetID.String()+"/onboard", "tok-b-admin", map[string]any{
		"username": "root", "password": "pw",
	})
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant onboard: want 404, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestDiscoveryPolicyDefaultAndSave(t *testing.T) {
	env := newDiscoveryTestEnv(t)

	// Default policy: readable by operator, disabled + safe.
	w := do(t, env.router, http.MethodGet, "/api/v1/discovery/policy", "tok-operator", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get policy: want 200, got %d (%s)", w.Code, w.Body.String())
	}

	// Saving requires write → operator denied.
	w = do(t, env.router, http.MethodPut, "/api/v1/discovery/policy", "tok-operator", map[string]any{"enabled": true})
	if w.Code != http.StatusForbidden {
		t.Fatalf("save policy read-only: want 403, got %d (%s)", w.Code, w.Body.String())
	}

	// Admin can save a flag-only policy.
	w = do(t, env.router, http.MethodPut, "/api/v1/discovery/policy", "tok-admin", map[string]any{
		"enabled": true,
		"rules":   []map[string]any{{"name": "ssh", "protocols": []string{"ssh"}}},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("save policy: want 200, got %d (%s)", w.Code, w.Body.String())
	}
}
