package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/broker"
	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/pkg/ratelimit"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestEnrollIPThrottle proves the public enrollment endpoint is rate-limited per
// client IP: a second request from the same IP after the bucket is spent is
// rejected with 429 rather than hitting the handler (resource-exhaustion guard).
func TestEnrollIPThrottle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/x", enrollIPThrottle(ratelimit.New(ratelimit.Config{RPS: 1, Burst: 1})), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	first := httptest.NewRecorder()
	r.ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/x", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first request: want 200, got %d", first.Code)
	}
	second := httptest.NewRecorder()
	r.ServeHTTP(second, httptest.NewRequest(http.MethodPost, "/x", nil))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request from same IP: want 429, got %d", second.Code)
	}
}

// agentTestDeps builds router-ready Deps with two tenants and a wired agent
// enrollment service backed by an ephemeral CA, so the full enroll → list →
// bind → revoke surface runs against a real (SQLite) database.
func agentTestDeps(t *testing.T) Deps {
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
	ca, err := broker.NewEphemeralCA()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	ready := &atomic.Bool{}
	ready.Store(true)
	enrollLimiter := NewAgentEnrollIPLimiter()
	t.Cleanup(enrollLimiter.Stop)
	return Deps{
		Validator: mapValidator{byToken: map[string]*iamcore.Claims{
			"tok-a": {Subject: "user-a", TenantID: "tenant-a"},
			"tok-b": {Subject: "user-b", TenantID: "tenant-b"},
		}},
		DB:                   db,
		Encryptor:            crypto.PassthroughEncryptor{},
		ConnectorEncryptor:   access.PassthroughEncryptor{},
		AgentEnrollment:      broker.NewEnrollmentService(db, ca, "relay.example:7443"),
		AgentEnrollIPLimiter: enrollLimiter,
		Ready:                ready,
	}
}

// workspaceID loads the workspace UUID for a tenant.
func workspaceID(t *testing.T, deps Deps, tenant string) uuid.UUID {
	t.Helper()
	var ws models.Workspace
	if err := deps.DB.Where("iam_core_tenant_id = ?", tenant).Take(&ws).Error; err != nil {
		t.Fatalf("load workspace %s: %v", tenant, err)
	}
	return ws.ID
}

// mintAndEnroll mints a token for the tenant then redeems it through the public
// enrollment endpoint, returning the new agent id.
func mintAndEnroll(t *testing.T, r http.Handler, token string) uuid.UUID {
	t.Helper()
	w := do(t, r, http.MethodPost, "/api/v1/agents", token, map[string]any{"name": "edge-1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("mint token: want 201, got %d (%s)", w.Code, w.Body.String())
	}
	var mint struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &mint); err != nil {
		t.Fatalf("decode mint: %v", err)
	}
	if mint.Token == "" {
		t.Fatal("mint returned empty token")
	}
	_, csrPEM, _, err := broker.GenerateAgentKey()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	w = do(t, r, http.MethodPost, "/api/v1/agents/enroll", "", map[string]any{
		"token":         mint.Token,
		"csr":           string(csrPEM),
		"agent_version": "test",
		"platform":      "linux/amd64",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("enroll: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	var enrolled struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &enrolled); err != nil {
		t.Fatalf("decode enroll: %v", err)
	}
	id, err := uuid.Parse(enrolled.AgentID)
	if err != nil {
		t.Fatalf("bad agent id %q: %v", enrolled.AgentID, err)
	}
	return id
}

func TestAgentEnrollListAndCrossTenantIsolation(t *testing.T) {
	deps := agentTestDeps(t)
	r := NewRouter(deps)

	agentID := mintAndEnroll(t, r, "tok-a")

	// tenant-a sees its agent.
	w := do(t, r, http.MethodGet, "/api/v1/agents", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list agents: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	var listed struct {
		Agents []broker.AgentView `json:"agents"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Agents) != 1 || listed.Agents[0].Agent.ID != agentID {
		t.Fatalf("tenant-a should see exactly its agent, got %+v", listed.Agents)
	}

	// tenant-b sees none (isolation), and cannot fetch tenant-a's agent by id.
	w = do(t, r, http.MethodGet, "/api/v1/agents", "tok-b", nil)
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list b: %v", err)
	}
	if len(listed.Agents) != 0 {
		t.Fatalf("tenant-b must not see tenant-a agents, got %+v", listed.Agents)
	}
	w = do(t, r, http.MethodGet, "/api/v1/agents/"+agentID.String(), "tok-b", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get: want 404, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestAgentEnrollTokenIsOneShot(t *testing.T) {
	deps := agentTestDeps(t)
	r := NewRouter(deps)

	w := do(t, r, http.MethodPost, "/api/v1/agents", "tok-a", map[string]any{"name": "edge-1"})
	var mint struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &mint)

	_, csrPEM, _, err := broker.GenerateAgentKey()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	body := map[string]any{"token": mint.Token, "csr": string(csrPEM)}

	// First redemption succeeds.
	if w := do(t, r, http.MethodPost, "/api/v1/agents/enroll", "", body); w.Code != http.StatusOK {
		t.Fatalf("first enroll: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	// Replay with the same token is rejected (one-shot), with the coarse 401.
	if w := do(t, r, http.MethodPost, "/api/v1/agents/enroll", "", body); w.Code != http.StatusUnauthorized {
		t.Fatalf("replay enroll: want 401, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestAgentBindUnbindTarget(t *testing.T) {
	deps := agentTestDeps(t)
	r := NewRouter(deps)
	ws := workspaceID(t, deps, "tenant-a")
	agentID := mintAndEnroll(t, r, "tok-a")

	target := &models.PAMTarget{WorkspaceID: ws, Name: "db", Protocol: models.PAMProtocolPostgres, Address: "10.0.0.5:5432"}
	target.ID = uuid.New()
	if err := deps.DB.Create(target).Error; err != nil {
		t.Fatalf("seed target: %v", err)
	}

	// Bind the target to the agent.
	w := do(t, r, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/targets", "tok-a",
		map[string]any{"target_id": target.ID.String()})
	if w.Code != http.StatusOK {
		t.Fatalf("bind: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	var reloaded models.PAMTarget
	if err := deps.DB.Where("id = ?", target.ID).Take(&reloaded).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.ViaAgentID == nil || *reloaded.ViaAgentID != agentID {
		t.Fatalf("target not bound to agent, via=%v", reloaded.ViaAgentID)
	}

	// It shows up under the agent's bound targets.
	w = do(t, r, http.MethodGet, "/api/v1/agents/"+agentID.String()+"/targets", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list bound: want 200, got %d", w.Code)
	}

	// Unbind reverts to direct dialing.
	w = do(t, r, http.MethodDelete, "/api/v1/agents/"+agentID.String()+"/targets/"+target.ID.String(), "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("unbind: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	var after models.PAMTarget
	if err := deps.DB.Where("id = ?", target.ID).Take(&after).Error; err != nil {
		t.Fatalf("reload2: %v", err)
	}
	if after.ViaAgentID != nil {
		t.Fatalf("target should be unbound, via=%v", after.ViaAgentID)
	}
}

func TestAgentRevoke(t *testing.T) {
	deps := agentTestDeps(t)
	r := NewRouter(deps)
	agentID := mintAndEnroll(t, r, "tok-a")

	w := do(t, r, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/revoke", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	var agent models.TargetAgent
	if err := deps.DB.Where("id = ?", agentID).Take(&agent).Error; err != nil {
		t.Fatalf("reload agent: %v", err)
	}
	if agent.Status != models.AgentStatusRevoked {
		t.Fatalf("agent status = %q, want revoked", agent.Status)
	}
}

func TestAgentMintUnavailableWithoutCA(t *testing.T) {
	deps := agentTestDeps(t)
	deps.AgentEnrollment = nil // no CA configured
	r := NewRouter(deps)

	// The public enrollment route is absent (404) and mint returns 503.
	if w := do(t, r, http.MethodPost, "/api/v1/agents", "tok-a", map[string]any{"name": "x"}); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("mint without CA: want 503, got %d (%s)", w.Code, w.Body.String())
	}
	if w := do(t, r, http.MethodPost, "/api/v1/agents/enroll", "", map[string]any{"token": "x", "csr": "y"}); w.Code != http.StatusNotFound {
		t.Fatalf("enroll route without CA: want 404, got %d (%s)", w.Code, w.Body.String())
	}
}
