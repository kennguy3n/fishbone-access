package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// mapValidator maps a bearer token to a fixed set of claims, so a single router
// can exercise two different tenants (proving cross-tenant isolation).
type mapValidator struct{ byToken map[string]*iamcore.Claims }

func (m mapValidator) Validate(token string) (*iamcore.Claims, error) {
	c, ok := m.byToken[token]
	if !ok {
		return nil, iamcore.ErrInvalidToken
	}
	return c, nil
}

func lifecycleTestDeps(t *testing.T) Deps {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Two tenants, mapped 1:1 to workspaces.
	for _, ten := range []string{"tenant-a", "tenant-b"} {
		if err := db.Create(&models.Workspace{Name: ten, IAMCoreTenantID: ten}).Error; err != nil {
			t.Fatalf("seed workspace %s: %v", ten, err)
		}
	}
	ready := &atomic.Bool{}
	ready.Store(true)
	return Deps{
		Validator: mapValidator{byToken: map[string]*iamcore.Claims{
			"tok-a":     {Subject: "user-a", TenantID: "tenant-a"},
			"tok-b":     {Subject: "user-b", TenantID: "tenant-b"},
			"tok-a-mfa": {Subject: "user-a", TenantID: "tenant-a", MFASatisfied: true},
		}},
		DB:        db,
		Encryptor: crypto.PassthroughEncryptor{},
		// Connector-instance ops (Create/TestConnectivity/TriggerSync) need a
		// non-nil credential encryptor; without one they fail with an opaque
		// "credential encryptor is required" 500. The catalogue/wizard tests
		// don't seal secrets, but wire a passthrough here so a future handler
		// test that does create a connector gets working deps, not a surprise.
		ConnectorEncryptor: access.PassthroughEncryptor{},
		Ready:              ready,
	}
}

func do(t *testing.T, r http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
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
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestAccessRequestEndpointCrossTenantIsolation(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))

	// tenant-a creates a request.
	w := do(t, r, http.MethodPost, "/api/v1/access-requests", "tok-a", map[string]any{
		"target_user_id": "ext-user",
		"resource_ref":   "app:db",
		"role":           "reader",
		"risk_level":     "high", // parked, not auto-approved
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", w.Code, w.Body.String())
	}
	var created struct {
		Request models.AccessRequest `json:"request"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	id := created.Request.ID.String()
	if id == "" {
		t.Fatal("no request id returned")
	}

	// tenant-a can read its own request.
	w = do(t, r, http.MethodGet, "/api/v1/access-requests/"+id, "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("owner GET = %d, want 200", w.Code)
	}

	// tenant-b must NOT see tenant-a's request (workspace-scoped → 404).
	w = do(t, r, http.MethodGet, "/api/v1/access-requests/"+id, "tok-b", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant GET = %d, want 404", w.Code)
	}

	// tenant-b's list is empty.
	w = do(t, r, http.MethodGet, "/api/v1/access-requests", "tok-b", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d", w.Code)
	}
	var listed struct {
		Requests []models.AccessRequest `json:"requests"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Requests) != 0 {
		t.Fatalf("tenant-b sees %d requests, want 0", len(listed.Requests))
	}
}

func TestUnauthenticatedRejected(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))
	w := do(t, r, http.MethodGet, "/api/v1/access-requests", "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no-token status = %d, want 401", w.Code)
	}
}

// TestSubresourceUnknownParentReturns404 proves the history/items subresource
// endpoints 404 on a non-existent parent rather than returning an empty
// collection with 200 (which would falsely imply the parent exists but is
// empty).
func TestSubresourceUnknownParentReturns404(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))
	missing := uuid.NewString()

	w := do(t, r, http.MethodGet, "/api/v1/access-requests/"+missing+"/history", "tok-a", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("history of unknown request = %d, want 404, body=%s", w.Code, w.Body.String())
	}

	w = do(t, r, http.MethodGet, "/api/v1/access-reviews/"+missing+"/items", "tok-a", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("items of unknown review = %d, want 404, body=%s", w.Code, w.Body.String())
	}
}

func TestPolicyPromoteRequiresMFA(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))

	// Create a draft policy as tenant-a.
	def := json.RawMessage(`{"action":"grant","subjects":["u1"],"resources":["app:db"],"role":"reader"}`)
	w := do(t, r, http.MethodPost, "/api/v1/policies", "tok-a", map[string]any{
		"name":       "p1",
		"definition": def,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create policy = %d, body=%s", w.Code, w.Body.String())
	}
	var created struct {
		Policy models.Policy `json:"policy"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	id := created.Policy.ID.String()

	// Promote without MFA → 403 (the MFA gate runs in middleware, before the
	// handler's test-before-rollout checks).
	w = do(t, r, http.MethodPost, "/api/v1/policies/"+id+"/promote", "tok-a", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("promote without MFA = %d, want 403", w.Code)
	}

	// Access policies must be simulated before they can be rolled out.
	w = do(t, r, http.MethodPost, "/api/v1/policies/"+id+"/simulate", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("simulate = %d, want 200, body=%s", w.Code, w.Body.String())
	}

	// Promote with MFA after simulation → 200.
	w = do(t, r, http.MethodPost, "/api/v1/policies/"+id+"/promote", "tok-a-mfa", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("promote with MFA = %d, want 200, body=%s", w.Code, w.Body.String())
	}
}

// TestOptionalBodyEndpointAcceptsNoContentLength proves an optional-body action
// (cancel) succeeds when the client sends no Content-Length header. Go reports
// ContentLength == -1 for such requests; bindOptional must treat that as "no
// body" rather than feeding an empty reader to ShouldBindJSON (which would EOF
// and 400). httptest.NewRequest with a *bytes.Buffer sets a real length, so this
// builds the request directly to exercise the -1 path.
func TestOptionalBodyEndpointAcceptsNoContentLength(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))

	// tenant-a creates a high-risk (parked, cancellable) request.
	w := do(t, r, http.MethodPost, "/api/v1/access-requests", "tok-a", map[string]any{
		"target_user_id": "ext-user",
		"resource_ref":   "app:db",
		"role":           "reader",
		"risk_level":     "high",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", w.Code, w.Body.String())
	}
	var created struct {
		Request models.AccessRequest `json:"request"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	id := created.Request.ID.String()

	// Bodyless POST with no Content-Length header (ContentLength == -1).
	req := httptest.NewRequest(http.MethodPost, "/api/v1/access-requests/"+id+"/cancel", http.NoBody)
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer tok-a")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cancel with no Content-Length = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

// TestOptionalBodyChunkedBodyIsBound proves bindOptional reads a body sent with
// ContentLength == -1 (chunked Transfer-Encoding) instead of silently dropping
// it. A Content-Length check would skip binding and never see the payload; the
// bind-and-treat-EOF-as-empty approach reads it, so a malformed chunked body is
// correctly rejected with 400 (proving the body reached the decoder).
func TestOptionalBodyChunkedBodyIsBound(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))

	w := do(t, r, http.MethodPost, "/api/v1/access-requests", "tok-a", map[string]any{
		"target_user_id": "ext-user",
		"resource_ref":   "app:db",
		"role":           "reader",
		"risk_level":     "high",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", w.Code, w.Body.String())
	}
	var created struct {
		Request models.AccessRequest `json:"request"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	id := created.Request.ID.String()

	// Malformed JSON sent with ContentLength == -1 (as a chunked client would).
	req := httptest.NewRequest(http.MethodPost, "/api/v1/access-requests/"+id+"/cancel", strings.NewReader("{ not json"))
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer tok-a")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("cancel with malformed chunked body = %d, want 400 (body must be read, not dropped), body=%s", rec.Code, rec.Body.String())
	}
}
