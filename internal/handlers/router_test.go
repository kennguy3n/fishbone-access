package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
)

type fakeValidator struct{ claims *iamcore.Claims }

func (f fakeValidator) Validate(string) (*iamcore.Claims, error) { return f.claims, nil }

func init() { gin.SetMode(gin.TestMode) }

func TestHealthAlwaysOK(t *testing.T) {
	r := NewRouter(Deps{})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("health status = %d", w.Code)
	}
}

func TestReadyzReflectsFlag(t *testing.T) {
	ready := &atomic.Bool{}
	r := NewRouter(Deps{Ready: ready})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz before ready = %d, want 503", w.Code)
	}

	ready.Store(true)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("readyz after ready = %d, want 200", w2.Code)
	}
}

func TestDegradedWhenNoValidator(t *testing.T) {
	r := NewRouter(Deps{Validator: nil})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/me", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 in degraded mode", w.Code)
	}
}

func TestWhoamiWithValidator(t *testing.T) {
	v := fakeValidator{claims: &iamcore.Claims{Subject: "user-1", TenantID: "tenant-1", Roles: []string{"admin"}, MFASatisfied: true}}
	r := NewRouter(Deps{Validator: v})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer token")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var body struct {
		UserID   string `json:"user_id"`
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.UserID != "user-1" || body.TenantID != "tenant-1" {
		t.Fatalf("whoami body = %+v", body)
	}
}

func TestListProvidersUnauthenticated(t *testing.T) {
	r := NewRouter(Deps{})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/connectors/providers", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}
