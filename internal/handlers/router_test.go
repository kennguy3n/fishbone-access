package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

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

// TestWhoamiNilClaimsFailsClosed exercises whoami directly with no claims in
// context (simulating a future reorder that mounts it without Auth). It must
// return 401, not panic on a nil-claims dereference.
func TestWhoamiNilClaimsFailsClosed(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)

	whoami(c) // must not panic

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("whoami with nil claims = %d, want 401", w.Code)
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

type stubLimiter struct {
	allow bool
	keys  []string
}

func (s *stubLimiter) Allow(key string) (bool, time.Duration) {
	s.keys = append(s.keys, key)
	return s.allow, time.Second
}

// TestRateLimiterWiredOnAuthenticatedSurface proves the limiter is mounted on
// the authenticated /api/v1 group, keyed by the resolved tenant id, and returns
// 429 when the tenant is over budget.
func TestRateLimiterWiredOnAuthenticatedSurface(t *testing.T) {
	v := fakeValidator{claims: &iamcore.Claims{Subject: "u", TenantID: "tenant-1"}}

	blocked := &stubLimiter{allow: false}
	r := NewRouter(Deps{Validator: v, RateLimiter: blocked})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer token")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over-budget status = %d, want 429; body=%s", w.Code, w.Body.String())
	}
	if len(blocked.keys) != 1 || blocked.keys[0] != "tenant-1" {
		t.Fatalf("limiter keyed by %v, want [tenant-1] (the resolved tenant)", blocked.keys)
	}

	allowed := &stubLimiter{allow: true}
	r2 := NewRouter(Deps{Validator: v, RateLimiter: allowed})
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req2.Header.Set("Authorization", "Bearer token")
	r2.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("under-budget status = %d, want 200", w2.Code)
	}
}

// TestRateLimiterNotMountedInDegradedMode ensures the limiter never runs on the
// degraded (no-validator) path: that surface already 503s, and the limiter must
// not be consulted without a resolved tenant.
func TestRateLimiterNotMountedInDegradedMode(t *testing.T) {
	blocked := &stubLimiter{allow: false}
	r := NewRouter(Deps{Validator: nil, RateLimiter: blocked})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/me", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("degraded status = %d, want 503", w.Code)
	}
	if len(blocked.keys) != 0 {
		t.Fatalf("limiter consulted in degraded mode (keys=%v); it must not be", blocked.keys)
	}
}
