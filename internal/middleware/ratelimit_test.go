package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

type fakeLimiter struct {
	allow bool
	retry time.Duration

	mu   sync.Mutex
	keys []string
}

func (f *fakeLimiter) Allow(key string) (bool, time.Duration) {
	f.mu.Lock()
	f.keys = append(f.keys, key)
	f.mu.Unlock()
	return f.allow, f.retry
}

func (f *fakeLimiter) seenKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.keys...)
}

// setTenant injects a resolved tenant id the way ResolveTenant would, so the
// rate-limit middleware downstream has a key.
func setTenant(tenant string) gin.HandlerFunc {
	return func(c *gin.Context) { c.Set(ctxKeyTenantID, tenant) }
}

func TestRateLimitAllowsUnderLimit(t *testing.T) {
	lim := &fakeLimiter{allow: true}
	r := newRouter(setTenant("tenant-a"), RateLimit(lim, nil))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := lim.seenKeys(); len(got) != 1 || got[0] != "tenant-a" {
		t.Fatalf("limiter keyed by %v, want [tenant-a]", got)
	}
}

func TestRateLimitBlocksOverLimit(t *testing.T) {
	lim := &fakeLimiter{allow: false, retry: 1500 * time.Millisecond}
	var throttledRoutes []string
	onThrottle := func(route string) { throttledRoutes = append(throttledRoutes, route) }
	r := newRouter(setTenant("tenant-a"), RateLimit(lim, onThrottle))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	// 1.5s rounds UP to 2s.
	if ra := w.Header().Get("Retry-After"); ra != "2" {
		t.Fatalf("Retry-After = %q, want \"2\"", ra)
	}
	if len(throttledRoutes) != 1 || throttledRoutes[0] != "/x" {
		t.Fatalf("onThrottle routes = %v, want [/x] (route template, not tenant id)", throttledRoutes)
	}
}

func TestRateLimitNilLimiterFailsOpen(t *testing.T) {
	r := newRouter(setTenant("tenant-a"), RateLimit(nil, nil))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (nil limiter must fail open)", w.Code)
	}
}

func TestRateLimitNoTenantFailsOpen(t *testing.T) {
	lim := &fakeLimiter{allow: false} // would block if consulted
	r := newRouter(RateLimit(lim, nil))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no resolved tenant must fail open)", w.Code)
	}
	if got := lim.seenKeys(); len(got) != 0 {
		t.Fatalf("limiter should not be consulted without a tenant, saw keys %v", got)
	}
}

func TestRateLimitNoRetryAfterWhenZeroDelay(t *testing.T) {
	lim := &fakeLimiter{allow: false, retry: 0}
	r := newRouter(setTenant("t"), RateLimit(lim, nil))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	if ra := w.Header().Get("Retry-After"); ra != "" {
		t.Fatalf("Retry-After = %q, want unset for a non-positive delay", ra)
	}
}
