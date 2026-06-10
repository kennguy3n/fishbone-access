package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/gin-gonic/gin"
)

// withAssets installs an in-memory SPA tree for the duration of a test and
// restores the previous (nil) Assets afterwards, so these tests exercise the
// serving logic without the embed_ui build tag.
func withAssets(t *testing.T) {
	t.Helper()
	prev := Assets
	Assets = fstest.MapFS{
		"index.html":    {Data: []byte("<!doctype html><title>app</title>")},
		"assets/app.js": {Data: []byte("console.log(1)")},
		"config.js":     {Data: []byte("window.__SNG_CONFIG__={}")},
	}
	t.Cleanup(func() { Assets = prev })
}

func newEngine() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	Register(r)
	return r
}

func get(t *testing.T, r *gin.Engine, target string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
	return w
}

func TestServeIndexCarriesNoCache(t *testing.T) {
	withAssets(t)
	r := newEngine()

	// Both a deep-link (SPA fallback) and a direct /index.html request must
	// return the shell with Cache-Control: no-cache, so a stale shell can't
	// pin clients to content-hashed bundles that 404 after a deploy.
	for _, target := range []string{"/", "/policies/abc", "/index.html"} {
		w := get(t, r, target)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", target, w.Code)
		}
		if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
			t.Errorf("%s: Cache-Control = %q, want %q", target, cc, "no-cache")
		}
		if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Errorf("%s: Content-Type = %q, want html", target, ct)
		}
	}
}

func TestServeRealAsset(t *testing.T) {
	withAssets(t)
	r := newEngine()

	w := get(t, r, "/assets/app.js")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if w.Body.String() != "console.log(1)" {
		t.Errorf("body = %q, want the asset contents", w.Body.String())
	}
	// Content-hashed assets under /assets/ are served immutable so browsers
	// can cache them indefinitely instead of revalidating on every load.
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("asset Cache-Control = %q, want immutable long-lived caching", cc)
	}
}

func TestServeConfigJSCarriesNoCache(t *testing.T) {
	withAssets(t)
	r := newEngine()

	// config.js is the runtime-overridable config asset: it must be served with
	// its real bytes (not the SPA shell) AND with Cache-Control: no-cache, so a
	// deploy that rewrites it isn't shadowed by a stale browser-cached copy.
	w := get(t, r, "/config.js")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if w.Body.String() != "window.__SNG_CONFIG__={}" {
		t.Errorf("body = %q, want the config.js contents", w.Body.String())
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("config.js Cache-Control = %q, want %q", cc, "no-cache")
	}
}

func TestReservedPathsNotShadowed(t *testing.T) {
	withAssets(t)
	r := newEngine()

	// /api (bare), /api/* , /health and /readyz must 404 from the SPA fallback
	// rather than returning the HTML shell.
	for _, target := range []string{"/api", "/api/v1/policies", "/health", "/readyz"} {
		w := get(t, r, target)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", target, w.Code)
		}
		if ct := w.Header().Get("Content-Type"); ct == "text/html; charset=utf-8" {
			t.Errorf("%s: served HTML shell, want JSON 404", target)
		}
	}
}

func TestNonGetIsNotFound(t *testing.T) {
	withAssets(t)
	r := newEngine()

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/anything", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("POST status = %d, want 404", w.Code)
	}
}

func TestRegisterNoopWhenDisabled(t *testing.T) {
	prev := Assets
	Assets = nil
	t.Cleanup(func() { Assets = prev })

	r := gin.New()
	Register(r) // must not panic and must not install a NoRoute handler
	w := get(t, r, "/")
	if w.Code != http.StatusNotFound {
		t.Errorf("disabled: status = %d, want 404 (gin default)", w.Code)
	}
	var _ = Assets
}
