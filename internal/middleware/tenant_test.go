package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
)

func TestResolveTenantClaimWins(t *testing.T) {
	v := fakeValidator{claims: &iamcore.Claims{Subject: "u", TenantID: "claim-tenant"}}
	r := newRouter(Auth(v), ResolveTenant())
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer good")
	req.Header.Set(TenantHeader, "claim-tenant")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestResolveTenantMismatch403(t *testing.T) {
	v := fakeValidator{claims: &iamcore.Claims{Subject: "u", TenantID: "claim-tenant"}}
	r := newRouter(Auth(v), ResolveTenant())
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer good")
	req.Header.Set(TenantHeader, "other-tenant")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 on tenant mismatch", w.Code)
	}
}

// TestResolveTenantHeaderOnlyRejected locks in the fail-closed fix: a token
// with no tenant_id claim must NOT be able to assume a tenant via a client-
// supplied X-Tenant-ID header. Accepting the header here would be a tenant-
// isolation bypass (any authenticated principal could act as any tenant).
func TestResolveTenantHeaderOnlyRejected(t *testing.T) {
	v := fakeValidator{claims: &iamcore.Claims{Subject: "u"}} // no tenant claim
	r := newRouter(Auth(v), ResolveTenant())
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer good")
	req.Header.Set(TenantHeader, "hdr-tenant")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for header-only tenant (no claim)", w.Code)
	}
}

func TestResolveTenantNoClaim403(t *testing.T) {
	v := fakeValidator{claims: &iamcore.Claims{Subject: "u"}}
	r := newRouter(Auth(v), ResolveTenant())
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer good")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 when token carries no tenant claim", w.Code)
	}
}
