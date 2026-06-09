package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
)

func TestHasPermission(t *testing.T) {
	cases := []struct {
		name     string
		scopes   []string
		required string
		want     bool
	}{
		{"exact", []string{"compliance.export"}, "compliance.export", true},
		{"global", []string{"*"}, "compliance.export", true},
		{"prefix wildcard", []string{"compliance.*"}, "compliance.export", true},
		{"prefix wildcard no match", []string{"campaigns.*"}, "compliance.export", false},
		{"unrelated scope", []string{"access.read"}, "compliance.export", false},
		{"empty scopes", nil, "compliance.export", false},
		{"empty requirement fails closed", []string{"*"}, "", false},
		// A bare prefix without the dot must NOT grant a sibling-prefixed scope.
		{"prefix must keep dot", []string{"compliance.*"}, "compliancex.export", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasPermission(tc.scopes, tc.required); got != tc.want {
				t.Fatalf("hasPermission(%v, %q) = %v, want %v", tc.scopes, tc.required, got, tc.want)
			}
		})
	}
}

// serveWithClaims runs the RequirePermission middleware with the given claims
// pre-seeded into the context (as Auth would), returning the recorded status.
func serveWithClaims(t *testing.T, claims *iamcore.Claims, required string) int {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/x", func(c *gin.Context) {
		if claims != nil {
			c.Set(ctxKeyClaims, claims)
		}
		RequirePermission(required)(c)
		if !c.IsAborted() {
			c.Status(http.StatusOK)
		}
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	return w.Code
}

func TestRequirePermissionFailsClosed(t *testing.T) {
	// No claims at all -> 401.
	if code := serveWithClaims(t, nil, "compliance.export"); code != http.StatusUnauthorized {
		t.Fatalf("missing claims: got %d, want 401", code)
	}
	// Authenticated but missing scope -> 403.
	if code := serveWithClaims(t, &iamcore.Claims{Subject: "u", Scopes: []string{"access.read"}}, "compliance.export"); code != http.StatusForbidden {
		t.Fatalf("insufficient scope: got %d, want 403", code)
	}
	// Authenticated with the scope -> pass.
	if code := serveWithClaims(t, &iamcore.Claims{Subject: "u", Scopes: []string{"compliance.export"}}, "compliance.export"); code != http.StatusOK {
		t.Fatalf("sufficient scope: got %d, want 200", code)
	}
}
