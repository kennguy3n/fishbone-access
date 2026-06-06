package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
)

type fakeValidator struct {
	claims *iamcore.Claims
	err    error
}

func (f fakeValidator) Validate(string) (*iamcore.Claims, error) {
	return f.claims, f.err
}

func init() { gin.SetMode(gin.TestMode) }

func newRouter(mws ...gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.Use(mws...)
	r.GET("/x", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"tenant": TenantFromContext(c),
		})
	})
	return r
}

func TestAuthRejectsMissingToken(t *testing.T) {
	r := newRouter(Auth(fakeValidator{claims: &iamcore.Claims{Subject: "u"}}))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestAuthRejectsInvalidToken(t *testing.T) {
	r := newRouter(Auth(fakeValidator{err: errors.New("bad")}))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer xyz")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestAuthAcceptsValidToken(t *testing.T) {
	v := fakeValidator{claims: &iamcore.Claims{Subject: "u", TenantID: "t1"}}
	r := newRouter(Auth(v), ResolveTenant())
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer good")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestRequireMFA(t *testing.T) {
	// No MFA → 403.
	v := fakeValidator{claims: &iamcore.Claims{Subject: "u", TenantID: "t1", MFASatisfied: false}}
	r := newRouter(Auth(v), RequireMFA())
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer good")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 when MFA not satisfied", w.Code)
	}

	// MFA satisfied → 200.
	v2 := fakeValidator{claims: &iamcore.Claims{Subject: "u", TenantID: "t1", MFASatisfied: true}}
	r2 := newRouter(Auth(v2), RequireMFA())
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req2.Header.Set("Authorization", "Bearer good")
	r2.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 when MFA satisfied", w2.Code)
	}
}
