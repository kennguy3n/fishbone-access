package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/services/mfa"
)

// fakeStepUpVerifier records the arguments of the last VerifyStepUp call and
// returns a fixed result, so the middleware's fail-closed behaviour and
// error→status mapping can be exercised without real crypto.
type fakeStepUpVerifier struct {
	err error

	calls        int
	gotWS        uuid.UUID
	gotUser      string
	gotScope     string
	gotAssertion string
}

func (f *fakeStepUpVerifier) VerifyStepUp(_ context.Context, ws uuid.UUID, user, scope string, assertion []byte) error {
	f.calls++
	f.gotWS, f.gotUser, f.gotScope, f.gotAssertion = ws, user, scope, string(assertion)
	return f.err
}

// stepUpRouter mounts a context-seeding middleware (claims + workspace) followed
// by RequireStepUpMFA. seedClaims/seedWS control what the gate sees, mirroring
// the production chain Auth → RequireTenant → RequireStepUpMFA.
func stepUpRouter(verifier mfa.MFAVerifier, scope string, seedClaims *iamcore.Claims, seedWS *uuid.UUID) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if seedClaims != nil {
			c.Set(ctxKeyClaims, seedClaims)
		}
		if seedWS != nil {
			c.Set(ctxKeyWorkspaceID, *seedWS)
		}
		c.Next()
	})
	r.POST("/promote", RequireStepUpMFA(verifier, scope), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func stepUpRequest(t *testing.T, r http.Handler, assertion string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/promote", nil)
	if assertion != "" {
		req.Header.Set(StepUpAssertionHeader, assertion)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestRequireStepUpMFA_Success(t *testing.T) {
	ws := uuid.New()
	fv := &fakeStepUpVerifier{err: nil}
	r := stepUpRouter(fv, "policy.promote", &iamcore.Claims{Subject: "user-a"}, &ws)

	w := stepUpRequest(t, r, "123456")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	if fv.calls != 1 || fv.gotWS != ws || fv.gotUser != "user-a" || fv.gotScope != "policy.promote" || fv.gotAssertion != "123456" {
		t.Fatalf("verifier args = %+v", fv)
	}
}

func TestRequireStepUpMFA_NoClaims401(t *testing.T) {
	ws := uuid.New()
	fv := &fakeStepUpVerifier{}
	r := stepUpRouter(fv, "policy.promote", nil, &ws)
	if w := stepUpRequest(t, r, "123456"); w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if fv.calls != 0 {
		t.Fatal("verifier must not be called without claims")
	}
}

func TestRequireStepUpMFA_EmptySubject401(t *testing.T) {
	ws := uuid.New()
	fv := &fakeStepUpVerifier{}
	r := stepUpRouter(fv, "policy.promote", &iamcore.Claims{Subject: ""}, &ws)
	if w := stepUpRequest(t, r, "123456"); w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestRequireStepUpMFA_NoWorkspace403(t *testing.T) {
	fv := &fakeStepUpVerifier{}
	r := stepUpRouter(fv, "policy.promote", &iamcore.Claims{Subject: "user-a"}, nil)
	if w := stepUpRequest(t, r, "123456"); w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if fv.calls != 0 {
		t.Fatal("verifier must not be called without a workspace")
	}
}

func TestRequireStepUpMFA_NilVerifier503(t *testing.T) {
	ws := uuid.New()
	// An explicitly-nil verifier must fail closed (503), never skip the gate.
	r := stepUpRouter(nil, "policy.promote", &iamcore.Claims{Subject: "user-a"}, &ws)
	if w := stepUpRequest(t, r, "123456"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestRequireStepUpMFA_NoAssertion400(t *testing.T) {
	ws := uuid.New()
	fv := &fakeStepUpVerifier{}
	r := stepUpRouter(fv, "policy.promote", &iamcore.Claims{Subject: "user-a"}, &ws)
	if w := stepUpRequest(t, r, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if fv.calls != 0 {
		t.Fatal("verifier must not be called without an assertion header")
	}
}

func TestRequireStepUpMFA_Failed403(t *testing.T) {
	ws := uuid.New()
	fv := &fakeStepUpVerifier{err: mfa.ErrMFAFailed}
	r := stepUpRouter(fv, "policy.promote", &iamcore.Claims{Subject: "user-a"}, &ws)
	if w := stepUpRequest(t, r, "bad"); w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestRequireStepUpMFA_VerifierError503(t *testing.T) {
	ws := uuid.New()
	fv := &fakeStepUpVerifier{err: errors.New("db down")}
	r := stepUpRouter(fv, "policy.promote", &iamcore.Claims{Subject: "user-a"}, &ws)
	// A non-ErrMFAFailed error is an availability problem, not a denial: 503.
	if w := stepUpRequest(t, r, "123456"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}
