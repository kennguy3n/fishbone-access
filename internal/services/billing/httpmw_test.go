package billing

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func init() { gin.SetMode(gin.TestMode) }

// ctxKeyWorkspaceID mirrors middleware.RequireTenant's context key so the
// middleware unit test can seed a resolved workspace without the whole auth
// chain (the handlers router test exercises the real RequireTenant path).
const ctxKeyWorkspaceID = "workspace_id"

// fakeEnforcer returns a fixed decision/error and records how many times it was
// asked, so a test can assert fail-open paths never deny.
type fakeEnforcer struct {
	decision QuotaDecision
	err      error
	calls    int
}

func (f *fakeEnforcer) Decide(_ context.Context, _ uuid.UUID) (QuotaDecision, error) {
	f.calls++
	return f.decision, f.err
}

// run mounts QuotaMiddleware on a one-route router and returns the recorder plus
// whether the terminal handler ran and the captured onDecision args.
func run(t *testing.T, enforcer QuotaEnforcer, seedWorkspace bool) (*httptest.ResponseRecorder, bool, []string) {
	t.Helper()
	var handlerRan bool
	var decisions []string
	r := gin.New()
	if seedWorkspace {
		ws := uuid.New()
		r.Use(func(c *gin.Context) { c.Set(ctxKeyWorkspaceID, ws) })
	}
	r.Use(QuotaMiddleware(enforcer, func(state, route string) {
		decisions = append(decisions, state+" "+route)
	}))
	r.GET("/api/v1/thing", func(c *gin.Context) {
		handlerRan = true
		c.Status(http.StatusOK)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/thing", nil))
	return w, handlerRan, decisions
}

// TestMiddlewareNilEnforcerPassThrough proves a nil enforcer is transparent
// (fail-open), so the router can mount it unconditionally when billing is off.
func TestMiddlewareNilEnforcerPassThrough(t *testing.T) {
	w, ran, decisions := run(t, nil, true)
	if w.Code != http.StatusOK || !ran {
		t.Fatalf("nil enforcer should pass through: code=%d ran=%v", w.Code, ran)
	}
	if len(decisions) != 0 {
		t.Errorf("nil enforcer should not flag decisions: %v", decisions)
	}
}

// TestMiddlewareNoWorkspacePassThrough proves an unkeyed request (no resolved
// tenant) proceeds untouched rather than erroring.
func TestMiddlewareNoWorkspacePassThrough(t *testing.T) {
	enf := &fakeEnforcer{decision: QuotaDecision{State: QuotaHardExceeded, Deny: true}}
	w, ran, _ := run(t, enf, false) // no workspace seeded
	if w.Code != http.StatusOK || !ran {
		t.Fatalf("missing workspace should pass through: code=%d ran=%v", w.Code, ran)
	}
	if enf.calls != 0 {
		t.Errorf("enforcer should not be consulted without a workspace, calls=%d", enf.calls)
	}
}

// TestMiddlewareFailOpenOnError proves a lookup error allows the request — a
// billing outage degrades to "no enforcement", never a denied request.
func TestMiddlewareFailOpenOnError(t *testing.T) {
	enf := &fakeEnforcer{err: errors.New("boom")}
	w, ran, decisions := run(t, enf, true)
	if w.Code != http.StatusOK || !ran {
		t.Fatalf("error should fail open: code=%d ran=%v", w.Code, ran)
	}
	if len(decisions) != 0 {
		t.Errorf("error path should not flag a decision: %v", decisions)
	}
	if w.Header().Get(HeaderQuotaState) != "" {
		t.Error("error path should set no quota headers")
	}
}

// TestMiddlewareOKProceedsSilently proves a within-quota decision proceeds with
// no headers and no flag.
func TestMiddlewareOKProceedsSilently(t *testing.T) {
	enf := &fakeEnforcer{decision: QuotaDecision{State: QuotaOK}}
	w, ran, decisions := run(t, enf, true)
	if w.Code != http.StatusOK || !ran {
		t.Fatalf("ok should proceed: code=%d ran=%v", w.Code, ran)
	}
	if w.Header().Get(HeaderQuotaState) != "" || len(decisions) != 0 {
		t.Error("ok decision should set no headers and flag nothing")
	}
}

// TestMiddlewareSoftFlagsButAllows proves a soft-exceeded decision sets the
// quota headers, flags the breach (with the route TEMPLATE, not an id), and
// still allows the request.
func TestMiddlewareSoftFlagsButAllows(t *testing.T) {
	enf := &fakeEnforcer{decision: QuotaDecision{State: QuotaSoftExceeded, Metric: "api_requests"}}
	w, ran, decisions := run(t, enf, true)
	if w.Code != http.StatusOK || !ran {
		t.Fatalf("soft should allow: code=%d ran=%v", w.Code, ran)
	}
	if w.Header().Get(HeaderQuotaState) != "soft_exceeded" || w.Header().Get(HeaderQuotaMetric) != "api_requests" {
		t.Errorf("soft headers wrong: state=%q metric=%q", w.Header().Get(HeaderQuotaState), w.Header().Get(HeaderQuotaMetric))
	}
	if len(decisions) != 1 || decisions[0] != "soft_exceeded /api/v1/thing" {
		t.Errorf("onDecision = %v, want [soft_exceeded /api/v1/thing]", decisions)
	}
}

// TestMiddlewareHardDenies proves an enforced hard-exceeded decision rejects
// with 402 BEFORE the handler runs, sets the headers, and flags the breach.
func TestMiddlewareHardDenies(t *testing.T) {
	enf := &fakeEnforcer{decision: QuotaDecision{
		State: QuotaHardExceeded, Deny: true, Metric: "api_requests", Plan: "base", Used: 3, HardCap: 2,
	}}
	w, ran, decisions := run(t, enf, true)
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("hard+enforce should be 402, got %d", w.Code)
	}
	if ran {
		t.Error("handler must NOT run when hard-denied (rejected before expensive work)")
	}
	if w.Header().Get(HeaderQuotaState) != "hard_exceeded" {
		t.Errorf("hard header state = %q, want hard_exceeded", w.Header().Get(HeaderQuotaState))
	}
	if len(decisions) != 1 || decisions[0] != "hard_exceeded /api/v1/thing" {
		t.Errorf("onDecision = %v, want [hard_exceeded /api/v1/thing]", decisions)
	}
}

// TestMiddlewareHardShadowAllows proves a hard-exceeded decision with
// enforcement OFF (Deny=false) is treated like soft: headers + flag, but the
// request proceeds — the shadow rollout posture.
func TestMiddlewareHardShadowAllows(t *testing.T) {
	enf := &fakeEnforcer{decision: QuotaDecision{State: QuotaHardExceeded, Deny: false, Metric: "api_requests"}}
	w, ran, decisions := run(t, enf, true)
	if w.Code != http.StatusOK || !ran {
		t.Fatalf("hard-shadow should allow: code=%d ran=%v", w.Code, ran)
	}
	if w.Header().Get(HeaderQuotaState) != "hard_exceeded" {
		t.Errorf("shadow header state = %q, want hard_exceeded", w.Header().Get(HeaderQuotaState))
	}
	if len(decisions) != 1 {
		t.Errorf("shadow should still flag: %v", decisions)
	}
}
