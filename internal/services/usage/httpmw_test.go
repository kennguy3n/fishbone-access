package usage

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func init() { gin.SetMode(gin.TestMode) }

// ctxKeyWorkspaceID mirrors middleware.RequireTenant's context key (an
// unexported string const there). Pinning it here lets the middleware unit test
// seed a resolved workspace without standing up the whole auth chain; the
// handlers router test exercises the real RequireTenant path end-to-end.
const ctxKeyWorkspaceID = "workspace_id"

type fakeMeter struct{ records []uuid.UUID }

func (f *fakeMeter) Record(workspaceID uuid.UUID, _ string) {
	f.records = append(f.records, workspaceID)
}

// TestMiddlewareMetersResolvedWorkspace proves the middleware records exactly
// one count, keyed by the resolved workspace UUID, when one is present.
func TestMiddlewareMetersResolvedWorkspace(t *testing.T) {
	m := &fakeMeter{}
	ws := uuid.New()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/anything", nil)
	c.Set(ctxKeyWorkspaceID, ws)

	Middleware(m)(c)

	if len(m.records) != 1 || m.records[0] != ws {
		t.Fatalf("recorded %v, want exactly [%s]", m.records, ws)
	}
}

// TestMiddlewareNilMeterIsPassThrough proves a nil meter is a transparent
// pass-through (fail-open), so the router can mount it unconditionally.
func TestMiddlewareNilMeterIsPassThrough(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/anything", nil)
	c.Set(ctxKeyWorkspaceID, uuid.New())

	// Must not panic; the request simply proceeds unmetered.
	Middleware(nil)(c)
}

// TestMiddlewareNoWorkspaceFailsOpen proves that with no resolved workspace
// (e.g. a route mistakenly mounted before RequireTenant) the middleware records
// nothing rather than attributing usage to a bogus tenant — fail-open, exactly
// like the rate-limit middleware.
func TestMiddlewareNoWorkspaceFailsOpen(t *testing.T) {
	m := &fakeMeter{}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/anything", nil)
	// No workspace set in context.

	Middleware(m)(c)

	if len(m.records) != 0 {
		t.Fatalf("recorded %v, want nothing (no resolved workspace)", m.records)
	}
}
