package tenancy

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// captureRecorder records the (workspace, kind) pairs it was asked to record.
type captureRecorder struct {
	mu    sync.Mutex
	pairs []recordReq
}

func (c *captureRecorder) Record(ws uuid.UUID, kind string) {
	c.mu.Lock()
	c.pairs = append(c.pairs, recordReq{workspaceID: ws, kind: kind})
	c.mu.Unlock()
}

func (c *captureRecorder) calls() []recordReq {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]recordReq(nil), c.pairs...)
}

// withWorkspace simulates RequireTenant having resolved a workspace by setting
// the same gin context key (the production middleware runs before ours).
func withWorkspace(id uuid.UUID) gin.HandlerFunc {
	return func(c *gin.Context) {
		if id != uuid.Nil {
			c.Set("workspace_id", id)
		}
		c.Next()
	}
}

func newEngine(t *testing.T, rec ActivityRecorder, ws uuid.UUID) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(withWorkspace(ws), ActivityMiddleware(rec))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func do(t *testing.T, r *gin.Engine) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestActivityMiddlewareRecordsResolvedWorkspace(t *testing.T) {
	rec := &captureRecorder{}
	ws := uuid.New()
	do(t, newEngine(t, rec, ws))

	calls := rec.calls()
	if len(calls) != 1 {
		t.Fatalf("recorded %d times, want 1", len(calls))
	}
	if calls[0].workspaceID != ws || calls[0].kind != KindAPI {
		t.Errorf("recorded %+v, want {%s, api}", calls[0], ws)
	}
}

func TestActivityMiddlewareSkipsWhenNoWorkspace(t *testing.T) {
	rec := &captureRecorder{}
	do(t, newEngine(t, rec, uuid.Nil)) // no workspace resolved

	if got := len(rec.calls()); got != 0 {
		t.Fatalf("recorded %d times, want 0 (no workspace)", got)
	}
}

func TestActivityMiddlewareNilRecorderPassesThrough(t *testing.T) {
	// A nil recorder must not panic and must not block the request.
	do(t, newEngine(t, nil, uuid.New()))
}
