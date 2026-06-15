package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/services/tenancy"
	"github.com/kennguy3n/fishbone-access/internal/services/usage"
)

// fakeWorkspaceResolver maps any tenant to a fixed workspace (or returns nil to
// simulate "no workspace for tenant").
type fakeWorkspaceResolver struct{ ws uuid.UUID }

func (f fakeWorkspaceResolver) WorkspaceIDByTenant(context.Context, string) (uuid.UUID, error) {
	return f.ws, nil
}

// recordedActivity captures a tenancy.ActivityRecorder call.
type recordedActivity struct {
	ws   uuid.UUID
	kind string
}

type fakeRecorder struct {
	mu   sync.Mutex
	hits []recordedActivity
}

func (f *fakeRecorder) Record(ws uuid.UUID, kind string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits = append(f.hits, recordedActivity{ws: ws, kind: kind})
}

func (f *fakeRecorder) calls() []recordedActivity {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedActivity(nil), f.hits...)
}

// recordedUsage captures a usage.Meter call.
type recordedUsage struct {
	ws     uuid.UUID
	metric string
}

type fakeMeter struct {
	mu   sync.Mutex
	hits []recordedUsage
}

func (f *fakeMeter) Record(ws uuid.UUID, metric string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits = append(f.hits, recordedUsage{ws: ws, metric: metric})
}

func (f *fakeMeter) calls() []recordedUsage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedUsage(nil), f.hits...)
}

// newTestWebAccessHandlers builds a handler with the auth + recording seams
// wired but a nil bridge: every test below issues a plain (non-WebSocket) GET,
// so the recording fires at the authenticated handshake point and the upgrade
// then fails with a 400 before the bridge is ever touched.
func newTestWebAccessHandlers(ws uuid.UUID, rec tenancy.ActivityRecorder, m usage.Meter) (*webAccessHandlers, *gin.Engine) {
	h := &webAccessHandlers{
		validator: fakeValidator{claims: &iamcore.Claims{Subject: "alice", TenantID: "tenant-1"}},
		resolver:  fakeWorkspaceResolver{ws: ws},
		recorder:  rec,
		meter:     m,
	}
	r := gin.New()
	h.register(r)
	return h, r
}

func bearerRequest(method, target, token string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// TestServeRecordsActivityAndUsage proves an authenticated web-access handshake
// emits BOTH the dormancy activity signal and the per-session usage meter that
// the bypassed tenant-scoped middleware would otherwise have emitted — so a
// web-access-only tenant is neither wrongly hibernated nor invisible to billing.
func TestServeRecordsActivityAndUsage(t *testing.T) {
	ws := uuid.New()
	rec := &fakeRecorder{}
	meter := &fakeMeter{}
	_, r := newTestWebAccessHandlers(ws, rec, meter)

	for _, path := range []string{"/api/v1/webaccess/ssh", "/api/v1/webaccess/db"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, bearerRequest(http.MethodGet, path, "good-token"))
		// A plain GET cannot complete the WebSocket upgrade.
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: upgrade status = %d, want 400 (no WS handshake headers)", path, w.Code)
		}
	}

	activity := rec.calls()
	if len(activity) != 2 {
		t.Fatalf("activity records = %d, want 2 (one per handshake)", len(activity))
	}
	for _, a := range activity {
		if a.ws != ws {
			t.Fatalf("activity recorded for workspace %s, want %s", a.ws, ws)
		}
		if a.kind != tenancy.KindSession {
			t.Fatalf("activity kind = %q, want %q", a.kind, tenancy.KindSession)
		}
	}

	metered := meter.calls()
	if len(metered) != 2 {
		t.Fatalf("usage records = %d, want 2 (one per handshake)", len(metered))
	}
	for _, u := range metered {
		if u.ws != ws {
			t.Fatalf("usage metered for workspace %s, want %s", u.ws, ws)
		}
		if u.metric != usage.MetricWebAccessSessions {
			t.Fatalf("usage metric = %q, want %q", u.metric, usage.MetricWebAccessSessions)
		}
	}
}

// TestServeNoRecordWhenUnauthenticated proves the signals are gated on a fully
// authenticated, workspace-resolved handshake: a missing token (401) or a
// tenant with no workspace (403) records nothing, so the meter and the dormancy
// signal can never be driven for a request that never proved a tenant.
func TestServeNoRecordWhenUnauthenticated(t *testing.T) {
	t.Run("missing token", func(t *testing.T) {
		rec := &fakeRecorder{}
		meter := &fakeMeter{}
		_, r := newTestWebAccessHandlers(uuid.New(), rec, meter)

		w := httptest.NewRecorder()
		r.ServeHTTP(w, bearerRequest(http.MethodGet, "/api/v1/webaccess/ssh", ""))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if got := len(rec.calls()); got != 0 {
			t.Fatalf("activity records = %d, want 0", got)
		}
		if got := len(meter.calls()); got != 0 {
			t.Fatalf("usage records = %d, want 0", got)
		}
	})

	t.Run("no workspace for tenant", func(t *testing.T) {
		rec := &fakeRecorder{}
		meter := &fakeMeter{}
		// uuid.Nil from the resolver means "no workspace for tenant" (403).
		_, r := newTestWebAccessHandlers(uuid.Nil, rec, meter)

		w := httptest.NewRecorder()
		r.ServeHTTP(w, bearerRequest(http.MethodGet, "/api/v1/webaccess/ssh", "good-token"))
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
		if got := len(rec.calls()); got != 0 {
			t.Fatalf("activity records = %d, want 0", got)
		}
		if got := len(meter.calls()); got != 0 {
			t.Fatalf("usage records = %d, want 0", got)
		}
	})
}

// TestServeNilRecorderAndMeter proves the recording seams are optional: a
// degraded (no-DB) boot wires neither, and the handshake must still proceed to
// the upgrade attempt without panicking.
func TestServeNilRecorderAndMeter(t *testing.T) {
	_, r := newTestWebAccessHandlers(uuid.New(), nil, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, bearerRequest(http.MethodGet, "/api/v1/webaccess/ssh", "good-token"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (reached upgrade with nil recorder/meter)", w.Code)
	}
}
