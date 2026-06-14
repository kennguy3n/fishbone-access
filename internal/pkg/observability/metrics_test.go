package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func newTestEngine(m *Metrics) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(m.Middleware())
	r.GET("/metrics", gin.WrapH(m.Handler()))
	r.GET("/things/:id", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/boom", func(c *gin.Context) { c.Status(http.StatusInternalServerError) })
	return r
}

func do(t *testing.T, r http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}

func TestMiddlewareRecordsByRouteTemplate(t *testing.T) {
	m := NewMetrics()
	r := newTestEngine(m)

	// Two requests to the same parameterised route with DIFFERENT ids must
	// collapse to one series keyed on the template — proving the id can't blow
	// up cardinality across many tenants/objects.
	do(t, r, http.MethodGet, "/things/abc")
	do(t, r, http.MethodGet, "/things/xyz")
	do(t, r, http.MethodGet, "/boom")

	body := do(t, r, http.MethodGet, "/metrics").Body.String()

	wantCounter := `shieldnet_http_requests_total{method="GET",route="/things/:id",status="200"} 2`
	if !strings.Contains(body, wantCounter) {
		t.Errorf("metrics missing %q\n--- scrape ---\n%s", wantCounter, body)
	}
	want500 := `shieldnet_http_requests_total{method="GET",route="/boom",status="500"} 1`
	if !strings.Contains(body, want500) {
		t.Errorf("metrics missing %q", want500)
	}
	for _, want := range []string{
		"shieldnet_http_request_duration_seconds_bucket",
		"shieldnet_http_requests_in_flight",
		"go_goroutines",              // Go runtime collector
		"process_start_time_seconds", // process collector
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics scrape missing series %q", want)
		}
	}
}

func TestMiddlewareUnmatchedRouteLabel(t *testing.T) {
	m := NewMetrics()
	r := newTestEngine(m)

	do(t, r, http.MethodGet, "/no/such/route") // 404, no FullPath
	body := do(t, r, http.MethodGet, "/metrics").Body.String()

	if !strings.Contains(body, `route="unmatched"`) {
		t.Errorf("unmatched request should be labelled route=\"unmatched\"\n%s", body)
	}
}

// TestMiddlewareCountsPanicRecoveredRequests mirrors NewRouter's ordering —
// metrics middleware OUTSIDE gin.Recovery — and proves a handler panic is still
// recorded with the 500 status Recovery writes, so a burst of panics shows up
// in the error-rate golden signal instead of vanishing.
func TestMiddlewareCountsPanicRecoveredRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := NewMetrics()
	r := gin.New()
	r.Use(m.Middleware()) // outermost, exactly as NewRouter mounts it
	r.Use(gin.Recovery())
	r.GET("/metrics", gin.WrapH(m.Handler()))
	r.GET("/panic", func(c *gin.Context) { panic("boom") })

	do(t, r, http.MethodGet, "/panic")
	body := do(t, r, http.MethodGet, "/metrics").Body.String()

	want := `shieldnet_http_requests_total{method="GET",route="/panic",status="500"} 1`
	if !strings.Contains(body, want) {
		t.Errorf("panic-recovered request not counted; missing %q\n--- scrape ---\n%s", want, body)
	}
}

func TestRegisterDBPoolNilIsNoOp(t *testing.T) {
	if err := NewMetrics().RegisterDBPool(nil); err != nil {
		t.Fatalf("RegisterDBPool(nil) = %v, want nil", err)
	}
}

func TestIncThrottledByRouteTemplate(t *testing.T) {
	m := NewMetrics()
	r := newTestEngine(m)

	m.IncThrottled("/things/:id")
	m.IncThrottled("/things/:id")
	m.IncThrottled("") // empty route collapses to "unmatched"

	body := do(t, r, http.MethodGet, "/metrics").Body.String()
	if want := `shieldnet_http_requests_throttled_total{route="/things/:id"} 2`; !strings.Contains(body, want) {
		t.Errorf("metrics missing %q\n--- scrape ---\n%s", want, body)
	}
	if want := `shieldnet_http_requests_throttled_total{route="unmatched"} 1`; !strings.Contains(body, want) {
		t.Errorf("metrics missing %q", want)
	}
}

func TestHibernationMetricsExposeAggregates(t *testing.T) {
	m := NewMetrics()
	r := newTestEngine(m)

	m.SetDormantTenants(4200)
	m.SetDormantTenants(-1) // negative is ignored: must not stomp the last good value
	m.IncPeriodicJobSkipped("connector_sync")
	m.IncPeriodicJobSkipped("connector_sync")
	m.IncPeriodicJobSkipped("review_sweep")
	m.IncPeriodicJobSkipped("") // empty worker collapses to "unknown"
	m.IncWakeEvents()
	m.IncWakeEvents()
	m.IncWakeEvents()

	body := do(t, r, http.MethodGet, "/metrics").Body.String()
	for _, want := range []string{
		`shieldnet_hibernation_tenants_dormant 4200`,
		`shieldnet_hibernation_periodic_jobs_skipped_total{worker="connector_sync"} 2`,
		`shieldnet_hibernation_periodic_jobs_skipped_total{worker="review_sweep"} 1`,
		`shieldnet_hibernation_periodic_jobs_skipped_total{worker="unknown"} 1`,
		`shieldnet_hibernation_wake_events_total 3`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q\n--- scrape ---\n%s", want, body)
		}
	}
}
