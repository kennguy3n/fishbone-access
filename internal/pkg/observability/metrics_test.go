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

func TestRegisterDBPoolNilIsNoOp(t *testing.T) {
	if err := NewMetrics().RegisterDBPool(nil); err != nil {
		t.Fatalf("RegisterDBPool(nil) = %v, want nil", err)
	}
}
