// Package observability provides the control plane's operational telemetry:
// Prometheus metrics (golden signals + saturation) exposed on /metrics. It is
// the minimum needed to run 5,000 tenants without flying blind — request
// rate/error/latency per route and database-pool saturation — without pulling
// in a heavyweight agent.
//
// Cardinality is the operative constraint at this tenant count: every label
// combination is a stored time series, so the HTTP instruments are labelled by
// the matched ROUTE TEMPLATE (e.g. /api/v1/policies/:id) and status, never the
// raw path or the tenant id. That keeps the series count bounded by the route
// table regardless of how many tenants or object ids flow through.
package observability

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics owns a private Prometheus registry and the HTTP request instruments.
// Build one with NewMetrics, share it with the router (Middleware + Handler),
// and register the database pool once it exists. A private registry (rather
// than the global default) avoids process-wide init singletons and makes the
// collectors unit-testable in isolation.
type Metrics struct {
	reg         *prometheus.Registry
	reqTotal    *prometheus.CounterVec
	reqDuration *prometheus.HistogramVec
	inFlight    prometheus.Gauge
	throttled   *prometheus.CounterVec
	usageEvents *prometheus.CounterVec
	failOpen    *prometheus.CounterVec

	// Hibernation (scale-to-zero) instruments. All are AGGREGATE — none is
	// labelled by tenant id — so the series count stays bounded at 5,000
	// tenants, mirroring the cardinality discipline of the usage counter above.
	hibernationDormant prometheus.Gauge
	hibernationSkipped *prometheus.CounterVec
	hibernationWakeups prometheus.Counter
}

// NewMetrics builds the registry pre-loaded with the Go runtime and process
// collectors plus the control plane's HTTP instruments.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	m := &Metrics{
		reg: reg,
		reqTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "shieldnet",
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total HTTP requests by method, matched route template and status code.",
		}, []string{"method", "route", "status"}),
		reqDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "shieldnet",
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "HTTP request latency in seconds by method, matched route template and status code.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"method", "route", "status"}),
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "shieldnet",
			Subsystem: "http",
			Name:      "requests_in_flight",
			Help:      "HTTP requests currently being served.",
		}),
		throttled: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "shieldnet",
			Subsystem: "http",
			Name:      "requests_throttled_total",
			Help:      "Requests rejected by the per-tenant rate limiter (429), by matched route template. Deliberately NOT labelled by tenant id, which is unbounded at 5,000 tenants.",
		}, []string{"route"}),
		usageEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "shieldnet",
			Subsystem: "usage",
			Name:      "events_total",
			Help:      "Metered usage events flushed to the per-tenant rollup, by metric (e.g. api_requests). This is the FLEET-WIDE aggregate: deliberately NOT labelled by tenant id (5,000 tenants would explode the series count) — per-tenant attribution lives in the tenant_usage table, read back through the authenticated usage endpoint.",
		}, []string{"metric"}),
		failOpen: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "shieldnet",
			Subsystem: "sharedstore",
			Name:      "fail_open_total",
			Help:      "Shared-store (Redis) operations that failed and were handled fail-open, by subsystem (ratelimit|usage). A non-zero rate means Redis is degraded: the rate limiter is admitting rather than enforcing, or usage is degrading to the Postgres path / dropping. Labelled by subsystem ONLY (never tenant id) to keep cardinality bounded; alert on its rate to catch a flapping Redis.",
		}, []string{"subsystem"}),
		hibernationDormant: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "shieldnet",
			Subsystem: "hibernation",
			Name:      "tenants_dormant",
			Help:      "Number of tenants currently classified dormant (fleet-wide), refreshed by the ztna-api reconcile sweep. This is the headline scale-to-zero signal: it should track the dormant-trial majority. Aggregate only — never labelled by tenant id.",
		}),
		hibernationSkipped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "shieldnet",
			Subsystem: "hibernation",
			Name:      "periodic_jobs_skipped_total",
			Help:      "Periodic per-tenant jobs skipped because the tenant is dormant, by worker (e.g. connector_sync, review_sweep). This is the realized cost saving — every increment is work a periodic worker did NOT do for a hibernated tenant. Labelled by the small fixed worker set only, never by tenant id.",
		}, []string{"worker"}),
		hibernationWakeups: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "shieldnet",
			Subsystem: "hibernation",
			Name:      "wake_events_total",
			Help:      "Lazy wake transitions (dormant->active) driven by real tenant activity on the request path. A healthy fleet wakes tenants promptly and rarely; a spike means dormant tenants are returning. Aggregate only — never labelled by tenant id.",
		}),
	}
	reg.MustRegister(m.reqTotal, m.reqDuration, m.inFlight, m.throttled, m.usageEvents, m.failOpen,
		m.hibernationDormant, m.hibernationSkipped, m.hibernationWakeups)
	return m
}

// IncThrottled records a request rejected by the per-tenant rate limiter,
// labelled by the matched route TEMPLATE only (never the tenant id, to keep the
// series count bounded). Wire it as the rate-limit middleware's onThrottle hook.
func (m *Metrics) IncThrottled(route string) {
	if route == "" {
		route = "unmatched"
	}
	m.throttled.WithLabelValues(route).Inc()
}

// AddUsageEvents records n metered usage events for the given metric, labelled
// by the metric name ONLY (a small fixed set such as "api_requests"), never the
// tenant id — keeping the series count bounded at 5,000 tenants. Wire it as the
// usage aggregator's flush observer so the fleet-wide counter advances by each
// successful flush's summed-across-tenants delta. A negative n is ignored.
func (m *Metrics) AddUsageEvents(metric string, n int64) {
	if metric == "" || n <= 0 {
		return
	}
	m.usageEvents.WithLabelValues(metric).Add(float64(n))
}

// SetDormantTenants publishes the current fleet-wide dormant tenant count as a
// gauge. Wire it as the reconcile loop's post-sweep observer so the headline
// scale-to-zero signal refreshes every sweep. A negative count is ignored
// (a count read failure should not stomp the last good value with garbage).
func (m *Metrics) SetDormantTenants(n int64) {
	if n < 0 {
		return
	}
	m.hibernationDormant.Set(float64(n))
}

// IncPeriodicJobSkipped records one periodic per-tenant job skipped because the
// tenant is dormant, labelled by the worker name ONLY (a small fixed set such
// as "connector_sync" / "review_sweep"), never the tenant id. Wire it where a
// worker honours the hibernation gate and decides to defer a tenant's work.
func (m *Metrics) IncPeriodicJobSkipped(worker string) {
	if worker == "" {
		worker = "unknown"
	}
	m.hibernationSkipped.WithLabelValues(worker).Inc()
}

// IncWakeEvents records one lazy wake (dormant->active) driven by real tenant
// activity. Wire it as the activity recorder's wake observer so the counter
// advances exactly once per wake (the recorder reports woke=true once per
// transition, not per request).
func (m *Metrics) IncWakeEvents() {
	m.hibernationWakeups.Inc()
}

// IncSharedStoreFailOpen records one shared-store (Redis) operation that failed
// and was handled fail-open, labelled by subsystem ("ratelimit" or "usage")
// only — never the tenant id, to keep cardinality bounded. Wire it as the
// OnError hook of the Redis-backed limiter and usage sink so a degraded Redis
// surfaces as a non-zero counter rate instead of being invisible.
func (m *Metrics) IncSharedStoreFailOpen(subsystem string) {
	if subsystem == "" {
		subsystem = "unknown"
	}
	m.failOpen.WithLabelValues(subsystem).Inc()
}

// Handler is the Prometheus scrape endpoint backed by this registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// Middleware records request count, latency and the in-flight gauge for every
// request. It labels by the matched route TEMPLATE (c.FullPath()), so an id in
// the URL never spawns a new series; unmatched routes collapse to "unmatched".
//
// The recording runs in a deferred closure so a request that panics is still
// counted. For the recorded status to reflect the 500 that gin.Recovery writes,
// this middleware must be mounted OUTSIDE Recovery (see NewRouter): Recovery
// then recovers and writes the status before control unwinds back here.
func (m *Metrics) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		m.inFlight.Inc()
		defer func() {
			m.inFlight.Dec()
			route := c.FullPath()
			if route == "" {
				route = "unmatched"
			}
			status := strconv.Itoa(c.Writer.Status())
			m.reqTotal.WithLabelValues(c.Request.Method, route, status).Inc()
			m.reqDuration.WithLabelValues(c.Request.Method, route, status).
				Observe(time.Since(start).Seconds())
		}()

		c.Next()
	}
}

// RegisterDBPool exposes the connection pool's sql.DBStats (open/idle/in-use
// connections, wait count and wait duration) — the saturation signal that
// surfaces a pool exhausted by a noisy tenant before it becomes an outage. A
// nil pool is a no-op; call it once with the shared control-plane pool.
func (m *Metrics) RegisterDBPool(db *sql.DB) error {
	if db == nil {
		return nil
	}
	return m.reg.Register(collectors.NewDBStatsCollector(db, "controlplane"))
}
