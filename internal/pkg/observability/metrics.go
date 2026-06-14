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
	}
	reg.MustRegister(m.reqTotal, m.reqDuration, m.inFlight)
	return m
}

// Handler is the Prometheus scrape endpoint backed by this registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// Middleware records request count, latency and the in-flight gauge for every
// request. It labels by the matched route TEMPLATE (c.FullPath()), so an id in
// the URL never spawns a new series; unmatched routes collapse to "unmatched".
func (m *Metrics) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		m.inFlight.Inc()
		defer m.inFlight.Dec()

		c.Next()

		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		status := strconv.Itoa(c.Writer.Status())
		m.reqTotal.WithLabelValues(c.Request.Method, route, status).Inc()
		m.reqDuration.WithLabelValues(c.Request.Method, route, status).
			Observe(time.Since(start).Seconds())
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
