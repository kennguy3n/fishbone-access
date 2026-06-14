package observability

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// ServeMetrics starts a minimal HTTP server exposing this registry's /metrics
// scrape endpoint plus a /healthz liveness probe on addr, for the background
// worker binaries (access-connector-worker, access-workflow-engine) that have
// no API server of their own but still must be scraped — the aggregate
// hibernation skip counter lives in the workers, so without this their realized
// cost saving would be invisible.
//
// It mirrors the recorder/reconcile-loop lifecycle: it spawns the listener and
// returns a join function that triggers a graceful shutdown bound to ctx and
// blocks until the server has stopped, so a worker can defer it alongside its
// DB-pool close without a shutdown race. An empty addr DISABLES the server and
// returns a no-op join, so metrics exposure is configuration-driven without the
// caller branching.
func (m *Metrics) ServeMetrics(ctx context.Context, addr string) func() {
	if addr == "" {
		return func() {}
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", m.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// ReadHeaderTimeout guards the unauthenticated listener against a slowloris
	// client holding the worker's single metrics connection open indefinitely.
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	served := make(chan struct{})
	go func() {
		defer close(served)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Errorf(ctx, "observability: worker metrics server on %s exited: %v", addr, err)
		}
	}()

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		// Bound shutdown so a stuck scrape connection cannot wedge the worker's
		// drain; the listener is best-effort telemetry, not durable state.
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		<-served
	}()

	logger.Infof(ctx, "observability: worker metrics server listening on %s (/metrics, /healthz)", addr)
	return func() { <-stopped }
}
