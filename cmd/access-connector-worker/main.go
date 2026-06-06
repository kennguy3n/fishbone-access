// Command access-connector-worker drains the access_jobs queue: identity syncs,
// access provisioning, and revocation tasks produced by ztna-api. It runs the
// generic worker loop from internal/workers with the Postgres-backed queue and
// the connector-dispatch processor.
//
// Session 1A wires the boot/shutdown skeleton and the worker loop. The
// Postgres Queue (claiming access_jobs with FOR UPDATE SKIP LOCKED) and the
// connector-dispatch Processor are implemented in Session 1B and slot into the
// workers.New call below.
package main

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/kennguy3n/fishbone-access/internal/config"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"

	// Blank-import connectors so the worker can dispatch to any provider.
	_ "github.com/kennguy3n/fishbone-access/internal/services/access/connectors/all"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := config.Load()
	logger.Infof(ctx, "access-connector-worker: starting; %s", cfg.String())

	if !cfg.DatabaseConfigured() {
		logger.Errorf(ctx, "access-connector-worker: ACCESS_DATABASE_URL is required")
		stop()
		return
	}

	// Session 1B: construct the Postgres-backed workers.Queue + connector
	// dispatch workers.Processor here and run:
	//
	//	w := workers.New(queue, processor, workers.Config{})
	//	if err := w.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
	//		logger.Errorf(ctx, "worker exited: %v", err)
	//	}
	//
	// Until then the binary boots, validates config, and waits for a signal
	// so deployment wiring (env, health, image) is exercised end-to-end.
	logger.Infof(ctx, "access-connector-worker: ready; awaiting jobs")
	<-ctx.Done()
	logger.Infof(context.Background(), "access-connector-worker: shutting down")
}
