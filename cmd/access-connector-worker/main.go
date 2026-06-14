// Command access-connector-worker drains the access_jobs queue: identity syncs,
// access provisioning, and revocation tasks produced by ztna-api. It runs the
// generic worker loop from internal/workers with the Postgres-backed queue and
// the connector-dispatch processor.
//
// The binary opens a GORM Postgres pool (it does NOT run migrations — ztna-api
// is authoritative for schema), builds the credential encryptor from
// ACCESS_CREDENTIAL_DEK, and runs the worker loop until SIGINT/SIGTERM.
package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/kennguy3n/fishbone-access/internal/config"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/pkg/observability"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/tenancy"
	"github.com/kennguy3n/fishbone-access/internal/workers"

	// Blank-import connectors so the worker can dispatch to any provider.
	_ "github.com/kennguy3n/fishbone-access/internal/services/access/connectors/all"
)

func main() {
	if err := run(); err != nil {
		logger.Errorf(context.Background(), "access-connector-worker: fatal: %v", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		return err
	}
	for _, warning := range cfg.Warnings() {
		logger.Warnf(ctx, "access-connector-worker: %s", warning)
	}
	logger.Infof(ctx, "access-connector-worker: starting; %s", cfg.String())
	logger.Infof(ctx, "access-connector-worker: registered connectors: %d", access.RegisteredCount())

	if !cfg.DatabaseConfigured() {
		logger.Errorf(ctx, "access-connector-worker: ACCESS_DATABASE_URL is required")
		stop()
		return nil
	}

	gdb, err := database.Open(cfg.DatabaseURL)
	if err != nil {
		return err
	}
	if err := database.ApplyPoolLimits(gdb, cfg.DBMaxOpenConns, cfg.DBMaxIdleConns, cfg.DBConnMaxLifetime); err != nil {
		return err
	}
	defer func() {
		if sqlDB, derr := gdb.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	}()

	enc, err := access.CredentialEncryptorFromConfig(cfg.KMSMasterKey, cfg.KMSKeyVersion, cfg.CredentialDEK)
	if err != nil {
		return err
	}
	if access.IsPassthroughEncryptor(enc) {
		// Defence in depth: the boot helper never returns the test-only
		// passthrough, but refuse to run under it if a future wiring change
		// ever did — the worker decrypts and re-seals upstream credentials.
		logger.Errorf(ctx, "access-connector-worker: refusing to start under passthrough encryptor")
		stop()
		return nil
	}
	if !cfg.CredentialEncryptionConfigured() {
		// The disabled (fail-closed) encryptor is wired: provisioning/revoke
		// jobs that need to open secrets will error per-job. Log loudly so the
		// misconfiguration is visible rather than surfacing only as job failures.
		logger.Warnf(ctx, "access-connector-worker: neither ACCESS_KMS_MASTER_KEY nor ACCESS_CREDENTIAL_DEK set; jobs needing connector secrets will fail closed")
	}

	// Operational telemetry. The worker has no API server, so it serves its own
	// minimal /metrics (+ /healthz) endpoint; this is where the aggregate
	// hibernation skip counter is scraped from. Best-effort: a metrics bind
	// failure must not stop the worker draining jobs.
	metrics := observability.NewMetrics()
	if sqlDB, derr := gdb.DB(); derr == nil {
		if rerr := metrics.RegisterDBPool(sqlDB); rerr != nil {
			logger.Warnf(ctx, "access-connector-worker: db pool metrics not registered: %v", rerr)
		}
	}
	joinMetrics := metrics.ServeMetrics(ctx, cfg.WorkerMetricsAddr)
	defer joinMetrics()
	// joinMetrics() blocks until ctx is cancelled, and the top-level defer stop()
	// (which cancels ctx) runs AFTER it in LIFO order — so an early return or a
	// panic below would otherwise deadlock shutdown. Registering stop() here,
	// immediately after defer joinMetrics(), makes LIFO cancel ctx FIRST on every
	// return path, so the invariant is self-enforcing rather than relying on the
	// explicit stop() after Worker.Run. signal.NotifyContext's stop is idempotent.
	defer stop()

	// Hibernation gate (scale-to-zero): the worker only ever READS the gate to
	// skip a dormant tenant's periodic sync; ztna-api owns classification (the
	// reconcile sweep) and activity recording (the request path). The worker
	// deliberately records NO activity of its own — doing work for a tenant must
	// not itself count as that tenant's activity, or a hibernated tenant could
	// never stay dormant. Construct the real DB-backed Service only when
	// hibernation is enabled; otherwise AlwaysRun so the processor can depend on
	// a non-nil gate and the disabled mode degrades cleanly (no gate DB reads).
	//
	// The gate path (ShouldRunPeriodic) consults only Enabled + the persisted
	// dormancy state; IdleThreshold/DefaultTier feed Reconcile/BudgetFor, which
	// this binary never calls. They are passed anyway so the worker's gate is
	// configured identically to ztna-api's Service — if classification semantics
	// ever become threshold-aware on the read path, the worker stays in lockstep
	// rather than silently diverging on a default.
	var gate tenancy.HibernationGate = tenancy.AlwaysRun{}
	if cfg.Tenancy.HibernationEnabled {
		gate = tenancy.NewService(gdb, tenancy.Config{
			Enabled:       true,
			IdleThreshold: cfg.Tenancy.DormantIdleThreshold,
			DefaultTier:   cfg.Tenancy.DefaultTier,
		})
		logger.Infof(ctx, "access-connector-worker: tenant hibernation enabled; dormant tenants' periodic identity syncs are deferred (on-demand provision/revoke always run)")
	} else {
		logger.Infof(ctx, "access-connector-worker: tenant hibernation DISABLED; every tenant's syncs run (AlwaysRun gate)")
	}

	// Filter the shared access_jobs queue to connector job types only, so this
	// worker never claims workflow-engine jobs (which it cannot process) when
	// both workers drain the same table.
	queue := workers.NewPostgresQueue(gdb, workers.WithJobTypes(
		access.JobTypeSyncIdentities,
		access.JobTypeProvision,
		access.JobTypeRevoke,
	))
	processor := access.NewConnectorJobProcessor(gdb, enc).
		WithHibernationGate(gate, func() { metrics.IncPeriodicJobSkipped("connector_sync") })
	w := workers.New(queue, processor, workers.Config{})

	logger.Infof(ctx, "access-connector-worker: ready; draining access_jobs")
	werr := w.Run(ctx)

	// Worker has returned (context cancelled or fatal). The deferred stop()
	// registered after defer joinMetrics() cancels ctx before the metrics join
	// runs, so shutdown is correct without depending on Worker.Run's internal
	// "only returns ctx.Err()" contract.
	if werr != nil && !errors.Is(werr, context.Canceled) {
		return werr
	}
	logger.Infof(context.Background(), "access-connector-worker: shutting down")
	return nil
}
