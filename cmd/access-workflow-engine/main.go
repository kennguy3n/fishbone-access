// Command access-workflow-engine runs the ShieldNet Access workflow
// orchestration plane. It drives the JML (Joiner/Mover/Leaver) lifecycle,
// approval chains, and scheduled access certifications on top of the
// lifecycle services and the connector worker queue.
//
// The binary runs two cooperating loops until SIGINT/SIGTERM:
//
//   - a worker that drains the persisted access_jobs queue, filtered to the
//     workflow job types (JML events, provisioning of approved requests, and
//     scheduled review sweeps), so in-flight workflows survive a restart; and
//   - a periodic review scheduler that enqueues a certification sweep per
//     workspace.
//
// It does NOT run migrations (ztna-api is authoritative for schema) and does
// NOT serve HTTP — the Submit/Approve/Deny engine API is exercised in-process by
// ztna-api handlers; this binary is the asynchronous executor + scheduler.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/config"
	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/pkg/aiclient"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/pkg/observability"
	"github.com/kennguy3n/fishbone-access/internal/services/access/workflow_engine"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
	"github.com/kennguy3n/fishbone-access/internal/services/tenancy"
	"github.com/kennguy3n/fishbone-access/internal/services/workflow"
	"github.com/kennguy3n/fishbone-access/internal/workers"

	// Blank-import connectors so the provisioning + leaver paths can dispatch to
	// any provider when this binary executes provisioning/JML jobs.
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	_ "github.com/kennguy3n/fishbone-access/internal/services/access/connectors/all"
)

func main() {
	if err := run(); err != nil {
		logger.Errorf(context.Background(), "access-workflow-engine: fatal: %v", err)
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
		logger.Warnf(ctx, "access-workflow-engine: %s", warning)
	}
	logger.Infof(ctx, "access-workflow-engine: starting; %s", cfg.String())

	if !cfg.DatabaseConfigured() {
		logger.Errorf(ctx, "access-workflow-engine: ACCESS_DATABASE_URL is required")
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

	// This binary is an asynchronous executor of provisioning/JML jobs that MUST
	// open real connector secrets, so it refuses to boot without a credential
	// key (the fail-closed encryptor would degrade every job to a decrypt
	// failure) rather than starting and failing per job. Either the
	// per-workspace KMS master key or the static DEK satisfies the gate; with
	// neither set the encryptor is the disabled/passthrough case.
	if !cfg.CredentialEncryptionConfigured() {
		logger.Errorf(ctx, "access-workflow-engine: refusing to start without ACCESS_KMS_MASTER_KEY or ACCESS_CREDENTIAL_DEK; provisioning/JML jobs cannot open connector secrets under the passthrough encryptor")
		stop()
		return nil
	}

	// The connector resolver opens secret envelopes through the same
	// CredentialEncryptor the connector-management layer seals them with, so the
	// engine recovers credentials under the identical AAD / workspace-DEK / key
	// version (a plain crypto.Encryptor would use a different AAD and fail to
	// open). CredentialEncryptorFromConfig hard-errors on a non-empty but
	// malformed key, so a typo'd DEK/master key aborts boot rather than
	// silently mis-decrypting; it prefers the per-workspace KMS master key.
	connEnc, err := access.CredentialEncryptorFromConfig(cfg.KMSMasterKey, cfg.KMSKeyVersion, cfg.CredentialDEK)
	if err != nil {
		return fmt.Errorf("connector credential encryptor init: %w", err)
	}

	// Lifecycle services: the engine orchestrates these; it never
	// re-implements the FSM, connector protocol, or kill switch.
	resolver := lifecycle.NewDBConnectorResolver(gdb, connEnc)
	reqSvc := lifecycle.NewAccessRequestService(gdb)
	prov := lifecycle.NewAccessProvisioningService(gdb, reqSvc, resolver)
	workflowSvc := lifecycle.NewWorkflowService(reqSvc)

	// The iam-core management client disables users for the leaver kill switch
	// (layer 3); wired only when management credentials are present (else the
	// layer reports "skipped" rather than failing every BlockUser).
	var disabler lifecycle.IdentityDisabler
	if cfg.IAMCore.ManagementConfigured() {
		disabler = iamcore.NewManagementClient(cfg.IAMCore, nil)
	}
	jmlSvc := lifecycle.NewJMLService(gdb, reqSvc, workflowSvc, prov, resolver, disabler)
	// The review service revokes grants the certification campaign tears down;
	// the provisioning service is the GrantRevoker.
	reviewSvc := lifecycle.NewReviewService(gdb, prov)

	// AI client (mTLS A2A). NewAIClientFromEnv returns an unconfigured client
	// (→ deterministic fallback) when no agent is configured, and an error only
	// on a half-configured mTLS setup, which is fatal misconfiguration.
	ai, err := aiclient.NewAIClientFromEnv()
	if err != nil {
		return err
	}
	if !ai.Configured() {
		logger.Warnf(ctx, "access-workflow-engine: AI agent not configured; risk/review skills use deterministic fallback")
	}

	approvals := workflow_engine.NewApprovalStore(gdb)
	queue := workers.NewPostgresQueue(gdb, workers.WithJobTypes(workflow_engine.AllJobTypes()...))

	engine, err := workflow_engine.NewEngine(workflow_engine.Deps{
		Requests:  reqSvc,
		Workflow:  workflowSvc,
		AI:        ai,
		Approvals: approvals,
		Queue:     queue,
	})
	if err != nil {
		return err
	}

	// The no-code JML workflow builder's asynchronous execution path: the engine
	// runs published workflows via the same Service.Run the manual API uses,
	// building step dependencies bound to each run's workspace + actor.
	wfSvc := workflow.NewService(gdb)
	wfStepSvcs := workflow.StepServices{Requests: reqSvc, Prov: prov, Reviews: reviewSvc, JML: jmlSvc}
	processor, err := workflow_engine.NewJobProcessor(workflow_engine.ProcessorDeps{
		JML:         jmlSvc,
		Provisioner: prov,
		Reviews:     reviewSvc,
		Grants:      workflow_engine.NewGormGrantLookup(gdb),
		AI:          ai,
		Workflows:   wfSvc,
		WorkflowDeps: func(ws uuid.UUID, actor string) workflow.StepDeps {
			return workflow.BuildStepDeps(gdb, wfStepSvcs, ws, actor)
		},
	})
	if err != nil {
		return err
	}

	// Operational telemetry. Like the connector worker this binary serves no
	// API, so it exposes its own minimal /metrics (+ /healthz); the aggregate
	// review-sweep skip counter is scraped from here. Best-effort — a bind
	// failure must not stop the engine.
	metrics := observability.NewMetrics()
	if sqlDB, derr := gdb.DB(); derr == nil {
		if rerr := metrics.RegisterDBPool(sqlDB); rerr != nil {
			logger.Warnf(ctx, "access-workflow-engine: db pool metrics not registered: %v", rerr)
		}
	}
	joinMetrics := metrics.ServeMetrics(ctx, cfg.WorkerMetricsAddr)
	defer joinMetrics()
	// joinMetrics() blocks until ctx is cancelled, and the top-level defer stop()
	// (which cancels ctx) runs AFTER it in LIFO order — so any early return below
	// would otherwise deadlock shutdown. Registering stop() here, immediately
	// after defer joinMetrics(), makes LIFO cancel ctx FIRST on every return path,
	// so the invariant is self-enforcing rather than relying on each error site to
	// remember an explicit stop(). signal.NotifyContext's stop is idempotent.
	defer stop()

	// Hibernation gate (scale-to-zero): the scheduler READS the gate to defer a
	// dormant workspace's periodic certification sweep. ztna-api owns dormancy
	// classification and activity recording; this binary only consults the gate
	// and records no activity of its own (scheduled work must not keep a tenant
	// awake). DB-backed Service only when enabled, else AlwaysRun for clean
	// degradation. The gate path (ShouldRunPeriodic) consults only Enabled + the
	// persisted dormancy state; IdleThreshold/DefaultTier feed Reconcile/BudgetFor
	// (never called here) and are passed only for parity with ztna-api's Service.
	var gate tenancy.HibernationGate = tenancy.AlwaysRun{}
	if cfg.Tenancy.HibernationEnabled {
		gate = tenancy.NewService(gdb, tenancy.Config{
			Enabled:       true,
			IdleThreshold: cfg.Tenancy.DormantIdleThreshold,
			DefaultTier:   cfg.Tenancy.DefaultTier,
		})
		logger.Infof(ctx, "access-workflow-engine: tenant hibernation enabled; dormant workspaces' periodic review sweeps are deferred")
	} else {
		logger.Infof(ctx, "access-workflow-engine: tenant hibernation DISABLED; every workspace is swept (AlwaysRun gate)")
	}

	reviewScheduler, err := workflow_engine.NewReviewScheduler(
		engine,
		workflow_engine.NewGormWorkspaceLister(gdb),
		workflow_engine.ReviewSchedulerConfig{},
	)
	if err != nil {
		// Shutdown is safe here: the defer stop() registered after defer
		// joinMetrics() cancels ctx before joinMetrics() joins (see above).
		return err
	}
	reviewScheduler.WithHibernationGate(gate, func() { metrics.IncPeriodicJobSkipped("review_sweep") })

	// Credential-rotation sweep (Session C). It rotates due target credentials
	// (interval + rotate-on-checkin) and reaps expired ephemeral DB credentials,
	// re-sealing through the same PAM vault / per-workspace DEK path the API
	// uses (connEnc). The sweep is set-based and hibernation-gated, so dormant
	// tenants cost nothing; on-demand "rotate now" goes through the API and is
	// never gated here. Disabled cleanly when ACCESS_ROTATION_ENABLED=false.
	var rotationScheduler *pam.RotationScheduler
	if cfg.Rotation.Enabled {
		rotVault := pam.NewVault(gdb, connEnc, nil)
		rotRegistry := pam.NewExecutorRegistry(cfg.Rotation.DialTimeout)
		rotEngine := pam.NewRotationEngine(gdb, rotVault, rotRegistry)
		rotReaper := pam.NewDynamicCredentialService(gdb, rotVault, cfg.Rotation.DialTimeout)
		rotationScheduler, err = pam.NewRotationScheduler(gdb, rotEngine, pam.RotationSchedulerConfig{
			Interval: cfg.Rotation.SweepInterval,
		})
		if err != nil {
			return err
		}
		rotationScheduler.
			WithHibernationGate(gate, func() { metrics.IncPeriodicJobSkipped("rotation_sweep") }).
			WithReaper(rotReaper)
		logger.Infof(ctx, "access-workflow-engine: credential rotation sweep enabled (interval=%s)", cfg.Rotation.SweepInterval)
	} else {
		logger.Infof(ctx, "access-workflow-engine: credential rotation sweep DISABLED (ACCESS_ROTATION_ENABLED=false)")
	}

	w := workers.New(queue, processor, workers.Config{})

	logger.Infof(ctx, "access-workflow-engine: ready; draining workflow jobs + scheduling reviews")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if rerr := reviewScheduler.Run(ctx); rerr != nil && !errors.Is(rerr, context.Canceled) {
			logger.Errorf(context.Background(), "access-workflow-engine: review scheduler exited: %v", rerr)
		}
	}()

	if rotationScheduler != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rerr := rotationScheduler.Run(ctx); rerr != nil && !errors.Is(rerr, context.Canceled) {
				logger.Errorf(context.Background(), "access-workflow-engine: rotation scheduler exited: %v", rerr)
			}
		}()
	}

	werr := w.Run(ctx)

	// Worker has returned (context cancelled or fatal). Stop the scheduler and
	// join it before the deferred DB-pool close runs.
	stop()
	wg.Wait()

	if werr != nil && !errors.Is(werr, context.Canceled) {
		return werr
	}
	logger.Infof(context.Background(), "access-workflow-engine: shutting down")
	return nil
}
