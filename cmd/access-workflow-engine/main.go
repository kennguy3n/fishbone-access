// Command access-workflow-engine runs the ShieldNet Access workflow
// orchestration plane. It drives the JML (Joiner/Mover/Leaver) lifecycle,
// approval chains, and scheduled access certifications on top of the 1C
// lifecycle services and the 1B connector worker queue.
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
	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/access/workflow_engine"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
	"github.com/kennguy3n/fishbone-access/internal/services/workflow"
	"github.com/kennguy3n/fishbone-access/internal/workers"

	// Blank-import connectors so the provisioning + leaver paths can dispatch to
	// any provider when this binary executes provisioning/JML jobs.
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

	// Credential encryptor opens connector secret envelopes for the lifecycle
	// provisioning / JML services this engine drives. Like the connector worker,
	// this binary is an asynchronous executor of provisioning/JML jobs that MUST
	// open real connector secrets, so it refuses to boot under the fail-closed
	// passthrough encryptor (DEK unset) rather than degrading to per-job
	// failures. FromKey treats a non-empty but malformed key as a hard error.
	enc, err := crypto.FromKey(cfg.CredentialDEK)
	if err != nil {
		return fmt.Errorf("credential encryptor init: %w", err)
	}
	if crypto.IsPassthrough(enc) {
		logger.Errorf(ctx, "access-workflow-engine: refusing to start without ACCESS_CREDENTIAL_DEK; provisioning/JML jobs cannot open connector secrets under the passthrough encryptor")
		stop()
		return nil
	}

	// Lifecycle services (1C): the engine orchestrates these; it never
	// re-implements the FSM, connector protocol, or kill switch.
	resolver := lifecycle.NewDBConnectorResolver(gdb, enc)
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

	reviewScheduler, err := workflow_engine.NewReviewScheduler(
		engine,
		workflow_engine.NewGormWorkspaceLister(gdb),
		workflow_engine.ReviewSchedulerConfig{},
	)
	if err != nil {
		return err
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
