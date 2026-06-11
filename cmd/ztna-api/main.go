// Command ztna-api is the ShieldNet Access HTTP API. It boots a Gin server
// exposing the access-platform endpoints, validates iam-core bearer tokens, and
// blank-imports every connector so the process-global registry is populated.
//
// When ACCESS_DATABASE_URL is set the binary opens a GORM Postgres pool and
// applies the SQL migrations in internal/migrations. When it is unset the
// binary still boots (degraded mode) so `go run` works without Postgres —
// the authenticated API surface then returns 503.
//
// When IAM_CORE_ISSUER is set the binary builds the JWKS-backed token
// validator; when unset the authenticated surface returns 503 rather than
// allowing unauthenticated access (fail closed).
//
// Graceful shutdown: SIGINT/SIGTERM trigger http.Server.Shutdown with a
// configurable timeout so in-flight requests finish.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/config"
	"github.com/kennguy3n/fishbone-access/internal/handlers"
	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/migrations"
	"github.com/kennguy3n/fishbone-access/internal/pkg/aiclient"
	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
	"github.com/kennguy3n/fishbone-access/internal/services/mfa"
	"github.com/kennguy3n/fishbone-access/internal/services/tenancy"

	// Blank-import the connector aggregator so every provider's init()
	// registers it with the access registry.
	_ "github.com/kennguy3n/fishbone-access/internal/services/access/connectors/all"
)

func main() {
	if err := run(); err != nil {
		logger.Errorf(context.Background(), "ztna-api: fatal: %v", err)
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
	logger.Infof(ctx, "ztna-api: starting; %s", cfg.String())
	logger.Infof(ctx, "ztna-api: registered connectors: %d", access.RegisteredCount())

	ready := &atomic.Bool{}

	var deps handlers.Deps
	if cfg.DatabaseConfigured() {
		gdb, err := setupDatabase(ctx, cfg)
		if err != nil {
			return fmt.Errorf("database setup: %w", err)
		}
		deps.DB = gdb
		// Own the pool: close it on the way out so we don't leak idle Postgres
		// connections (the pool outlives setupDatabase because the 1B-1E
		// handlers query through it).
		defer func() {
			if sqlDB, err := gdb.DB(); err == nil {
				_ = sqlDB.Close()
			}
		}()

		// Route RequireTenant's tenant→workspace resolution through the backend
		// selected by ACCESS_DATABASE_DRIVER (WS10/WS15 GORM→pgx migration, starting
		// with the workspace-config read on the hot path of every authenticated
		// request). Both backends honour the identical contract (same query, same
		// gorm.ErrRecordNotFound on a miss), so tenant isolation is unchanged
		// whichever is selected.
		switch cfg.DatabaseDriver {
		case config.DriverPgx:
			// Open a pgxpool alongside the GORM pool. It is sized by its own bound
			// (DBPgxMaxConns), independent of the GORM pool, because the
			// workspace-config read is light; this keeps the added per-process
			// connection footprint small and explicit. Opened only on the pgx path
			// so a gorm-driver boot pays no second pool.
			pool, err := database.OpenPool(ctx, cfg.DatabaseURL, int32(cfg.DBPgxMaxConns), cfg.DBConnMaxLifetime, 0)
			if err != nil {
				return fmt.Errorf("pgx pool setup: %w", err)
			}
			deps.WorkspaceResolver = database.NewPgxWorkspaceConfigRepo(pool)
			// Close the pgx pool on shutdown. It is queried only by RequireTenant
			// on the HTTP request path. On the normal (signal) exit, run() returns
			// only after srv.Shutdown has drained in-flight requests, so no request
			// races this close. On the fatal-serve-error exit, run() returns
			// without draining, but srv.Serve has already stopped so no new request
			// can start; this close has exactly the same exposure as the GORM
			// pool's deferred close above (both fire in LIFO order on the same
			// path), so the pgx pool adds no shutdown race the process did not
			// already have.
			defer pool.Close()
			logger.Infof(ctx, "ztna-api: pgxpool adapter enabled for workspace-config reads")
		case config.DriverGorm:
			// Reuse the GORM pool already opened above; no second pool.
			deps.WorkspaceResolver = database.NewGormWorkspaceConfigRepo(gdb)
			logger.Infof(ctx, "ztna-api: GORM backend enabled for workspace-config reads")
		default:
			// Unreachable today: cfg.Validate() rejects any other value at boot.
			// The branch is here so that adding a driver to DatabaseDriver.Valid()
			// without wiring it here fails fast instead of leaving
			// deps.WorkspaceResolver nil and panicking on the first request.
			return fmt.Errorf("ztna-api: unsupported ACCESS_DATABASE_DRIVER %q", cfg.DatabaseDriver)
		}
	} else {
		logger.Warnf(ctx, "ztna-api: ACCESS_DATABASE_URL unset; booting in degraded mode (no DB)")
	}
	switch {
	case cfg.IAMCore.Configured():
		v, err := iamcore.NewValidator(ctx, cfg.IAMCore)
		if err != nil {
			return fmt.Errorf("iam-core validator init: %w", err)
		}
		deps.Validator = v
		logger.Infof(ctx, "ztna-api: iam-core token validation enabled (issuer=%s)", cfg.IAMCore.Issuer)
		// iam-core takes precedence, so a co-configured AUTH_JWT_SECRET is inert
		// — but silently ignoring it hides a misconfiguration. Surface it, and
		// shout in a production environment where a lingering dev secret is a
		// real posture smell (the case below never fires once iam-core wins).
		if cfg.DevAuth.Configured() {
			if cfg.IsProductionEnv() {
				logger.Warnf(ctx, "ztna-api: AUTH_JWT_SECRET is set but IGNORED — iam-core validation is configured and takes precedence (ACCESS_ENV=%q). Unset AUTH_JWT_SECRET in production so no inert dev-auth credential lingers in the environment.", cfg.Env)
			} else {
				logger.Warnf(ctx, "ztna-api: AUTH_JWT_SECRET is set but ignored; iam-core validation takes precedence over dev HMAC auth.")
			}
		}
	case cfg.DevAuthAllowed():
		// Non-production shared-secret path: lets the blog harnesses (and local
		// development) drive the authenticated API without an iam-core instance.
		// Refused entirely when ACCESS_ENV is a production label, and absent
		// from production builds by build tag (iamcore/devauth_prod.go).
		v, err := iamcore.NewDevValidator(cfg.DevAuth.Secret, cfg.DevAuth.Issuer, cfg.DevAuth.Audience)
		if err != nil {
			return fmt.Errorf("dev HMAC validator init: %w", err)
		}
		deps.Validator = v
		logger.Warnf(ctx, "ztna-api: DEV HMAC token validation enabled (issuer=%s); NOT for production", cfg.DevAuth.Issuer)
	case cfg.DevAuth.Configured() && cfg.IsProductionEnv():
		return fmt.Errorf("AUTH_JWT_SECRET set but ACCESS_ENV=%q is a production label; refusing to enable dev HMAC auth", cfg.Env)
	default:
		logger.Warnf(ctx, "ztna-api: no token validator configured; authenticated API returns 503")
	}

	// Credential encryptor opens connector secret envelopes for the lifecycle
	// provisioning / JML / reconciliation services. FromKey returns a
	// passthrough (seal-refusing) encryptor when no DEK is set, so connectors
	// without sealed secrets still resolve in degraded dev boots.
	enc, err := crypto.FromKey(cfg.CredentialDEK)
	if err != nil {
		return fmt.Errorf("credential encryptor init: %w", err)
	}
	deps.Encryptor = enc

	// Access-stack credential encryptor for the connector-management surface.
	// It is the same encryptor the access-connector-worker builds from the
	// same DEK, so a connector created through the API seals its secrets in a
	// form the worker can open when it runs the sync — without it the two
	// stacks would diverge and a created connector could never be synced.
	connEnc, err := access.CredentialEncryptorFromKey(cfg.CredentialDEK)
	if err != nil {
		return fmt.Errorf("connector credential encryptor init: %w", err)
	}
	deps.ConnectorEncryptor = connEnc

	// AI client (mTLS A2A) shared by the lifecycle risk review baked into the
	// elevation request flow and the connector setup wizard. NewAIClientFromEnv
	// returns an unconfigured client (→ fail-open deterministic fallback) when no
	// agent is set, and errors only on a half-configured mTLS setup (fatal
	// misconfiguration). Both consumers are fail-OPEN, so an unconfigured client
	// degrades gracefully rather than blocking boot.
	ai, err := aiclient.NewAIClientFromEnv()
	if err != nil {
		return fmt.Errorf("ai client init: %w", err)
	}
	if !ai.Configured() {
		logger.Warnf(ctx, "ztna-api: AI agent not configured; risk review uses fail-open deterministic fallback")
	}
	deps.AI = ai

	// The iam-core management client disables (blocks) users for the leaver
	// kill switch (layer 3). It is wired only when the management credentials
	// (client id + secret) are present, since BlockUser mints a
	// client_credentials token: gating on full management config means the
	// layer reports "skipped" when iam-core is set up for JWT validation only,
	// instead of a non-nil client that fails every BlockUser call (which would
	// report the layer "failed").
	if cfg.IAMCore.ManagementConfigured() {
		deps.Disabler = iamcore.NewManagementClient(cfg.IAMCore, nil)
	}

	deps.Ready = ready

	// RBAC authorization tier + step-up MFA. Both are backed by tables that
	// only exist when a DB is configured, so they are wired only in the
	// non-degraded path. The RBACService caches memberships per workspace
	// (DefaultCacheTTL) to keep the per-request permission resolve off the DB.
	// The composite step-up verifier today carries only a TOTP leg (the repo
	// has no WebAuthn enrolment yet) and enforces single-use replay protection;
	// a background loop tied to the signal context prunes expired used-code
	// rows. AuthzMiddleware and the high-risk step-up gates are mounted by the
	// router only when these deps are non-nil.
	if deps.DB != nil {
		deps.RBAC = authz.NewRBACService(deps.DB, authz.DefaultCacheTTL)
		totpVerifier, err := mfa.NewTOTPMFAVerifier(deps.DB, deps.Encryptor)
		if err != nil {
			return fmt.Errorf("totp verifier init: %w", err)
		}
		// Give the cleanup loop its own cancellable context and join it on the
		// way out, mirroring the scheduler below, so the goroutine is guaranteed
		// to have stopped before the deferred DB-pool close runs (the pool's
		// close defer was registered earlier, so this later-registered defer
		// runs first under LIFO). This holds on every run() exit path.
		cleanupCtx, cleanupCancel := context.WithCancel(ctx)
		joinCleanup := totpVerifier.StartUsedCodeCleanupLoop(cleanupCtx, mfa.DefaultCleanupInterval, mfa.DefaultTOTPUsedCodeRetention)
		defer func() {
			cleanupCancel()
			joinCleanup()
		}()
		deps.StepUpMFA = mfa.NewCompositeMFAVerifier(nil, totpVerifier)
		if crypto.IsPassthrough(deps.Encryptor) {
			// No DEK ⇒ the encryptor refuses to seal/open, so TOTP enrolment
			// and every VerifyStepUp fail closed with ErrSecretsDisabled (503).
			// The gate stays wired (fail-closed is correct), but make the
			// degraded posture loud at boot rather than only surfacing on the
			// first promote attempt.
			logger.Warnf(ctx, "ztna-api: ACCESS_CREDENTIAL_DEK unset; step-up TOTP MFA wired but DISABLED (enrolment + verification will 503 until a DEK is configured)")
		} else {
			logger.Infof(ctx, "ztna-api: RBAC authorization + step-up TOTP MFA enabled")
		}
	}

	// Periodic lifecycle maintenance: the grant-expiry sweep and the daily
	// orphan-account reconciliation. Run in-process (tied to the server's
	// signal context) so expiry is enforced even before the Session 1B durable
	// worker queue lands. The sweeps are idempotent and workspace-scoped, so
	// running them on every replica is safe. Only started when a DB is present.
	if deps.DB != nil {
		resolver := lifecycle.NewDBConnectorResolver(deps.DB, deps.ConnectorEncryptor)
		reqSvc := lifecycle.NewAccessRequestService(deps.DB)
		workflow := lifecycle.NewWorkflowService(reqSvc)
		prov := lifecycle.NewAccessProvisioningService(deps.DB, reqSvc, resolver)
		jml := lifecycle.NewJMLService(deps.DB, reqSvc, workflow, prov, resolver, deps.Disabler)
		contractorSvc := lifecycle.NewContractorService(deps.DB, prov)
		sched := lifecycle.NewScheduler(
			deps.DB,
			lifecycle.NewExpiryEnforcer(deps.DB, prov),
			lifecycle.NewOrphanReconciler(deps.DB, resolver),
			lifecycle.SchedulerConfig{},
		)
		// Attach the SoD anomaly→evidence detector and the contractor-grant
		// expiry/offboard enforcer so their periodic sweeps run alongside the
		// expiry and orphan sweeps. Both are idempotent and workspace-scoped.
		sched.SetAnomalyDetector(lifecycle.NewAnomalyDetector(deps.DB))
		sched.SetContractorEnforcer(lifecycle.NewContractorExpiryEnforcer(deps.DB, contractorSvc, prov, jml))
		// Give the scheduler its own cancellable context and join it on the way
		// out so it is guaranteed to have stopped before the deferred DB-pool
		// close runs. The pool's close defer was registered earlier (right after
		// setupDatabase), so this later-registered defer runs first (LIFO) — the
		// scheduler can never issue a query against an already-closed pool. This
		// holds on every run() exit path (signal shutdown and fatal serve error).
		schedCtx, schedCancel := context.WithCancel(ctx)
		var schedWG sync.WaitGroup
		schedWG.Add(1)
		go func() {
			defer schedWG.Done()
			if err := sched.Run(schedCtx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Errorf(context.Background(), "ztna-api: lifecycle scheduler exited: %v", err)
			}
		}()
		defer func() {
			schedCancel()
			schedWG.Wait()
		}()
		logger.Infof(ctx, "ztna-api: lifecycle scheduler started (expiry + orphan reconciliation + sod anomaly evidence + contractor expiry)")
	}

	// Tenant hibernation (WS1 scale/NoOps): track per-tenant activity, classify
	// the dormant-trial fraction, and let periodic workers skip them so the
	// dormant majority costs ~nothing. Background loops are tied to the signal
	// context and joined on the way out (LIFO, after the scheduler, before the
	// DB-pool close) so none can touch an already-closed pool.
	//
	// Activity recording is wired whenever a DB is present, INDEPENDENT of
	// HibernationEnabled: Service.RecordActivity ignores the gate, and the
	// documented contract is that activity is always captured so the feature can
	// be toggled on later with accurate history (otherwise a later enable would
	// classify every tenant from workspaces.created_at and wrongly hibernate
	// long-lived active tenants until their next request). The reconcile sweep,
	// by contrast, only earns its keep when hibernation is enabled — when it is
	// off the gate short-circuits to "run" for everyone, so classifying is
	// pointless work — so only that loop is conditional.
	if deps.DB != nil {
		tenancySvc := tenancy.NewService(deps.DB, tenancy.Config{
			Enabled:       cfg.Tenancy.HibernationEnabled,
			IdleThreshold: cfg.Tenancy.DormantIdleThreshold,
			DefaultTier:   cfg.Tenancy.DefaultTier,
		})

		// Always: drain request-path activity and lazily wake dormant tenants.
		// Fed by the router's activity middleware (deps.ActivityRecorder).
		recorder := tenancy.NewAsyncRecorder(tenancySvc, tenancy.AsyncRecorderConfig{
			Throttle:      cfg.Tenancy.ActivityFlushInterval,
			IdleThreshold: cfg.Tenancy.DormantIdleThreshold,
			QueueSize:     cfg.Tenancy.ActivityQueueSize,
		})
		recCtx, recCancel := context.WithCancel(ctx)
		joinRecorder := recorder.Run(recCtx)
		defer func() {
			recCancel()
			joinRecorder()
		}()
		deps.ActivityRecorder = recorder

		if cfg.Tenancy.HibernationEnabled {
			// Only when enabled: periodically (re)classify tenants set-based.
			reconcileCtx, reconcileCancel := context.WithCancel(ctx)
			joinReconcile := tenancy.NewReconcileLoop(tenancySvc, cfg.Tenancy.ReconcileInterval).Run(reconcileCtx)
			defer func() {
				reconcileCancel()
				joinReconcile()
			}()
			logger.Infof(ctx, "ztna-api: tenant hibernation enabled (idle threshold %s, reconcile every %s); dormant tenants skip periodic work and wake on activity",
				cfg.Tenancy.DormantIdleThreshold, cfg.Tenancy.ReconcileInterval)
		} else {
			logger.Infof(ctx, "ztna-api: tenant hibernation DISABLED (ACCESS_TENANCY_HIBERNATION_ENABLED=false); all tenants treated as active, but activity is still recorded so the feature can be enabled later with accurate history")
		}
	}

	srv := &http.Server{
		Handler:           handlers.NewRouter(deps),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Bind synchronously so a bind failure (e.g. port in use) is a hard boot
	// error returned from run() — exit code 1 — rather than a goroutine-only
	// log that leaves the process exiting 0 (which would defeat container
	// restart-on-failure). ready is only flipped once the socket is bound.
	ln, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.HTTPAddr, err)
	}
	ready.Store(true)
	logger.Infof(ctx, "ztna-api: listening on %s", ln.Addr())

	serveErr := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	// Wait for either a signal (ctx cancelled) or a fatal serve error.
	select {
	case <-ctx.Done():
		logger.Infof(context.Background(), "ztna-api: shutting down")
	case err := <-serveErr:
		if err != nil {
			return fmt.Errorf("http server: %w", err)
		}
		return nil
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	return nil
}

// setupDatabase opens Postgres, applies SQL migrations, and returns the pool so
// the caller can wire it into the handlers and own its lifecycle (close on
// shutdown). Auto-migrate is intentionally NOT used in production — the
// reviewable SQL migrations are authoritative.
func setupDatabase(ctx context.Context, cfg config.Config) (*gorm.DB, error) {
	gdb, err := database.Open(cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		// gdb.DB() only fails when the pool isn't a *sql.DB (never with the
		// postgres driver today), but close defensively so a future driver swap
		// can't leak the pool — mirroring the migration-failure path below.
		if closer, ok := gdb.ConnPool.(io.Closer); ok {
			_ = closer.Close()
		}
		return nil, err
	}
	// Bound the pool before doing any work on it (migrations included) so this
	// process can never open more Postgres connections than configured. The API
	// is the most-replicated tier serving the 5,000-tenant fleet, so it also
	// caps idle-connection time: a replica that goes quiet releases connections
	// back to Postgres instead of reserving max_connections headroom (NoOps).
	if err := database.ApplyPoolLimitsWithIdle(gdb, cfg.DBMaxOpenConns, cfg.DBMaxIdleConns, cfg.DBConnMaxLifetime, cfg.DBConnMaxIdleTime); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	applied, err := migrations.Run(ctx, sqlDB)
	if err != nil {
		// Don't leak the pool if migrations fail.
		_ = sqlDB.Close()
		return nil, err
	}
	logger.Infof(ctx, "ztna-api: applied %d migration(s)", len(applied))
	return gdb, nil
}
