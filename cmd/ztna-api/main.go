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
	"github.com/kennguy3n/fishbone-access/internal/pkg/observability"
	"github.com/kennguy3n/fishbone-access/internal/pkg/ratelimit"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
	"github.com/kennguy3n/fishbone-access/internal/services/billing"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
	"github.com/kennguy3n/fishbone-access/internal/services/mfa"
	"github.com/kennguy3n/fishbone-access/internal/services/tenancy"
	"github.com/kennguy3n/fishbone-access/internal/services/usage"

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
	// Surface config knobs whose value will be silently overridden by a safe
	// fallback (or that carry an operational caveat, e.g. the credential
	// key-overlap migration note). These are deliberately non-fatal (the
	// dormant-trial fleet must boot even with a fat-fingered knob; see
	// config.Config.Warnings), but logging them loudly here means a
	// misconfiguration is caught at startup rather than only inferred from later
	// behaviour. The tier-name check lives here because config is a leaf package
	// that does not know the tier ladder.
	for _, warning := range cfg.Warnings() {
		logger.Warnf(ctx, "ztna-api: %s", warning)
	}
	if t := cfg.Tenancy.DefaultTier; !tenancy.IsKnownTier(t) {
		logger.Warnf(ctx, "ztna-api: tenancy config: ACCESS_TENANCY_DEFAULT_TIER=%q is not a recognised tier; un-tiered tenants will fall back to the most-constrained (trial) budget", t)
	}

	ready := &atomic.Bool{}

	var deps handlers.Deps
	// Operational telemetry: one Prometheus registry shared by the request
	// instrumentation and the /metrics scrape endpoint (wired in NewRouter). The
	// DB pool's saturation stats are registered on it once the pool is open.
	metrics := observability.NewMetrics()
	deps.Metrics = metrics

	// Distributed tracing is opt-in via the standard OTEL_EXPORTER_OTLP_ENDPOINT.
	// When unset this is a no-op and the request middleware is not mounted, so
	// the default (SME) deployment carries no tracing overhead.
	traceShutdown, traceEnabled, err := observability.InitTracer(ctx, "ztna-api")
	if err != nil {
		return fmt.Errorf("init tracing: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := traceShutdown(shutdownCtx); err != nil {
			logger.Warnf(context.Background(), "ztna-api: trace exporter shutdown: %v", err)
		}
	}()
	if traceEnabled {
		deps.TracingServiceName = "ztna-api"
		logger.Infof(ctx, "ztna-api: OpenTelemetry tracing enabled (OTLP endpoint configured)")
	}

	// Per-tenant inbound rate limiting: cap a single tenant's request rate so a
	// noisy or runaway tenant cannot monopolise the shared Postgres pool (and
	// our bill) at the expense of the other tenants. The limiter is in-memory
	// (per replica — see config.RateLimitConfig) and opt-out via
	// ACCESS_TENANT_RATE_LIMIT_ENABLED=false. Stop releases its janitor on
	// shutdown.
	if cfg.RateLimit.Enabled {
		limiter := ratelimit.New(ratelimit.Config{
			RPS:   cfg.RateLimit.RequestsPerSecond,
			Burst: cfg.RateLimit.Burst,
		})
		defer limiter.Stop()
		deps.RateLimiter = limiter
		logger.Infof(ctx, "ztna-api: per-tenant rate limiting enabled (%g req/s, burst %d, per replica)", cfg.RateLimit.RequestsPerSecond, cfg.RateLimit.Burst)
	}

	if cfg.DatabaseConfigured() {
		gdb, err := setupDatabase(ctx, cfg)
		if err != nil {
			return fmt.Errorf("database setup: %w", err)
		}
		deps.DB = gdb
		if sqlDB, err := gdb.DB(); err == nil {
			if err := metrics.RegisterDBPool(sqlDB); err != nil {
				return fmt.Errorf("register db pool metrics: %w", err)
			}
		} else {
			// gdb.DB() effectively never fails for the postgres driver (see
			// setupDatabase), but if it did we'd silently lose pool-saturation
			// visibility; log it so the gap is observable rather than invisible.
			logger.Warnf(ctx, "ztna-api: db pool metrics not registered: %v", err)
		}
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

	// Encryptor for the process-wide (non-per-workspace) at-rest secrets — today
	// the TOTP step-up MFA secrets. CryptoEncryptorFromConfig mirrors the
	// connector path's precedence so one ACCESS_KMS_MASTER_KEY roots ALL at-rest
	// encryption: with the master key set it derives a stable service key from it
	// (so a fully KMS-migrated deployment keeps MFA working rather than silently
	// degrading), else it uses the static DEK, else a passthrough that fails
	// closed in degraded dev boots.
	enc, err := access.CryptoEncryptorFromConfig(cfg.KMSMasterKey, cfg.CredentialDEK)
	if err != nil {
		return fmt.Errorf("credential encryptor init: %w", err)
	}
	deps.Encryptor = enc

	// Access-stack credential encryptor for the connector-management surface.
	// It is the same encryptor the access-connector-worker builds from the
	// same config, so a connector created through the API seals its secrets in
	// a form the worker can open when it runs the sync — without it the two
	// stacks would diverge and a created connector could never be synced.
	// FromConfig prefers the per-workspace KMS master key (deriving a distinct
	// DEK per workspace) and falls back to the single static DEK, so both
	// stacks must be configured identically for the seals to interoperate.
	connEnc, err := access.CredentialEncryptorFromConfig(cfg.KMSMasterKey, cfg.KMSKeyVersion, cfg.CredentialDEK)
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
			// No key at all ⇒ the encryptor refuses to seal/open, so TOTP
			// enrolment and every VerifyStepUp fail closed with
			// ErrSecretsDisabled (503). The gate stays wired (fail-closed is
			// correct), but make the degraded posture loud at boot rather than
			// only surfacing on the first promote attempt.
			logger.Warnf(ctx, "ztna-api: neither ACCESS_KMS_MASTER_KEY nor ACCESS_CREDENTIAL_DEK set; step-up TOTP MFA wired but DISABLED (enrolment + verification will 503 until a key is configured)")
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

	// Per-tenant usage metering (WS billing foundation): accumulate per-tenant
	// usage counts on the request path and flush them to the tenant_usage
	// rollup so cost-to-serve is attributable per tenant — the "who is using
	// what" half of the cost story (the rate limiter above is the "cap the
	// abuser" half). Like the rate limiter it is in-memory and PER REPLICA:
	// each replica flushes its own deltas with an additive UPSERT, so N
	// replicas sum into one row rather than overwriting. Per-tenant attribution
	// lives in Postgres (cardinality is cheap there); only AGGREGATE counters
	// reach /metrics, fed by the flush observer below. Wired only when a DB is
	// present (the rollup needs Postgres) and metering is enabled.
	//
	// Shutdown ordering matters: the flush loop must NOT stop when the signal
	// context is cancelled, because srv.Shutdown then drains in-flight requests
	// that are still calling Record — counts that would be stranded if the loop
	// had already done its final flush. So usageCtx keeps the signal context's
	// values (logging/tracing) but drops its cancellation (WithoutCancel), and
	// the loop is stopped solely by this defer. The defer is registered after
	// the DB-pool-close defer, so LIFO runs it BEFORE the pool closes; and it
	// runs only after run() returns, i.e. after srv.Shutdown has finished
	// draining — so the final flush captures the drain window and still can't
	// touch a closed pool.
	if deps.DB != nil && cfg.UsageMetering.Enabled {
		usageStore := usage.NewStore(deps.DB)
		aggregator := usage.New(usageStore, usage.Config{
			FlushInterval: cfg.UsageMetering.FlushInterval,
			Observe:       metrics.AddUsageEvents,
		})
		usageCtx, usageCancel := context.WithCancel(context.WithoutCancel(ctx))
		joinUsage := aggregator.Run(usageCtx)
		defer func() {
			usageCancel()
			joinUsage()
		}()
		deps.UsageMeter = aggregator
		deps.UsageReader = usageStore
		logger.Infof(ctx, "ztna-api: per-tenant usage metering enabled (flush every %s, per replica); per-tenant counts roll up to tenant_usage, only aggregate counters on /metrics", cfg.UsageMetering.FlushInterval)
	}

	// Billing economics layer: per-tenant statements + quota enforcement, ON TOP
	// of the usage rollup above. It reads the SAME tenant_usage the meter writes
	// (a fresh usage.Store reader — billing only reads), so it introduces no
	// second source of truth for consumption. The service runs a per-replica,
	// TTL-bounded decision cache with a background janitor; its Stop is deferred
	// so the goroutine is reaped on shutdown. Enabled independently of metering
	// (config.Warnings flags the metering-off footgun), and disabled by default
	// since enforcement can reject requests.
	if deps.DB != nil && cfg.Billing.Enabled {
		planStore := billing.NewStore(deps.DB)
		billingSvc := billing.NewService(planStore, usage.NewStore(deps.DB), billing.Config{
			EnforceHardCap: cfg.Billing.EnforceHardCap,
			CacheTTL:       cfg.Billing.CacheTTL,
		})
		defer billingSvc.Stop()
		deps.BillingEnforcer = billingSvc
		deps.BillingReader = billingSvc
		mode := "shadow (over-hard-cap requests are flagged but ALLOWED)"
		if cfg.Billing.EnforceHardCap {
			mode = "enforcing (over-hard-cap requests are denied 402 before expensive work)"
		}
		logger.Infof(ctx, "ztna-api: per-tenant billing enabled (decision cache TTL %s, per replica; hard-cap %s); statements derive from tenant_usage, fail-open", cfg.Billing.CacheTTL, mode)
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
