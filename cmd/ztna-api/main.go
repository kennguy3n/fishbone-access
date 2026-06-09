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
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"

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

		// Open a pgxpool alongside the GORM pool and route RequireTenant's
		// tenant→workspace resolution through the pgxpool adapter (WS10 GORM→pgx
		// migration, starting with the workspace-config read on the hot path of
		// every authenticated request). The rest of the control plane still
		// queries through GORM; the two pools share the same Postgres and the
		// adapter honours the identical contract (same query, same
		// gorm.ErrRecordNotFound on a miss), so tenant isolation is unchanged.
		// The pgx pool is sized by its own bound (DBPgxMaxConns), independent of
		// the GORM pool, because the workspace-config read is light; this keeps
		// the added per-process connection footprint small and explicit.
		pool, err := database.OpenPool(ctx, cfg.DatabaseURL, int32(cfg.DBPgxMaxConns), cfg.DBConnMaxLifetime, 0)
		if err != nil {
			return fmt.Errorf("pgx pool setup: %w", err)
		}
		deps.WorkspaceResolver = database.NewPgxWorkspaceConfigRepo(pool)
		// Close the pgx pool on shutdown. It is queried only by RequireTenant on
		// the HTTP request path. On the normal (signal) exit, run() returns only
		// after srv.Shutdown has drained in-flight requests, so no request races
		// this close. On the fatal-serve-error exit, run() returns without
		// draining, but srv.Serve has already stopped so no new request can start;
		// this close has exactly the same exposure as the GORM pool's deferred
		// close above (both fire in LIFO order on the same path), so the pgx pool
		// adds no shutdown race the process did not already have.
		defer pool.Close()
		logger.Infof(ctx, "ztna-api: pgxpool adapter enabled for workspace-config reads")
	} else {
		logger.Warnf(ctx, "ztna-api: ACCESS_DATABASE_URL unset; booting in degraded mode (no DB)")
	}
	if cfg.IAMCore.Configured() {
		v, err := iamcore.NewValidator(ctx, cfg.IAMCore)
		if err != nil {
			return fmt.Errorf("iam-core validator init: %w", err)
		}
		deps.Validator = v
		logger.Infof(ctx, "ztna-api: iam-core token validation enabled (issuer=%s)", cfg.IAMCore.Issuer)
	} else {
		logger.Warnf(ctx, "ztna-api: iam-core NOT configured; authenticated API returns 503")
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

	// Periodic lifecycle maintenance: the grant-expiry sweep and the daily
	// orphan-account reconciliation. Run in-process (tied to the server's
	// signal context) so expiry is enforced even before the Session 1B durable
	// worker queue lands. The sweeps are idempotent and workspace-scoped, so
	// running them on every replica is safe. Only started when a DB is present.
	if deps.DB != nil {
		resolver := lifecycle.NewDBConnectorResolver(deps.DB, deps.Encryptor)
		reqSvc := lifecycle.NewAccessRequestService(deps.DB)
		prov := lifecycle.NewAccessProvisioningService(deps.DB, reqSvc, resolver)
		sched := lifecycle.NewScheduler(
			deps.DB,
			lifecycle.NewExpiryEnforcer(deps.DB, prov),
			lifecycle.NewOrphanReconciler(deps.DB, resolver),
			lifecycle.SchedulerConfig{},
		)
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
		logger.Infof(ctx, "ztna-api: lifecycle scheduler started (expiry + orphan reconciliation)")
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
	// process can never open more Postgres connections than configured.
	if err := database.ApplyPoolLimits(gdb, cfg.DBMaxOpenConns, cfg.DBMaxIdleConns, cfg.DBConnMaxLifetime); err != nil {
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
