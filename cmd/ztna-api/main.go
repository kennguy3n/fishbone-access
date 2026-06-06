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
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/config"
	"github.com/kennguy3n/fishbone-access/internal/handlers"
	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/migrations"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/access"

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

	if cfg.DatabaseConfigured() {
		if err := setupDatabase(ctx, cfg); err != nil {
			return fmt.Errorf("database setup: %w", err)
		}
	} else {
		logger.Warnf(ctx, "ztna-api: ACCESS_DATABASE_URL unset; booting in degraded mode (no DB)")
	}

	var deps handlers.Deps
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
	deps.Ready = ready

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handlers.NewRouter(deps),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		ready.Store(true)
		logger.Infof(ctx, "ztna-api: listening on %s", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Errorf(ctx, "ztna-api: server error: %v", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Infof(context.Background(), "ztna-api: shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	return nil
}

// setupDatabase opens Postgres, applies SQL migrations, and verifies
// connectivity. Auto-migrate is intentionally NOT used in production — the
// reviewable SQL migrations are authoritative.
func setupDatabase(ctx context.Context, cfg config.Config) error {
	gdb, err := database.Open(cfg.DatabaseURL)
	if err != nil {
		return err
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		return err
	}
	applied, err := migrations.Run(ctx, sqlDB)
	if err != nil {
		return err
	}
	logger.Infof(ctx, "ztna-api: applied %d migration(s)", len(applied))
	return nil
}
