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
	"sync/atomic"
	"syscall"
	"time"

	"gorm.io/gorm"

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
	deps.Ready = ready

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
	applied, err := migrations.Run(ctx, sqlDB)
	if err != nil {
		// Don't leak the pool if migrations fail.
		_ = sqlDB.Close()
		return nil, err
	}
	logger.Infof(ctx, "ztna-api: applied %d migration(s)", len(applied))
	return gdb, nil
}
