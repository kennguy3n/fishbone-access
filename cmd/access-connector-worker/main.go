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
	"github.com/kennguy3n/fishbone-access/internal/services/access"
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

	enc, err := access.CredentialEncryptorFromKey(cfg.CredentialDEK)
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
	if cfg.CredentialDEK == "" {
		// The disabled (fail-closed) encryptor is wired: provisioning/revoke
		// jobs that need to open secrets will error per-job. Log loudly so the
		// misconfiguration is visible rather than surfacing only as job failures.
		logger.Warnf(ctx, "access-connector-worker: ACCESS_CREDENTIAL_DEK unset; jobs needing connector secrets will fail closed")
	}

	queue := workers.NewPostgresQueue(gdb)
	processor := access.NewConnectorJobProcessor(gdb, enc)
	w := workers.New(queue, processor, workers.Config{})

	logger.Infof(ctx, "access-connector-worker: ready; draining access_jobs")
	if err := w.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	logger.Infof(context.Background(), "access-connector-worker: shutting down")
	return nil
}
