// Command pam-gateway is the ShieldNet Access PAM multi-protocol proxy. It
// fronts privileged targets over SSH (2222), PostgreSQL (5432), MySQL (3306),
// and Kubernetes-exec (8443), minting short-lived credentials, recording each
// session, gating every command against the 1C policy engine, and appending to
// the per-workspace audit hash chain.
//
// Boot model (mirrors ztna-api): when ACCESS_DATABASE_URL is set the binary
// opens a GORM Postgres pool, applies the SQL migrations, builds the PAM
// services (vault, connect-token broker, session manager, command policy) and
// the four protocol ConnHandlers, then runs them on the gateway.Supervisor.
// When the database is unset the binary boots in degraded mode (no listeners)
// so `go run` works without provisioning Postgres.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/config"
	"github.com/kennguy3n/fishbone-access/internal/gateway"
	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/migrations"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// protocolPlan documents the listener addresses pam-gateway binds. Kept here so
// deployment manifests (docker-compose, Helm) and this binary agree on ports.
var protocolPlan = []struct{ Name, Addr string }{
	{"ssh", ":2222"},
	{"postgres", ":5432"},
	{"mysql", ":3306"},
	{"k8s-exec", ":8443"},
}

func main() {
	if err := run(); err != nil {
		logger.Errorf(context.Background(), "pam-gateway: fatal: %v", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := config.Load()
	logger.Infof(ctx, "pam-gateway: starting; %s", cfg.String())

	if !cfg.DatabaseConfigured() {
		logger.Warnf(ctx, "pam-gateway: ACCESS_DATABASE_URL unset; booting in degraded mode (no listeners)")
		for _, p := range protocolPlan {
			logger.Infof(ctx, "pam-gateway: protocol %q planned on %s (database required to serve)", p.Name, p.Addr)
		}
		<-ctx.Done()
		logger.Infof(context.Background(), "pam-gateway: shutting down")
		return nil
	}

	gdb, err := setupDatabase(ctx, cfg)
	if err != nil {
		return fmt.Errorf("database setup: %w", err)
	}
	defer func() {
		if sqlDB, derr := gdb.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	}()

	listeners, err := buildListeners(ctx, cfg, gdb)
	if err != nil {
		return fmt.Errorf("build listeners: %w", err)
	}

	sup := gateway.NewSupervisor(listeners)
	logger.Infof(ctx, "pam-gateway: ready; serving %d protocol listeners", len(listeners))
	if err := sup.Run(ctx); err != nil {
		return fmt.Errorf("supervisor: %w", err)
	}
	logger.Infof(context.Background(), "pam-gateway: shut down cleanly")
	return nil
}

// buildListeners constructs the PAM services and the four protocol
// ConnHandlers, returning the supervisor listener set.
func buildListeners(ctx context.Context, cfg config.Config, gdb *gorm.DB) ([]gateway.Listener, error) {
	// Credential encryptor seals/opens per-target upstream credentials. FromKey
	// returns a fail-closed encryptor when no DEK is set, so a target with a
	// sealed secret cannot be opened in a misconfigured boot.
	enc, err := access.CredentialEncryptorFromKey(cfg.CredentialDEK)
	if err != nil {
		return nil, fmt.Errorf("credential encryptor init: %w", err)
	}

	// Step-up MFA gate: wired only when iam-core is configured. When nil, a
	// target marked RequireMFA fails closed on reveal (the vault refuses to
	// open a gated secret without a configured gate).
	var stepUp *pam.StepUpGate
	if cfg.IAMCore.Configured() {
		v, verr := iamcore.NewValidator(ctx, cfg.IAMCore)
		if verr != nil {
			return nil, fmt.Errorf("iam-core validator init: %w", verr)
		}
		stepUp = pam.NewStepUpGate(v, stepUpMaxAge())
		logger.Infof(ctx, "pam-gateway: step-up MFA enabled (issuer=%s)", cfg.IAMCore.Issuer)
	} else {
		logger.Warnf(ctx, "pam-gateway: iam-core NOT configured; MFA-gated targets fail closed on reveal")
	}

	vault := pam.NewVault(gdb, enc, stepUp)
	policy := pam.NewCommandPolicyEvaluator(gdb, 5*time.Second)
	hub := gateway.NewSessionHub()
	sessions := pam.NewSessionManager(gdb, policy, hub)
	broker := pam.NewBroker(gdb, vault, stepUp)

	store, err := buildReplayStore(ctx)
	if err != nil {
		return nil, err
	}

	sshProxy, err := buildSSHProxy(ctx, broker, sessions, hub, store)
	if err != nil {
		return nil, err
	}
	pgProxy, err := gateway.NewPostgresProxy(gateway.PostgresProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store})
	if err != nil {
		return nil, err
	}
	myProxy, err := gateway.NewMySQLProxy(gateway.MySQLProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store})
	if err != nil {
		return nil, err
	}
	k8sProxy, err := gateway.NewK8sExecProxy(gateway.K8sExecProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store})
	if err != nil {
		return nil, err
	}

	return []gateway.Listener{
		{Name: "ssh", Addr: ":2222", Handler: sshProxy},
		{Name: "postgres", Addr: ":5432", Handler: pgProxy},
		{Name: "mysql", Addr: ":3306", Handler: myProxy},
		{Name: "k8s-exec", Addr: ":8443", Handler: k8sProxy},
	}, nil
}

// buildSSHProxy assembles the SSH proxy, loading the SSH CA (when configured)
// and a stable host key (or generating an ephemeral one).
func buildSSHProxy(ctx context.Context, broker *pam.Broker, sessions *pam.SessionManager, hub *gateway.SessionHub, store gateway.ReplayStore) (*gateway.SSHProxy, error) {
	var ca *gateway.SSHCertificateAuthority
	if v := os.Getenv("PAM_SSH_CA_KEY"); v != "" {
		loaded, err := gateway.LoadSSHCAFromValue(v, sshCertValidity())
		if err != nil {
			return nil, fmt.Errorf("load ssh ca: %w", err)
		}
		ca = loaded
		logger.Infof(ctx, "pam-gateway: ssh CA loaded (fingerprint=%s)", ca.Fingerprint())
	} else {
		logger.Warnf(ctx, "pam-gateway: PAM_SSH_CA_KEY unset; SSH proxy uses vault credentials (no CA-signed certs)")
	}

	hostKey, err := gateway.GenerateHostKey()
	if err != nil {
		return nil, fmt.Errorf("ssh host key: %w", err)
	}

	return gateway.NewSSHProxy(gateway.SSHProxyConfig{
		Broker:   broker,
		Sessions: sessions,
		Hub:      hub,
		Store:    store,
		CA:       ca,
		HostKey:  hostKey,
	})
}

// buildReplayStore selects the session-replay backend from the environment: an
// S3 bucket when PAM_REPLAY_S3_BUCKET is set, otherwise a filesystem store
// under PAM_REPLAY_DIR (default ./pam-replays).
func buildReplayStore(ctx context.Context) (gateway.ReplayStore, error) {
	if bucket := os.Getenv("PAM_REPLAY_S3_BUCKET"); bucket != "" {
		region := os.Getenv("PAM_REPLAY_S3_REGION")
		var opts []gateway.S3Option
		if ep := os.Getenv("PAM_REPLAY_S3_ENDPOINT"); ep != "" {
			opts = append(opts, gateway.WithEndpointURL(ep), gateway.WithForcePathStyle(true))
		}
		store, err := gateway.NewS3ReplayStore(ctx, bucket, region, opts...)
		if err != nil {
			return nil, fmt.Errorf("s3 replay store: %w", err)
		}
		logger.Infof(ctx, "pam-gateway: replay store = s3://%s", bucket)
		return store, nil
	}
	dir := os.Getenv("PAM_REPLAY_DIR")
	if dir == "" {
		dir = "./pam-replays"
	}
	store, err := gateway.NewFilesystemReplayStore(dir)
	if err != nil {
		return nil, fmt.Errorf("filesystem replay store: %w", err)
	}
	logger.Infof(ctx, "pam-gateway: replay store = file://%s", dir)
	return store, nil
}

// setupDatabase opens Postgres, applies SQL migrations, and returns the pool.
func setupDatabase(ctx context.Context, cfg config.Config) (*gorm.DB, error) {
	gdb, err := database.Open(cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	if err := database.ApplyPoolLimits(gdb, cfg.DBMaxOpenConns, cfg.DBMaxIdleConns, cfg.DBConnMaxLifetime); err != nil {
		return nil, err
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		return nil, fmt.Errorf("resolve sql db: %w", err)
	}
	applied, err := migrations.Run(ctx, sqlDB)
	if err != nil {
		return nil, fmt.Errorf("apply migrations: %w", err)
	}
	if len(applied) > 0 {
		logger.Infof(ctx, "pam-gateway: applied %d migration(s): %v", len(applied), applied)
	}
	return gdb, nil
}

// stepUpMaxAge is the freshness window a step-up assertion must satisfy.
func stepUpMaxAge() time.Duration {
	return durationEnv("PAM_STEPUP_MAX_AGE", 5*time.Minute)
}

// sshCertValidity is the lifetime of an ephemeral SSH certificate.
func sshCertValidity() time.Duration {
	return durationEnv("PAM_SSH_CERT_TTL", 5*time.Minute)
}

// durationEnv parses a duration from the environment, falling back to def. A
// set-but-unparseable or non-positive value is logged at warn level so a typo
// like "5m0" (missing trailing 's') or "-1m" surfaces instead of silently
// reverting to the default.
func durationEnv(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	switch {
	case err != nil:
		logger.Warnf(context.Background(), "pam-gateway: %s=%q is not a valid duration (%v); using default %s", key, v, err, def)
	case d <= 0:
		logger.Warnf(context.Background(), "pam-gateway: %s=%q must be positive; using default %s", key, v, def)
	default:
		return d
	}
	return def
}
