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
	"crypto/tls"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/config"
	"github.com/kennguy3n/fishbone-access/internal/gateway"
	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/migrations"
	"github.com/kennguy3n/fishbone-access/internal/pkg/aiclient"
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
	{"rdp", ":3389"},
	{"vnc", ":5900"},
	{"mongodb", ":27017"},
	{"redis", ":6379"},
	{"mssql", ":1433"},
	{"http", ":8080"},
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
	if err := cfg.Validate(); err != nil {
		return err
	}
	for _, warning := range cfg.Warnings() {
		logger.Warnf(ctx, "pam-gateway: %s", warning)
	}
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

	// Route the Vault's standalone audit appends through the backend selected by
	// ACCESS_DATABASE_DRIVER (WS10/WS15 GORM→pgx migration). The chain bookkeeping is
	// shared via the auditchain package — same advisory lock, same version-1
	// canonical hash — so a standalone event links into the same per-workspace
	// hash chain as the in-transaction (GORM) appends regardless of which backend
	// writes it, and the two coexist on one chain during the migration.
	var auditor database.AuditAppender
	switch cfg.DatabaseDriver {
	case config.DriverPgx:
		// Open a pgxpool alongside GORM, closed after the supervisor returns so no
		// listener can race the close. It is sized by its own bound
		// (DBPgxMaxConns), independent of the GORM pool, because standalone audit
		// appends are low-volume; this keeps the added connection footprint small.
		// Opened only on the pgx path so a gorm-driver boot pays no second pool.
		pool, err := database.OpenPool(ctx, cfg.DatabaseURL, int32(cfg.DBPgxMaxConns), cfg.DBConnMaxLifetime, 0)
		if err != nil {
			return fmt.Errorf("pgx pool setup: %w", err)
		}
		defer pool.Close()
		auditor = database.NewPgxAuditRepo(pool)
		logger.Infof(ctx, "pam-gateway: pgxpool adapter enabled for standalone audit appends")
	case config.DriverGorm:
		// Reuse the GORM pool already opened above; no second pool.
		auditor = database.NewGormAuditRepo(gdb)
		logger.Infof(ctx, "pam-gateway: GORM backend enabled for standalone audit appends")
	default:
		// Unreachable today: cfg.Validate() rejects any other value at boot. The
		// branch is here so that adding a driver to DatabaseDriver.Valid() without
		// wiring it here fails fast instead of leaving auditor nil and panicking.
		return fmt.Errorf("pam-gateway: unsupported ACCESS_DATABASE_DRIVER %q", cfg.DatabaseDriver)
	}

	listeners, err := buildListeners(ctx, cfg, gdb, auditor)
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

// buildListeners constructs the PAM services and the ten protocol
// ConnHandlers, returning the supervisor listener set.
func buildListeners(ctx context.Context, cfg config.Config, gdb *gorm.DB, auditor database.AuditAppender) ([]gateway.Listener, error) {
	// Credential encryptor seals/opens per-target upstream credentials.
	// FromConfig prefers the per-workspace KMS master key (a distinct DEK per
	// workspace) and falls back to the single static DEK; with neither set it
	// returns a fail-closed encryptor, so a target with a sealed secret cannot
	// be opened in a misconfigured boot.
	enc, err := access.CredentialEncryptorFromConfig(cfg.KMSMasterKey, cfg.KMSKeyVersion, cfg.CredentialDEK)
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
	// Route the Vault's standalone audit append — today only the secret-reveal
	// event — through the pgxpool adapter; state-mutating events (target create,
	// secret rotate, connect-token mint, session open) use the in-transaction
	// GORM path so the audit row commits atomically with the change.
	vault.SetAuditor(auditor)
	policy := pam.NewCommandPolicyEvaluator(gdb, 5*time.Second)
	hub := gateway.NewSessionHub()
	sessions := pam.NewSessionManager(gdb, policy, hub)
	broker := pam.NewBroker(gdb, vault, stepUp)

	// JIT lease state machine. The AI client scores lease risk at request time
	// (fail-OPEN advisory: an unconfigured/unreachable agent degrades to a
	// deterministic fallback rather than blocking the request). Binding the
	// lease service to the broker makes connect-token mint/redeem fail closed
	// against a lease that expired or was revoked, and wiring the session
	// manager as the lease's session terminator means a revoked or swept-expired
	// lease tears down any session still brokering its credential.
	ai, err := aiclient.NewAIClientFromEnv()
	if err != nil {
		return nil, fmt.Errorf("ai client init: %w", err)
	}
	if !ai.Configured() {
		logger.Warnf(ctx, "pam-gateway: AI agent not configured; lease risk scoring uses deterministic fallback")
	}
	leases := pam.NewPAMLeaseService(gdb, ai)
	leases.SetSessionTerminator(sessions)
	broker.SetLeaseValidator(leases)

	// Cross-process session-control reconciler: pause/terminate issued through
	// the control-plane API land in the database; this loop applies that durable
	// intent to the sessions THIS gateway process is proxying. Tied to ctx so it
	// stops on shutdown.
	reconciler := gateway.NewSessionReconciler(hub, sessions, 0)
	go reconciler.Run(ctx)

	// Global JIT-lease TTL enforcement: the per-workspace POST /pam/leases/expire
	// is the on-demand entry point, but a multi-tenant deployment needs an
	// unattended sweeper so a lapsed lease's live sessions are reaped promptly
	// without every tenant polling. Idempotent per-lease claims make this safe to
	// run in every gateway process. Tied to ctx so it stops on shutdown.
	go leases.RunExpirySweep(ctx, 0)

	store, err := buildReplayStore(ctx)
	if err != nil {
		return nil, err
	}

	sshProxy, err := buildSSHProxy(ctx, broker, sessions, hub, store)
	if err != nil {
		return nil, err
	}
	// Optional verified keypair for the operator-facing DB/k8s listeners. When
	// unset each proxy mints an ephemeral self-signed cert so the operator hop is
	// still encrypted (clients connect with sslmode=require / equivalent).
	proxyTLS, err := buildProxyTLSConfig(ctx)
	if err != nil {
		return nil, err
	}
	pgProxy, err := gateway.NewPostgresProxy(gateway.PostgresProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store, TLSConfig: proxyTLS})
	if err != nil {
		return nil, err
	}
	myProxy, err := gateway.NewMySQLProxy(gateway.MySQLProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store, TLSConfig: proxyTLS})
	if err != nil {
		return nil, err
	}
	k8sProxy, err := gateway.NewK8sExecProxy(gateway.K8sExecProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store, TLSConfig: proxyTLS})
	if err != nil {
		return nil, err
	}

	// Workstream 1 protocol proxies. Each follows the same pattern as the
	// original four (token redemption, vault credential injection, session
	// recording, 1C command gating, audit hash chain).
	//
	// RDP presents server-side TLS to the operator when the target uses Enhanced
	// RDP Security ("tls"/"nla"); reuse the shared operator-facing keypair.
	rdpProxy, err := gateway.NewRDPProxy(gateway.RDPProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store, TLSConfig: proxyTLS})
	if err != nil {
		return nil, err
	}
	vncProxy, err := gateway.NewVNCProxy(gateway.VNCProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store})
	if err != nil {
		return nil, err
	}
	mongoProxy, err := gateway.NewMongoProxy(gateway.MongoProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store})
	if err != nil {
		return nil, err
	}
	redisProxy, err := gateway.NewRedisProxy(gateway.RedisProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store})
	if err != nil {
		return nil, err
	}
	mssqlProxy, err := gateway.NewMSSQLProxy(gateway.MSSQLProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store})
	if err != nil {
		return nil, err
	}
	webProxy, err := gateway.NewWebProxy(gateway.WebProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store})
	if err != nil {
		return nil, err
	}

	return []gateway.Listener{
		{Name: "ssh", Addr: ":2222", Handler: sshProxy},
		{Name: "postgres", Addr: ":5432", Handler: pgProxy},
		{Name: "mysql", Addr: ":3306", Handler: myProxy},
		{Name: "k8s-exec", Addr: ":8443", Handler: k8sProxy},
		{Name: "rdp", Addr: ":3389", Handler: rdpProxy},
		{Name: "vnc", Addr: ":5900", Handler: vncProxy},
		{Name: "mongodb", Addr: ":27017", Handler: mongoProxy},
		{Name: "redis", Addr: ":6379", Handler: redisProxy},
		{Name: "mssql", Addr: ":1433", Handler: mssqlProxy},
		{Name: "http", Addr: ":8080", Handler: webProxy},
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

	// Prefer a stable host key (PAM_SSH_HOST_KEY, inline PEM or a file path) so
	// the listener's fingerprint survives restarts and operators' SSH clients do
	// not warn about a changed host key. Fall back to an ephemeral key only when
	// none is configured (development).
	var hostKey ssh.Signer
	if v := os.Getenv("PAM_SSH_HOST_KEY"); v != "" {
		loaded, lerr := gateway.LoadHostKeyFromValue(v)
		if lerr != nil {
			return nil, fmt.Errorf("load ssh host key: %w", lerr)
		}
		hostKey = loaded
		logger.Infof(ctx, "pam-gateway: ssh host key loaded (fingerprint=%s)", ssh.FingerprintSHA256(hostKey.PublicKey()))
	} else {
		generated, gerr := gateway.GenerateHostKey()
		if gerr != nil {
			return nil, fmt.Errorf("ssh host key: %w", gerr)
		}
		hostKey = generated
		logger.Warnf(ctx, "pam-gateway: PAM_SSH_HOST_KEY unset; using ephemeral host key (fingerprint changes each boot, clients TOFU)")
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

// buildProxyTLSConfig loads a shared TLS keypair for the operator-facing
// PostgreSQL/MySQL/k8s listeners from PAM_PROXY_TLS_CERT and PAM_PROXY_TLS_KEY
// (PEM file paths). When either is unset it returns (nil, nil) and each proxy
// falls back to an ephemeral self-signed cert. Both set or neither: a single
// set value is a misconfiguration and fails fast.
func buildProxyTLSConfig(ctx context.Context) (*tls.Config, error) {
	certPath := os.Getenv("PAM_PROXY_TLS_CERT")
	keyPath := os.Getenv("PAM_PROXY_TLS_KEY")
	if certPath == "" && keyPath == "" {
		logger.Warnf(ctx, "pam-gateway: PAM_PROXY_TLS_CERT/KEY unset; DB & k8s proxies use ephemeral self-signed certs")
		return nil, nil
	}
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("pam-gateway: PAM_PROXY_TLS_CERT and PAM_PROXY_TLS_KEY must both be set")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load proxy tls keypair: %w", err)
	}
	logger.Infof(ctx, "pam-gateway: DB & k8s proxies use configured TLS keypair (%s)", certPath)
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
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
