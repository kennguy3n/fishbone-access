// Command pam-gateway is the ShieldNet Access PAM multi-protocol proxy. It
// fronts privileged targets over SSH (2222), PostgreSQL (5432), MySQL (3306),
// and Kubernetes-exec (8443), minting short-lived credentials, recording each
// session, gating every command against the policy engine, and appending to
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

	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/broker"
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

// Agent relay timeouts. The server certificate is long-lived (the relay
// reissues it each boot from the CA) and the dial timeout bounds opening a
// brokered stream + handshaking the upstream through the agent tunnel.
const (
	agentRelayServerCertTTL = 365 * 24 * time.Hour
	agentRelayDialTimeout   = 15 * time.Second
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
	// ACCESS_DATABASE_DRIVER (the GORM→pgx migration). The chain bookkeeping is
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

	listeners, sessions, err := buildListeners(ctx, cfg, gdb, auditor)
	if err != nil {
		return fmt.Errorf("build listeners: %w", err)
	}

	sup := gateway.NewSupervisor(listeners)
	logger.Infof(ctx, "pam-gateway: ready; serving %d protocol listeners", len(listeners))
	runErr := sup.Run(ctx)
	// Listeners have stopped; flush any in-flight detached post-session advisory
	// scoring before the deferred database pool close so those audit writes are
	// not lost on shutdown. This runs on the error path too: listeners bind
	// sequentially, so a late bind failure can return an error after an earlier
	// listener briefly served traffic and spawned scoring goroutines — those are
	// tracked by sessions.bg, not the supervisor's wait group, so they must be
	// drained here regardless of how Run returned.
	sessions.Drain()
	if runErr != nil {
		return fmt.Errorf("supervisor: %w", runErr)
	}
	logger.Infof(context.Background(), "pam-gateway: shut down cleanly")
	return nil
}

// buildListeners constructs the PAM services and the ten protocol
// ConnHandlers, returning the supervisor listener set.
func buildListeners(ctx context.Context, cfg config.Config, gdb *gorm.DB, auditor database.AuditAppender) ([]gateway.Listener, *pam.SessionManager, error) {
	// Credential encryptor seals/opens per-target upstream credentials.
	// FromConfig prefers the per-workspace KMS master key (a distinct DEK per
	// workspace) and falls back to the single static DEK; with neither set it
	// returns a fail-closed encryptor, so a target with a sealed secret cannot
	// be opened in a misconfigured boot.
	enc, err := access.CredentialEncryptorFromConfig(cfg.KMSMasterKey, cfg.KMSKeyVersion, cfg.CredentialDEK)
	if err != nil {
		return nil, nil, fmt.Errorf("credential encryptor init: %w", err)
	}

	// Step-up MFA gate: wired only when iam-core is configured. When nil, a
	// target marked RequireMFA fails closed on reveal (the vault refuses to
	// open a gated secret without a configured gate).
	var stepUp *pam.StepUpGate
	if cfg.IAMCore.Configured() {
		v, verr := iamcore.NewValidator(ctx, cfg.IAMCore)
		if verr != nil {
			return nil, nil, fmt.Errorf("iam-core validator init: %w", verr)
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
		return nil, nil, fmt.Errorf("ai client init: %w", err)
	}
	if !ai.Configured() {
		logger.Warnf(ctx, "pam-gateway: AI agent not configured; lease risk scoring uses deterministic fallback")
	}
	// Score each privileged session's command stream when it ends (advisory,
	// fail-open): the verdict lands as a pam.session.risk_assessed audit event.
	// A nil/unconfigured client leaves this off, so an agent-less deployment
	// pays nothing.
	sessions.SetRiskScorer(ai)
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

	store, err := buildReplayStore(ctx, cfg, gdb, enc)
	if err != nil {
		return nil, nil, err
	}

	// Outbound connector agent relay. When an agent CA is configured this builds
	// the relay (the control-plane end of the agents' outbound mTLS tunnels) and
	// a broker dialer that routes "via agent" targets through it; the protocol
	// proxies take the dialer so a target marked via-agent is reached over the
	// agent's tunnel while every other target still dials directly. When no CA is
	// configured the dialer is nil (proxies default to direct) and no relay
	// listener is added — the feature stays entirely off.
	agentDialer, agentListeners, err := buildAgentRelay(ctx, cfg, gdb)
	if err != nil {
		return nil, nil, err
	}

	sshProxy, err := buildSSHProxy(ctx, broker, sessions, hub, store, agentDialer)
	if err != nil {
		return nil, nil, err
	}
	// Optional verified keypair for the operator-facing DB/k8s listeners. When
	// unset each proxy mints an ephemeral self-signed cert so the operator hop is
	// still encrypted (clients connect with sslmode=require / equivalent).
	proxyTLS, err := buildProxyTLSConfig(ctx)
	if err != nil {
		return nil, nil, err
	}
	pgProxy, err := gateway.NewPostgresProxy(gateway.PostgresProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store, TLSConfig: proxyTLS, Dialer: agentDialer})
	if err != nil {
		return nil, nil, err
	}
	myProxy, err := gateway.NewMySQLProxy(gateway.MySQLProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store, TLSConfig: proxyTLS, Dialer: agentDialer})
	if err != nil {
		return nil, nil, err
	}
	k8sProxy, err := gateway.NewK8sExecProxy(gateway.K8sExecProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store, TLSConfig: proxyTLS, Dialer: agentDialer})
	if err != nil {
		return nil, nil, err
	}

	// The remaining protocol proxies. Each follows the same pattern as the
	// SSH/Postgres/MySQL/k8s-exec proxies (token redemption, vault credential
	// injection, session recording, command gating, audit hash chain).
	//
	// RDP presents server-side TLS to the operator when the target uses Enhanced
	// RDP Security ("tls"/"nla"); reuse the shared operator-facing keypair.
	rdpProxy, err := gateway.NewRDPProxy(gateway.RDPProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store, TLSConfig: proxyTLS, Dialer: agentDialer})
	if err != nil {
		return nil, nil, err
	}
	vncProxy, err := gateway.NewVNCProxy(gateway.VNCProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store, Dialer: agentDialer})
	if err != nil {
		return nil, nil, err
	}
	mongoProxy, err := gateway.NewMongoProxy(gateway.MongoProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store, Dialer: agentDialer})
	if err != nil {
		return nil, nil, err
	}
	redisProxy, err := gateway.NewRedisProxy(gateway.RedisProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store, Dialer: agentDialer})
	if err != nil {
		return nil, nil, err
	}
	mssqlProxy, err := gateway.NewMSSQLProxy(gateway.MSSQLProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store, Dialer: agentDialer})
	if err != nil {
		return nil, nil, err
	}
	webProxy, err := gateway.NewWebProxy(gateway.WebProxyConfig{Broker: broker, Sessions: sessions, Hub: hub, Store: store, Dialer: agentDialer})
	if err != nil {
		return nil, nil, err
	}

	listeners := []gateway.Listener{
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
	}
	listeners = append(listeners, agentListeners...)
	return listeners, sessions, nil
}

// buildAgentRelay constructs the outbound connector agent relay and a broker
// dialer when an agent CA is configured. It returns (nil, nil, nil) when the
// feature is off, so the proxies fall back to direct dialing and no relay
// listener is bound. The relay verifies agent client certificates against the
// configured CA and presents a server certificate the same CA issued, so it
// shares trust with the ztna-api enrollment signer across processes.
//
// When the cross-replica forward plane is also configured (its own mTLS triad,
// separate from the agent CA) the relay additionally claims/refreshes/releases
// ownership of its tunnels in the durable session directory and an internal
// forward listener is returned alongside the relay listener, so a dial that
// lands on a replica NOT holding the tunnel is forwarded to the one that does.
func buildAgentRelay(ctx context.Context, cfg config.Config, gdb *gorm.DB) (gateway.TargetDialer, []gateway.Listener, error) {
	if !cfg.AgentBroker.Configured() {
		logger.Warnf(ctx, "pam-gateway: outbound agent CA not configured; via-agent targets cannot be brokered")
		return nil, nil, nil
	}
	ca, err := broker.LoadCAFromValues(cfg.AgentBroker.CACert, cfg.AgentBroker.CAKey)
	if err != nil {
		return nil, nil, fmt.Errorf("agent CA load: %w", err)
	}
	// Issue the relay's TLS server certificate from the agent CA so agents (which
	// were handed the CA at enrollment) verify it, valid for the configured SANs.
	serverCert, err := ca.IssueServerCert(cfg.AgentBroker.RelayHosts, agentRelayServerCertTTL)
	if err != nil {
		return nil, nil, fmt.Errorf("agent relay server cert: %w", err)
	}
	serverTLS := broker.NewRelayServerTLS(serverCert, ca)

	// Optional cross-replica HA forward plane. Its mTLS identity is loaded from a
	// CA DISTINCT from the agent CA (replicas authenticate to each other, never
	// with agent certs). When unconfigured the relay stays single-replica and a
	// non-local agent fails closed exactly as before.
	var relayOpts []broker.RelayOption
	var forwardTLS *broker.ForwardTLS
	if cfg.AgentBroker.CrossReplicaConfigured() {
		forwardTLS, err = broker.LoadForwardTLS(cfg.AgentBroker.ForwardCert, cfg.AgentBroker.ForwardKey, cfg.AgentBroker.ForwardCACert)
		if err != nil {
			return nil, nil, fmt.Errorf("agent forward mTLS load: %w", err)
		}
		var dir broker.SessionDirectory = broker.NewGormSessionDirectory(gdb, cfg.AgentBroker.DirectoryStaleAfter)
		// Optional Redis write-through fast-path for the owner-lookup read on the
		// cross-replica dial path. Postgres stays authoritative; the cache is
		// fail-open, so a malformed URL or Redis outage degrades to the direct
		// Postgres read rather than crashing a 5,000-tenant fleet.
		if cfg.DirectoryRedisActive() {
			if opt, perr := redis.ParseURL(cfg.RedisURL); perr != nil {
				logger.Warnf(ctx, "pam-gateway: ACCESS_REDIS_URL is malformed (%v); session directory falls back to direct Postgres reads", perr)
			} else {
				rdb := redis.NewClient(opt)
				go func() {
					<-ctx.Done()
					if cerr := rdb.Close(); cerr != nil {
						logger.Warnf(context.Background(), "pam-gateway: closing session-directory Redis client: %v", cerr)
					}
				}()
				dir = broker.NewRedisSessionDirectory(dir, rdb, broker.RedisDirectoryConfig{
					StaleAfter: cfg.AgentBroker.DirectoryStaleAfter,
				})
				logger.Infof(ctx, "pam-gateway: session-directory Redis fast-path enabled (fail-open; Postgres authoritative)")
			}
		}
		fwdClient := broker.NewForwardClient(forwardTLS, agentRelayDialTimeout)
		relayOpts = append(relayOpts, broker.WithCrossReplica(dir, fwdClient, cfg.AgentBroker.NodeID, cfg.AgentBroker.ForwardAddr))
	}

	relay := broker.NewRelay(broker.NewGormStore(gdb), serverTLS, relayOpts...)
	dialer := gateway.NewBrokerDialer(relay, agentRelayDialTimeout)
	listeners := []gateway.Listener{{Name: "agent-relay", Addr: cfg.AgentBroker.RelayListen, Handler: relay}}
	logger.Infof(ctx, "pam-gateway: outbound agent relay enabled on %s (advertise=%s, SANs=%v)",
		cfg.AgentBroker.RelayListen, cfg.AgentBroker.RelayAddr, cfg.AgentBroker.RelayHosts)

	if forwardTLS != nil {
		forwarder := broker.NewForwarder(relay, forwardTLS)
		listeners = append(listeners, gateway.Listener{Name: "agent-forward", Addr: cfg.AgentBroker.ForwardListen, Handler: forwarder})
		logger.Infof(ctx, "pam-gateway: cross-replica forward plane enabled node=%s listen=%s advertise=%s",
			cfg.AgentBroker.NodeID, cfg.AgentBroker.ForwardListen, cfg.AgentBroker.ForwardAddr)
	} else {
		logger.Warnf(ctx, "pam-gateway: cross-replica forward plane OFF; via-agent dials resolve only on the replica holding the tunnel")
	}
	return dialer, listeners, nil
}

// buildSSHProxy assembles the SSH proxy, loading the SSH CA (when configured)
// and a stable host key (or generating an ephemeral one).
func buildSSHProxy(ctx context.Context, broker *pam.Broker, sessions *pam.SessionManager, hub *gateway.SessionHub, store gateway.ReplayStore, dialer gateway.TargetDialer) (*gateway.SSHProxy, error) {
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
		Dialer:   dialer,
	})
}

// buildReplayStore selects the session-replay backend from the environment (an
// S3 bucket when PAM_REPLAY_S3_BUCKET is set, otherwise a filesystem store under
// PAM_REPLAY_DIR) and, when a per-workspace KMS key is configured, wraps it in
// transparent at-rest encryption so the recording blob — which holds typed
// secrets and query output — is sealed under the owning workspace's DEK in
// addition to the SHA-256 the recorder anchors for integrity. With no KMS key
// (dev/test) the plain store is used and behaviour is unchanged; the encrypting
// decorator also passes pre-encryption plaintext recordings through unchanged,
// so enabling a key never strands older blobs.
func buildReplayStore(ctx context.Context, cfg config.Config, gdb *gorm.DB, enc access.CredentialEncryptor) (gateway.ReplayStore, error) {
	base, err := gateway.OpenReplayStoreFromEnv(ctx)
	if err != nil {
		return nil, err
	}
	if !replayEncryptionConfigured(cfg) {
		logger.Warnf(ctx, "pam-gateway: replay blob at-rest encryption DISABLED (no ACCESS_KMS_MASTER_KEY); recordings are integrity-hashed but stored as plaintext")
		return base, nil
	}
	store, err := gateway.WrapWithEncryption(base, enc, gateway.NewGormSessionWorkspaceResolver(gdb))
	if err != nil {
		return nil, fmt.Errorf("replay at-rest encryption: %w", err)
	}
	logger.Infof(ctx, "pam-gateway: replay blob at-rest encryption ENABLED (per-workspace DEK)")
	return store, nil
}

// replayEncryptionConfigured reports whether a per-workspace KMS master key is
// configured. At-rest encryption uses the per-workspace derived DEK, so it is
// enabled only with a KMS master key (not the single static credential DEK,
// which is not workspace-scoped).
func replayEncryptionConfigured(cfg config.Config) bool {
	return cfg.KMSMasterKey != ""
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
