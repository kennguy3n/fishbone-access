// Package config loads the ShieldNet Access platform configuration from the
// process environment. Every binary (ztna-api, access-connector-worker,
// pam-gateway) calls Load exactly once at boot and threads the returned Config
// through its service constructors.
//
// The configuration is intentionally env-driven (12-factor) so the same image
// runs across the three cost-optimised deployment tiers (single-server
// docker-compose, managed K8s, full production) with nothing but environment
// changes.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// DatabaseDriver selects which backend implements the repository contracts that
// have both a GORM and a pgxpool implementation (workspace-config reads in
// ztna-api, standalone audit appends in pam-gateway). The two backends honour an
// identical contract — same queries, same soft-delete scoping, same
// gorm.ErrRecordNotFound sentinel, and the same per-workspace advisory lock and
// version-1 canonical audit hash via the shared auditchain package — so the flag
// only chooses the driver, never the behaviour, and lets the GORM→pgx migration
// proceed by flipping one environment variable per deployment with an instant
// rollback path.
type DatabaseDriver string

const (
	// DriverPgx routes those repositories through the github.com/jackc/pgx/v5
	// pgxpool adapter. It is the default because it is the lighter path for the
	// hot workspace-config read and the standalone audit append.
	DriverPgx DatabaseDriver = "pgx"
	// DriverGorm routes those repositories through the incumbent GORM pool, so a
	// deployment can fall back to the battle-tested backend without a redeploy.
	DriverGorm DatabaseDriver = "gorm"
	// defaultDatabaseDriver preserves the pre-flag behaviour, where ztna-api and
	// pam-gateway always used the pgx adapter for these paths.
	defaultDatabaseDriver = DriverPgx
)

// Valid reports whether d is a recognised driver.
func (d DatabaseDriver) Valid() bool {
	return d == DriverPgx || d == DriverGorm
}

// Config is the fully-resolved platform configuration.
type Config struct {
	// Env is the deployment environment label ("dev", "staging", "prod").
	Env string
	// HTTPAddr is the listen address for the ztna-api HTTP server.
	HTTPAddr string
	// WorkerMetricsAddr is the listen address for the background WORKER
	// binaries' minimal /metrics + /healthz server (access-connector-worker,
	// access-workflow-engine). Those binaries have no API server of their own,
	// but the aggregate hibernation skip counter increments inside them, so
	// they must be scrapable for the scale-to-zero saving to be observable.
	// ztna-api ignores this (it serves /metrics on HTTPAddr). Read from
	// ACCESS_WORKER_METRICS_ADDR; defaults to ":9090". Set empty to disable.
	WorkerMetricsAddr string
	// DatabaseURL is the Postgres DSN. When empty the binary boots in
	// degraded mode (handlers that need the DB return 503) so `go run`
	// works without provisioning Postgres.
	DatabaseURL string
	// RedisURL is the Redis connection URL (ACCESS_REDIS_URL). It is the shared
	// store seam for the globally-exact rate limiter and the cross-replica usage
	// accumulator (see RateLimitConfig.SharedStore and
	// UsageMeteringConfig.SharedStore), and the future worker-queue backend. It
	// is parsed and dialled only when a feature that needs it is enabled;
	// optional otherwise (degraded mode, and the default per-replica posture).
	RedisURL string
	// DBMaxOpenConns bounds the Postgres pool's total open connections.
	// ztna-api and access-connector-worker share a database but run as
	// separate processes, so each sizes its own pool; keeping a bound avoids
	// exhausting Postgres' max_connections under load.
	DBMaxOpenConns int
	// DBPgxMaxConns bounds the secondary pgxpool that the GORM→pgx
	// migration opens alongside the GORM pool (workspace-config reads in
	// ztna-api, standalone audit appends in pam-gateway). It is sized
	// independently and small by default because those paths are light — a
	// single indexed lookup or one append per event — so the pgx pool need not
	// mirror the full GORM budget. The per-process connection footprint is
	// therefore DBMaxOpenConns + DBPgxMaxConns; operators sizing Postgres'
	// max_connections across replicas should account for both.
	DBPgxMaxConns int
	// DBMaxIdleConns bounds idle (kept-warm) connections in the pool.
	DBMaxIdleConns int
	// DBConnMaxLifetime caps how long a single connection is reused before
	// being recycled, so a long-lived process picks up Postgres failovers and
	// avoids accumulating server-side state on stale backends.
	DBConnMaxLifetime time.Duration
	// DBConnMaxIdleTime closes a connection that has sat idle for this long,
	// dropping the pool BELOW DBMaxIdleConns during quiet periods instead of
	// holding warm connections open. This is a NoOps lever for the 5,000-tenant
	// fleet: SME traffic is bursty and diurnal, so a control-plane replica that
	// goes quiet (nights/weekends) returns its connections to Postgres rather
	// than reserving max_connections headroom it is not using. Non-positive
	// leaves idle connections un-aged (only DBConnMaxLifetime recycles them).
	DBConnMaxIdleTime time.Duration
	// DatabaseDriver selects the backend (pgx or gorm) for the repositories that
	// have both implementations. Read from ACCESS_DATABASE_DRIVER; defaults to pgx.
	// Validate rejects an unrecognised value so a typo fails the boot loudly
	// rather than silently falling back to a backend the operator did not pick.
	DatabaseDriver DatabaseDriver
	// CredentialDEK is the base64-encoded 32-byte AES-256 key used to seal
	// connector secrets at rest. When empty the binary refuses to persist
	// secrets (fails closed) rather than storing plaintext.
	CredentialDEK string

	// KMSMasterKey is the base64-encoded 32-byte master key (KEK) for the
	// per-workspace key manager. When set it is PREFERRED over CredentialDEK:
	// the binary derives a distinct AES-256 DEK per workspace from this key
	// (HKDF), giving tenant key separation without an external KMS — the
	// local/dev posture, with the same KeyManager seam a real KMS plugs into.
	// Read from ACCESS_KMS_MASTER_KEY.
	KMSMasterKey string

	// KMSKeyVersion is the current key version new writes seal under when
	// KMSMasterKey is set; bumping it rotates the derived DEK while rows sealed
	// under earlier versions still open. Read from ACCESS_KMS_KEY_VERSION;
	// defaults to 1.
	KMSKeyVersion int

	// Tenancy holds the multi-tenant scale/dormancy knobs that let the control
	// plane serve thousands of SME tenants under NoOps, hibernating the large
	// dormant-trial fraction so they consume near-zero periodic compute.
	Tenancy TenancyConfig

	// RateLimit caps the inbound request rate PER TENANT on the authenticated
	// API surface, so one noisy or runaway tenant cannot monopolise the shared
	// Postgres pool (and our bill) at the expense of the other tenants.
	RateLimit RateLimitConfig

	// Rotation tunes the credential-rotation sweep the workflow engine runs:
	// how often it scans for due rotations and the actor it records. The sweep
	// is set-based and hibernation-gated, so it stays cheap at 5k tenants.
	Rotation RotationConfig

	// UsageMetering accumulates per-tenant usage counts (API calls today) and
	// flushes them to the tenant_usage rollup so cost-to-serve is attributable
	// per tenant. It is the "who is using what" half of the cost story; the
	// rate limiter above is the "cap the abuser" half.
	UsageMetering UsageMeteringConfig

	// Billing turns the usage rollup into per-tenant statements and enforces
	// per-tenant plan quotas (soft warnings + hard caps). It is the economics
	// layer ON TOP of UsageMetering: statements derive from the same rollup, and
	// enforcement caps a runaway tenant before it burns shared resources (and the
	// bill).
	Billing BillingConfig

	// Recordings tunes the searchable session-recording forensic store: the
	// background index + retention-prune sweep cadence and the default
	// retention window. It is safe-by-default (pruning OFF until a window is
	// configured) so the feature never deletes forensic evidence without an
	// explicit policy.
	Recordings RecordingsConfig

	// WebAccess holds the clientless browser-access bridge settings: the
	// in-browser web-SSH terminal and the web database console served over a
	// WebSocket on ztna-api. It reuses the PAM gateway's leasing,
	// command-policy, recording, and audit machinery; these knobs only tune the
	// bridge's resource envelope (idle timeout, recording cap, upstream dial
	// timeout) so it stays cheap and safe-by-default across the dormant fleet.
	WebAccess WebAccessConfig

	// IAMCore holds the iam-core identity-provider integration settings.
	IAMCore IAMCoreConfig

	// DevAuth holds the non-production HMAC bearer-token settings. It is the
	// developer-convenience identity path used by the blog seed/capture
	// harnesses to drive the real control-plane API without standing up
	// iam-core. It is honoured ONLY in non-production builds and refused when
	// Env is a production label (see DevAuthAllowed); production binaries omit
	// the validator entirely (internal/iamcore/devauth_prod.go).
	DevAuth DevAuthConfig

	// AgentBroker configures the outbound connector agent feature (CA, relay
	// listen/advertise addresses). OFF by default.
	AgentBroker AgentBrokerConfig

	// ShutdownTimeout bounds graceful HTTP shutdown.
	ShutdownTimeout time.Duration
}

// TenancyConfig tunes tenant dormancy detection and hibernation. The defaults
// target a 5,000-SME NoOps deployment where a large fraction of tenants are
// dormant trials: those are detected by idle time and excluded from periodic
// work until they show real activity again, so steady-state cost tracks the
// active-tenant count rather than the provisioned-tenant count.
type TenancyConfig struct {
	// HibernationEnabled gates the whole subsystem. When false the gate always
	// reports "run" (no tenant is ever hibernated) so an operator can disable
	// the optimisation without code changes. Read from
	// ACCESS_TENANCY_HIBERNATION_ENABLED; defaults to true.
	HibernationEnabled bool
	// DormantIdleThreshold is how long a tenant must go without recorded
	// activity before it is classified dormant. The default (14 days) matches a
	// typical trial window: a trial that nobody has touched in two weeks should
	// stop costing periodic compute. Read from ACCESS_TENANCY_DORMANT_IDLE.
	DormantIdleThreshold time.Duration
	// ReconcileInterval is how often the dormancy sweep runs to (re)classify
	// tenants as a set-based UPDATE. It need not be frequent — dormancy is a
	// slow signal — so the default is 15m to keep the sweep cost negligible.
	// Read from ACCESS_TENANCY_RECONCILE_INTERVAL.
	ReconcileInterval time.Duration
	// ActivityFlushInterval is the write-coalescing window for activity
	// recording: at most one DB write per tenant per window, so a tenant under
	// sustained API load does not amplify into one write per request. It MUST be
	// far smaller than DormantIdleThreshold (the recorder enforces this) so a
	// coalesced burst can never hide a wake-from-dormant. Read from
	// ACCESS_TENANCY_ACTIVITY_FLUSH; defaults to 60s.
	ActivityFlushInterval time.Duration
	// ActivityQueueSize bounds the recorder's buffered enqueue channel. It is
	// sized above the tenant target so a synchronised cold-start burst (every
	// tenant's first request landing in one drain cycle, before per-tenant
	// coalescing has populated) is absorbed without dropping events; steady
	// state sits far below this because coalescing caps enqueues at one per
	// tenant per ActivityFlushInterval. Read from
	// ACCESS_TENANCY_ACTIVITY_QUEUE_SIZE; defaults to 8192 (> the 5,000-tenant
	// target with headroom). Dropped events are best-effort and re-enqueued by
	// the next request, so this is a tuning lever, not a correctness bound.
	ActivityQueueSize int
	// DefaultTier is the resource-budget tier applied to a tenant with no
	// explicit per-workspace budget row (see internal/services/tenancy). Read
	// from ACCESS_TENANCY_DEFAULT_TIER; defaults to "trial" (the most
	// constrained tier) so an un-tiered tenant cannot consume an active
	// tenant's share.
	DefaultTier string
}

// RecordingsConfig tunes the searchable session-recording forensic store's
// background sweep (cmd/access-workflow-engine). The sweep indexes finished PAM
// sessions into the searchable projection and tiers expired replay blobs out of
// object storage per the retention policy, hibernation-gated and fail-open like
// the review sweep.
type RecordingsConfig struct {
	// SweepEnabled gates the background index + prune sweep. When false the
	// engine runs no recordings maintenance (recordings are still searchable if
	// indexed by a prior run, and the API still serves them) — an operator can
	// disable the optimisation without code changes. Read from
	// ACCESS_RECORDING_SWEEP_ENABLED; defaults to true.
	SweepEnabled bool
	// SweepInterval is how often a full index+prune round runs over all
	// workspaces. Recordings are not latency-sensitive to index, so the default
	// (1h) keeps fleet-wide cost negligible. Read from
	// ACCESS_RECORDING_SWEEP_INTERVAL.
	SweepInterval time.Duration
	// DefaultRetentionDays is the plan/global retention window applied to a
	// workspace with NO explicit override (the per-workspace policy always wins).
	// 0 means "retain indefinitely", the safe default: the sweep never tiers a
	// blob out until a tenant (or an operator, fleet-wide) opts into a finite
	// window, so evidence is never deleted by default. Read from
	// ACCESS_RECORDING_RETENTION_DAYS.
	DefaultRetentionDays int
	// IndexBatch and PruneBatch bound the per-workspace work each sweep round
	// performs, so one busy tenant's backlog cannot monopolise a round. Read
	// from ACCESS_RECORDING_INDEX_BATCH / ACCESS_RECORDING_PRUNE_BATCH.
	IndexBatch int
	PruneBatch int
}

// RotationConfig tunes the credential-rotation sweep run inside the workflow
// engine. It is safe-by-default: rotation only happens for targets an operator
// has explicitly given a policy, so enabling the sweep cannot rotate anything
// unexpectedly.
type RotationConfig struct {
	// Enabled gates the periodic sweep. When false the workflow engine does not
	// start the rotation scheduler at all (on-demand "rotate now" via the API is
	// unaffected — it is never gated). Read from ACCESS_ROTATION_ENABLED;
	// defaults to true so a configured policy actually rotates.
	Enabled bool
	// SweepInterval is how often the scheduler scans for due rotations and reaps
	// expired dynamic credentials. The scan is set-based (O(due rows)), so a
	// short cadence stays cheap at 5k tenants; it should be short enough that
	// rotate-on-checkin fires promptly after a lease ends. Read from
	// ACCESS_ROTATION_SWEEP_INTERVAL; defaults to 60s (matches the lease sweep).
	SweepInterval time.Duration
	// DialTimeout bounds every upstream connection a rotation or ephemeral-cred
	// mint/drop makes (SSH/Postgres/MySQL). Read from
	// ACCESS_ROTATION_DIAL_TIMEOUT; defaults to 10s.
	DialTimeout time.Duration
}

// RateLimitConfig tunes the per-tenant inbound request limiter. The limiter is
// in-memory and therefore per-process: with N ztna-api replicas a tenant's
// effective ceiling is N×RequestsPerSecond. This is the deliberate local/dev
// posture (no extra infrastructure) and still bounds a single abusive tenant to
// a small multiple of the configured rate; a globally exact limit would use the
// ACCESS_REDIS_URL seam.
type RateLimitConfig struct {
	// Enabled gates the limiter. When false the API surface is not rate-limited
	// (the pre-feature behaviour). Read from ACCESS_TENANT_RATE_LIMIT_ENABLED;
	// defaults to true — protecting the shared pool is the safer default at
	// 5,000 tenants, and the defaults below are generous enough not to shape
	// normal SME usage.
	Enabled bool
	// RequestsPerSecond is the sustained per-tenant refill rate. Read from
	// ACCESS_TENANT_RATE_LIMIT_RPS; defaults to 50.
	RequestsPerSecond float64
	// Burst is the per-tenant bucket depth — the most requests a tenant may
	// make instantaneously before being shaped to RequestsPerSecond. A single
	// dashboard page load fans out into several XHRs, so this is set well above
	// RequestsPerSecond. Read from ACCESS_TENANT_RATE_LIMIT_BURST; defaults to
	// 100.
	Burst int
	// SharedStore opts the limiter into the globally-exact, Redis-backed
	// backend (an atomic server-side token bucket) instead of the per-replica
	// in-memory one, so a tenant's ceiling is RequestsPerSecond across the whole
	// fleet rather than N×RequestsPerSecond. Read from
	// ACCESS_TENANT_RATE_LIMIT_SHARED_STORE; defaults to false (the no-extra-
	// infrastructure posture). It is ONLY honoured when ACCESS_REDIS_URL is also
	// set — without a shared store there is nothing to share, so the wiring
	// falls back to the in-memory limiter and Warnings flags the dropped intent.
	// The Redis path is fail-open: a Redis outage reverts to admitting requests,
	// never to rejecting them.
	SharedStore bool
}

// UsageMeteringConfig tunes the per-tenant usage-metering rollup. Per-tenant
// usage counts (API calls today) are accumulated in-process and flushed to the
// tenant_usage table on an interval so cost-to-serve is attributable per
// tenant. Unlike the Prometheus instruments — which are deliberately NOT
// labelled by tenant id (5,000 tenants × routes would explode the series
// count) — the rollup is keyed by workspace_id in Postgres, where per-tenant
// cardinality is cheap; only AGGREGATE (non-tenant) counters reach /metrics.
//
// The aggregator is in-memory and therefore per-replica: each replica flushes
// its own deltas with an additive UPSERT (count = count + delta), so N replicas
// sum correctly into one row rather than overwriting each other. This mirrors
// the rate limiter's per-replica posture and needs no extra infrastructure.
type UsageMeteringConfig struct {
	// Enabled gates the subsystem. When false no usage is accumulated or
	// persisted (the pre-feature behaviour). Read from
	// ACCESS_USAGE_METERING_ENABLED; defaults to true — attributing
	// cost-to-serve is the safer default at 5,000 tenants, and the hot-path
	// cost is a single in-memory counter increment.
	Enabled bool
	// FlushInterval is how often accumulated per-tenant deltas are flushed to
	// the tenant_usage table (and the bound on how stale the read endpoint /
	// operator dashboards are). It also bounds write volume: at most one row
	// per (active tenant × metric) per interval, regardless of request rate,
	// since counts coalesce in memory between flushes. Read from
	// ACCESS_USAGE_METERING_FLUSH_INTERVAL; defaults to 30s.
	FlushInterval time.Duration
	// SharedStore opts metering into the Redis-backed cross-replica accumulator:
	// per-replica deltas are first summed into one shared Redis counter and a
	// single claim-based flush rolls that global counter up into the
	// tenant_usage table, instead of every replica writing the same row each
	// window. Postgres stays the durable record. Read from
	// ACCESS_USAGE_METERING_SHARED_STORE; defaults to false. ONLY honoured when
	// ACCESS_REDIS_URL is also set; otherwise the wiring falls back to the
	// per-replica additive UPSERT (already cross-replica correct) and Warnings
	// flags the dropped intent. The Redis path is fail-open: a Redis outage
	// degrades to the Postgres path or drops, never blocking a request.
	SharedStore bool
}

// BillingConfig tunes the per-tenant billing economics layer: statement
// generation and quota enforcement. Plans reuse the tenancy tier ladder
// (trial/base/pro/enterprise); the quota ladders and pricing live in code
// (internal/services/billing), so this config only gates the feature, chooses
// whether hard caps actually deny, and tunes the per-replica decision cache.
//
// The enforcement cache is in-memory and therefore per-replica, exactly like
// the rate limiter and the usage aggregator: each replica caches a tenant's
// decision for CacheTTL, so the fleet converges within that TTL without a
// per-request DB read or any shared infrastructure.
type BillingConfig struct {
	// Enabled gates the whole subsystem (the billing read/admin endpoints AND
	// the quota-enforcement middleware). It defaults to FALSE — unlike metering,
	// enforcement can reject requests, so it is opt-in: an operator turns it on
	// deliberately (typically first in shadow mode, see EnforceHardCap). Read
	// from ACCESS_BILLING_ENABLED.
	Enabled bool
	// EnforceHardCap controls whether an over-hard-ceiling tenant is actually
	// denied (402) or merely flagged. It defaults to FALSE: the safe rollout at
	// 5,000 tenants is "shadow mode" — detect and surface breaches (headers +
	// metrics) without rejecting — so an operator can see who WOULD be capped
	// before flipping enforcement on and risking a surprise mass-rejection. Read
	// from ACCESS_BILLING_ENFORCE_HARD_CAP.
	EnforceHardCap bool
	// CacheTTL is how long a per-workspace quota decision is reused before a
	// refresh — the window over which a replica's enforcement lags fresh usage,
	// and (with the meter's flush interval) the bound on cross-replica
	// convergence. Read from ACCESS_BILLING_CACHE_TTL; defaults to 30s. A
	// non-positive value falls back to the service's built-in default.
	CacheTTL time.Duration
}

// AgentBrokerConfig configures the outbound connector agent feature: the
// control-plane CA that signs agent identities, where the relay listens, and
// the public address agents are told to dial. The whole feature is OFF by
// default (no CA configured) so a deployment that does not use outbound agents
// pays nothing and the enrollment endpoint stays absent — safe-by-default and
// fail-closed: a target marked "via agent" cannot be brokered unless the
// operator deliberately wired a CA and relay.
type AgentBrokerConfig struct {
	// CACert / CAKey are the PEM-encoded agent CA certificate and private key
	// (inline PEM value, or a path to a file containing it — resolved by the
	// binaries). ztna-api uses the pair to SIGN agent client certificates and
	// to issue the relay server certificate; pam-gateway uses it to verify
	// agent client certificates and present the relay server certificate. Both
	// binaries must be given the SAME CA. When CACert is empty the feature is
	// disabled. Read from ACCESS_AGENT_CA_CERT / ACCESS_AGENT_CA_KEY.
	CACert string
	CAKey  string
	// RelayListen is the pam-gateway bind address for the agent relay listener
	// (plain TCP; the relay performs the mTLS handshake itself). Read from
	// ACCESS_AGENT_RELAY_LISTEN; defaults to ":7443".
	RelayListen string
	// RelayAddr is the PUBLIC host:port agents are told to dial out to (embedded
	// in the enrollment response). It must resolve from the customer network to
	// this deployment's relay. Read from ACCESS_AGENT_RELAY_ADDR; defaults to
	// the RelayListen value for single-host dev.
	RelayAddr string
	// RelayHosts are the DNS names / IPs the relay's server certificate is valid
	// for (SANs). Comma-separated. Read from ACCESS_AGENT_RELAY_HOSTS; defaults
	// to "localhost,127.0.0.1" for dev.
	RelayHosts []string

	// --- Cross-replica session directory + forward plane (HA) ---------------
	//
	// In a multi-replica deployment an agent's tunnel terminates on exactly one
	// pam-gateway replica, but a privileged session may be handled by another.
	// These settings let a replica that does NOT hold a tunnel forward the dial
	// to the replica that does, via a durable session directory and an internal
	// replica-to-replica mTLS listener. The whole forward plane is OFF unless
	// ForwardCACert + ForwardCert + ForwardKey are all set: a single-replica
	// deployment pays nothing and a non-local agent simply fails closed as
	// before — safe-by-default.

	// NodeID is this replica's stable identity, written into the directory as
	// the owner of the tunnels it holds. Read from ACCESS_AGENT_NODE_ID;
	// defaults to the OS hostname (the pod name under Kubernetes), so a typical
	// deployment needs no explicit value.
	NodeID string
	// ForwardListen is the bind address for the internal forward listener (plain
	// TCP; the forwarder performs the inter-replica mTLS handshake itself). Read
	// from ACCESS_AGENT_FORWARD_LISTEN; defaults to ":7444".
	ForwardListen string
	// ForwardAddr is the INTERNAL host:port peer replicas dial to reach this
	// replica's forward listener (a pod IP / headless-service address, never
	// exposed to tenants). Written into the directory so peers can forward here.
	// Read from ACCESS_AGENT_FORWARD_ADDR. When empty the replica claims no
	// ownership (it can still forward to others but cannot be forwarded to).
	ForwardAddr string
	// ForwardCACert / ForwardCert / ForwardKey are the inter-replica mTLS
	// material — DELIBERATELY SEPARATE from the agent CA: replicas authenticate
	// to each other, never with agent certificates. Each is an inline PEM value
	// or a path. ForwardCACert is the CA every replica trusts; ForwardCert /
	// ForwardKey are this replica's forward identity (valid for both client and
	// server auth). Read from ACCESS_AGENT_FORWARD_CA / ACCESS_AGENT_FORWARD_CERT
	// / ACCESS_AGENT_FORWARD_KEY. All three together gate the forward plane.
	ForwardCACert string
	ForwardCert   string
	ForwardKey    string
	// DirectoryStaleAfter is how long after a missed heartbeat an owner is
	// treated as crashed: a forwarded dial against a stale owner fails closed,
	// and global online state ignores it. Read from
	// ACCESS_AGENT_DIRECTORY_STALE_AFTER; non-positive uses the broker's
	// HealthOfflineAfter so the directory and the health surface agree.
	DirectoryStaleAfter time.Duration
	// DirectoryRedisFastPath opts the session directory into a Redis write-
	// through cache in front of Postgres for the one hot read on the cross-
	// replica dial path (owner lookup), mirroring the rate-limiter / usage
	// shared-store toggles. Postgres stays the source of truth and the cache is
	// FAIL-OPEN: a Redis outage degrades to a direct Postgres read, never to a
	// wrong or failed routing decision. Read from ACCESS_AGENT_DIRECTORY_REDIS;
	// defaults to false. ONLY honoured when ACCESS_REDIS_URL is also set (there
	// is nothing to cache in without it).
	DirectoryRedisFastPath bool
}

// Configured reports whether an agent CA certificate was supplied, which gates
// the whole outbound-agent feature.
func (c AgentBrokerConfig) Configured() bool { return c.CACert != "" }

// CrossReplicaConfigured reports whether the inter-replica forward plane is
// fully wired: all three mTLS values plus an advertised forward address must be
// present, otherwise the relay stays single-replica (a non-local agent fails
// closed) — safe-by-default.
func (c AgentBrokerConfig) CrossReplicaConfigured() bool {
	return c.ForwardCACert != "" && c.ForwardCert != "" && c.ForwardKey != "" && c.ForwardAddr != ""
}

// WebAccessConfig tunes the clientless browser-access bridge (web SSH terminal
// and web database console). The feature is safe-by-default and fail-open at
// the resource layer: when disabled the WebSocket routes are not mounted at all
// (the native gateway path is unaffected), and every governance control
// (lease validation, command policy, recording, audit, admin takeover) is
// inherited from the shared PAM services rather than re-implemented here, so a
// browser session can never be less governed than a native one.
type WebAccessConfig struct {
	// Enabled gates whether the WebSocket bridge routes are mounted. It
	// defaults to TRUE so the headline SME feature is available out of the box;
	// an operator can disable it (ACCESS_WEBACCESS_ENABLED=false) to remove the
	// browser entry-point entirely while keeping the native gateway listeners.
	Enabled bool
	// IdleTimeout severs a browser session that has exchanged no bytes in
	// either direction for this long, so an abandoned tab does not hold an
	// upstream connection (and its lease window) open indefinitely. Read from
	// ACCESS_WEBACCESS_IDLE_TIMEOUT; defaults to 15m. Non-positive disables the
	// idle sweep (the lease expiry still bounds the session).
	IdleTimeout time.Duration
	// DialTimeout bounds the upstream connect (SSH handshake / DB connect) the
	// bridge performs after redeeming the connect token. Read from
	// ACCESS_WEBACCESS_DIAL_TIMEOUT; defaults to 15s, matching the gateway
	// proxies. Non-positive falls back to that default.
	DialTimeout time.Duration
	// RecMaxBytes caps the per-session recording size (framed transcript) the
	// bridge buffers before truncating, identical in meaning to the gateway's
	// PAM_REPLAY_MAX_BYTES. Read from ACCESS_WEBACCESS_REC_MAX_BYTES; defaults
	// to 8 MiB. Non-positive disables the cap (unbounded recording).
	RecMaxBytes int
	// MaxResultRows caps how many rows the web database console returns for a
	// single query, so a `SELECT *` against a huge table cannot exhaust the
	// API replica's memory or flood the browser. Read from
	// ACCESS_WEBACCESS_MAX_RESULT_ROWS; defaults to 1000. Non-positive falls
	// back to that default (the cap is a safety rail, never off).
	MaxResultRows int
}

// DevAuthConfig configures the non-production shared-secret token validator.
type DevAuthConfig struct {
	// Secret is the HMAC-SHA256 signing secret (AUTH_JWT_SECRET). When empty
	// the dev path is disabled and the binary falls back to iam-core JWKS.
	Secret string
	// Issuer/Audience are the registered claims enforced on dev tokens. Each is
	// checked only when non-empty, mirroring the JWKS validator.
	Issuer   string
	Audience string
}

// Configured reports whether a dev HMAC secret was supplied.
func (c DevAuthConfig) Configured() bool { return c.Secret != "" }

// IAMCoreConfig configures integration with uneycom/iam-core, the upstream
// OAuth2/OIDC identity provider. See docs/iam-core-integration.md.
type IAMCoreConfig struct {
	// Issuer is the iam-core base URL. It hosts /oauth2/* and
	// /.well-known/* — e.g. https://iam.example.com.
	Issuer string
	// JWKSURL is the JWKS endpoint used to validate access-token
	// signatures. Defaults to Issuer + "/oauth2/jwks" when unset.
	JWKSURL string
	// DiscoveryURL is the OIDC discovery document. Defaults to
	// Issuer + "/.well-known/openid-configuration" when unset.
	DiscoveryURL string
	// ClientID / ClientSecret identify this product as a confidential
	// OAuth2 client (used for the SSO code flow and for minting a
	// client_credentials token against the management audience).
	ClientID     string
	ClientSecret string
	// Audience is the expected `aud` claim on access tokens issued for
	// this product.
	Audience string
	// ManagementBaseURL hosts the /api/v1/management/* API. Defaults to
	// Issuer when unset.
	ManagementBaseURL string
}

// Configured reports whether the minimum iam-core settings are present for
// JWT validation (issuer + a resolvable JWKS endpoint).
func (c IAMCoreConfig) Configured() bool {
	return c.Issuer != "" && c.ResolvedJWKSURL() != ""
}

// ManagementConfigured reports whether the Management API client can actually
// authenticate. The management calls (e.g. BlockUser for the leaver kill
// switch) mint a client_credentials token, which needs both ClientID and
// ClientSecret in addition to the issuer. Wiring a management client without
// these would produce a client that fails every call, so the caller should
// leave the dependent feature unwired (reporting "skipped") when this is false.
func (c IAMCoreConfig) ManagementConfigured() bool {
	return c.Configured() && c.ClientID != "" && c.ClientSecret != ""
}

// ResolvedJWKSURL returns JWKSURL, deriving it from Issuer when unset.
func (c IAMCoreConfig) ResolvedJWKSURL() string {
	if c.JWKSURL != "" {
		return c.JWKSURL
	}
	if c.Issuer == "" {
		return ""
	}
	return strings.TrimRight(c.Issuer, "/") + "/oauth2/jwks"
}

// ResolvedDiscoveryURL returns DiscoveryURL, deriving it from Issuer when unset.
func (c IAMCoreConfig) ResolvedDiscoveryURL() string {
	if c.DiscoveryURL != "" {
		return c.DiscoveryURL
	}
	if c.Issuer == "" {
		return ""
	}
	return strings.TrimRight(c.Issuer, "/") + "/.well-known/openid-configuration"
}

// ResolvedManagementBaseURL returns ManagementBaseURL, deriving it from Issuer
// when unset.
func (c IAMCoreConfig) ResolvedManagementBaseURL() string {
	if c.ManagementBaseURL != "" {
		return strings.TrimRight(c.ManagementBaseURL, "/")
	}
	return strings.TrimRight(c.Issuer, "/")
}

// Load reads the configuration from the environment, applying defaults. It
// never reads files and never panics: callers boot in degraded mode when
// optional dependencies are absent.
func Load() Config {
	return Config{
		Env:               getEnv("ACCESS_ENV", "dev"),
		HTTPAddr:          getEnv("ACCESS_HTTP_ADDR", ":8080"),
		WorkerMetricsAddr: getEnv("ACCESS_WORKER_METRICS_ADDR", ":9090"),
		DatabaseURL:       os.Getenv("ACCESS_DATABASE_URL"),
		RedisURL:          os.Getenv("ACCESS_REDIS_URL"),
		CredentialDEK:     os.Getenv("ACCESS_CREDENTIAL_DEK"),
		KMSMasterKey:      os.Getenv("ACCESS_KMS_MASTER_KEY"),
		KMSKeyVersion:     getInt("ACCESS_KMS_KEY_VERSION", 1),
		DBMaxOpenConns:    getInt("ACCESS_DB_MAX_OPEN_CONNS", 25),
		DBPgxMaxConns:     getInt("ACCESS_DB_PGX_MAX_CONNS", 8),
		DBMaxIdleConns:    getInt("ACCESS_DB_MAX_IDLE_CONNS", 5),
		DBConnMaxLifetime: getDuration("ACCESS_DB_CONN_MAX_LIFETIME", 30*time.Minute),
		DBConnMaxIdleTime: getDuration("ACCESS_DB_CONN_MAX_IDLE_TIME", 5*time.Minute),
		DatabaseDriver:    parseDatabaseDriver(os.Getenv("ACCESS_DATABASE_DRIVER")),
		ShutdownTimeout:   getDuration("ACCESS_SHUTDOWN_TIMEOUT", 10*time.Second),
		Tenancy: TenancyConfig{
			HibernationEnabled:    getBool("ACCESS_TENANCY_HIBERNATION_ENABLED", true),
			DormantIdleThreshold:  getDuration("ACCESS_TENANCY_DORMANT_IDLE", 14*24*time.Hour),
			ReconcileInterval:     getDuration("ACCESS_TENANCY_RECONCILE_INTERVAL", 15*time.Minute),
			ActivityFlushInterval: getDuration("ACCESS_TENANCY_ACTIVITY_FLUSH", 60*time.Second),
			ActivityQueueSize:     getInt("ACCESS_TENANCY_ACTIVITY_QUEUE_SIZE", 8192),
			DefaultTier:           getEnv("ACCESS_TENANCY_DEFAULT_TIER", "trial"),
		},
		RateLimit: RateLimitConfig{
			Enabled:           getBool("ACCESS_TENANT_RATE_LIMIT_ENABLED", true),
			RequestsPerSecond: getFloat("ACCESS_TENANT_RATE_LIMIT_RPS", 50),
			Burst:             getInt("ACCESS_TENANT_RATE_LIMIT_BURST", 100),
			SharedStore:       getBool("ACCESS_TENANT_RATE_LIMIT_SHARED_STORE", false),
		},
		Rotation: RotationConfig{
			Enabled:       getBool("ACCESS_ROTATION_ENABLED", true),
			SweepInterval: getDuration("ACCESS_ROTATION_SWEEP_INTERVAL", 60*time.Second),
			DialTimeout:   getDuration("ACCESS_ROTATION_DIAL_TIMEOUT", 10*time.Second),
		},
		UsageMetering: UsageMeteringConfig{
			Enabled:       getBool("ACCESS_USAGE_METERING_ENABLED", true),
			FlushInterval: getDuration("ACCESS_USAGE_METERING_FLUSH_INTERVAL", 30*time.Second),
			SharedStore:   getBool("ACCESS_USAGE_METERING_SHARED_STORE", false),
		},
		Billing: BillingConfig{
			Enabled:        getBool("ACCESS_BILLING_ENABLED", false),
			EnforceHardCap: getBool("ACCESS_BILLING_ENFORCE_HARD_CAP", false),
			CacheTTL:       getDuration("ACCESS_BILLING_CACHE_TTL", 30*time.Second),
		},
		Recordings: RecordingsConfig{
			SweepEnabled:         getBool("ACCESS_RECORDING_SWEEP_ENABLED", true),
			SweepInterval:        getDuration("ACCESS_RECORDING_SWEEP_INTERVAL", time.Hour),
			DefaultRetentionDays: getInt("ACCESS_RECORDING_RETENTION_DAYS", 0),
			IndexBatch:           getInt("ACCESS_RECORDING_INDEX_BATCH", 200),
			PruneBatch:           getInt("ACCESS_RECORDING_PRUNE_BATCH", 200),
		},
		WebAccess: WebAccessConfig{
			Enabled:       getBool("ACCESS_WEBACCESS_ENABLED", true),
			IdleTimeout:   getDuration("ACCESS_WEBACCESS_IDLE_TIMEOUT", 15*time.Minute),
			DialTimeout:   getDuration("ACCESS_WEBACCESS_DIAL_TIMEOUT", 15*time.Second),
			RecMaxBytes:   getInt("ACCESS_WEBACCESS_REC_MAX_BYTES", 8*1024*1024),
			MaxResultRows: getInt("ACCESS_WEBACCESS_MAX_RESULT_ROWS", 1000),
		},
		IAMCore: IAMCoreConfig{
			Issuer:            os.Getenv("IAM_CORE_ISSUER"),
			JWKSURL:           os.Getenv("IAM_CORE_JWKS_URL"),
			DiscoveryURL:      os.Getenv("IAM_CORE_OIDC_DISCOVERY"),
			ClientID:          os.Getenv("IAM_CORE_CLIENT_ID"),
			ClientSecret:      os.Getenv("IAM_CORE_CLIENT_SECRET"),
			Audience:          os.Getenv("IAM_CORE_AUDIENCE"),
			ManagementBaseURL: os.Getenv("IAM_CORE_MGMT_BASE_URL"),
		},
		DevAuth: DevAuthConfig{
			Secret:   os.Getenv("AUTH_JWT_SECRET"),
			Issuer:   getEnv("AUTH_JWT_ISSUER", "fishbone-access-dev"),
			Audience: getEnv("AUTH_JWT_AUDIENCE", "fishbone-access"),
		},
		AgentBroker: AgentBrokerConfig{
			CACert:                 os.Getenv("ACCESS_AGENT_CA_CERT"),
			CAKey:                  os.Getenv("ACCESS_AGENT_CA_KEY"),
			RelayListen:            getEnv("ACCESS_AGENT_RELAY_LISTEN", ":7443"),
			RelayAddr:              os.Getenv("ACCESS_AGENT_RELAY_ADDR"),
			RelayHosts:             getCSV("ACCESS_AGENT_RELAY_HOSTS", []string{"localhost", "127.0.0.1"}),
			NodeID:                 getEnv("ACCESS_AGENT_NODE_ID", defaultNodeID()),
			ForwardListen:          getEnv("ACCESS_AGENT_FORWARD_LISTEN", ":7444"),
			ForwardAddr:            os.Getenv("ACCESS_AGENT_FORWARD_ADDR"),
			ForwardCACert:          os.Getenv("ACCESS_AGENT_FORWARD_CA"),
			ForwardCert:            os.Getenv("ACCESS_AGENT_FORWARD_CERT"),
			ForwardKey:             os.Getenv("ACCESS_AGENT_FORWARD_KEY"),
			DirectoryStaleAfter:    getDuration("ACCESS_AGENT_DIRECTORY_STALE_AFTER", 0),
			DirectoryRedisFastPath: getBool("ACCESS_AGENT_DIRECTORY_REDIS", false),
		},
	}
}

// DatabaseConfigured reports whether a Postgres DSN was supplied.
func (c Config) DatabaseConfigured() bool { return c.DatabaseURL != "" }

// CredentialEncryptionConfigured reports whether ANY at-rest credential
// encryption key is configured — either the per-workspace KMS master key or the
// single static DEK. When false the binary wires the fail-closed encryptor and
// refuses to persist connector secrets. Binaries should gate their
// secrets-enabled behaviour on this rather than CredentialDEK alone.
func (c Config) CredentialEncryptionConfigured() bool {
	return c.KMSMasterKey != "" || c.CredentialDEK != ""
}

// IsProductionEnv reports whether the configured Env label denotes a production
// deployment. The dev HMAC auth path is refused for these labels even in a
// non-production build, so an operator cannot accidentally enable shared-secret
// tokens against a production database by setting AUTH_JWT_SECRET.
func (c Config) IsProductionEnv() bool {
	switch strings.ToLower(strings.TrimSpace(c.Env)) {
	case "prod", "production", "live":
		return true
	default:
		return false
	}
}

// DevAuthAllowed reports whether the non-production HMAC validator may be
// enabled: a secret must be supplied AND the environment must not be a
// production label.
func (c Config) DevAuthAllowed() bool {
	return c.DevAuth.Configured() && !c.IsProductionEnv()
}

// Validate checks invariants that must hold before a binary wires its services,
// returning a descriptive error so the caller can fail the boot fast. It is the
// place to reject values that Load deliberately does not normalise away (an
// unknown ACCESS_DATABASE_DRIVER), keeping Load total (never-panicking) while still
// surfacing misconfiguration loudly.
func (c Config) Validate() error {
	if !c.DatabaseDriver.Valid() {
		return fmt.Errorf("config: unknown ACCESS_DATABASE_DRIVER %q (want %q or %q)",
			c.DatabaseDriver, DriverPgx, DriverGorm)
	}
	// Surface a bad key version with a clear, field-specific message at the
	// config layer rather than letting the generic getInt (which permits 0) pass
	// it through to the crypto layer, where NewDerivedDEKKeyManager would reject
	// it with a lower-level error. Only enforced when the master key is set,
	// since the version is meaningless without it.
	if c.KMSMasterKey != "" && c.KMSKeyVersion < 1 {
		return fmt.Errorf("config: ACCESS_KMS_KEY_VERSION must be >= 1 when ACCESS_KMS_MASTER_KEY is set (got %d)", c.KMSKeyVersion)
	}
	// Reject a rate limiter that is enabled but cannot ever admit a request:
	// fail the boot loudly here rather than silently shaping every tenant to a
	// dead bucket. Only enforced when enabled, since the values are inert when
	// the limiter is off.
	if c.RateLimit.Enabled {
		if c.RateLimit.RequestsPerSecond <= 0 {
			return fmt.Errorf("config: ACCESS_TENANT_RATE_LIMIT_RPS must be > 0 when ACCESS_TENANT_RATE_LIMIT_ENABLED is true (got %g)", c.RateLimit.RequestsPerSecond)
		}
		if c.RateLimit.Burst < 1 {
			return fmt.Errorf("config: ACCESS_TENANT_RATE_LIMIT_BURST must be >= 1 when ACCESS_TENANT_RATE_LIMIT_ENABLED is true (got %d)", c.RateLimit.Burst)
		}
	}
	// The agent CA cert and key are useless apart: signing client/relay
	// certificates needs both. Reject a half-configured pair loudly at boot
	// rather than letting the feature appear enabled (CACert set ⇒ Configured)
	// only to fail when the relay tries to issue its server certificate.
	if (c.AgentBroker.CACert != "") != (c.AgentBroker.CAKey != "") {
		return errors.New("config: ACCESS_AGENT_CA_CERT and ACCESS_AGENT_CA_KEY must both be set or both be empty")
	}
	// The inter-replica forward identity is meaningless without its CA and key
	// (it must both present a certificate and verify peers). Reject a partial
	// triad loudly rather than silently disabling the forward plane and leaving
	// a multi-replica deployment failing brokered dials it expected to forward.
	fwdParts := 0
	for _, v := range []string{c.AgentBroker.ForwardCACert, c.AgentBroker.ForwardCert, c.AgentBroker.ForwardKey} {
		if v != "" {
			fwdParts++
		}
	}
	if fwdParts != 0 && fwdParts != 3 {
		return errors.New("config: ACCESS_AGENT_FORWARD_CA, ACCESS_AGENT_FORWARD_CERT and ACCESS_AGENT_FORWARD_KEY must all be set or all be empty")
	}
	return nil
}

// defaultNodeID is the replica identity used when ACCESS_AGENT_NODE_ID is unset:
// the OS hostname, which is the pod name under Kubernetes and unique per replica
// behind the load balancer. It falls back to a generated value only if the
// hostname is unavailable, so two replicas never accidentally share an identity.
func defaultNodeID() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "pam-gateway-" + uuid.NewString()
}

// Warnings returns non-fatal misconfiguration notes the binary should log
// loudly at boot. Unlike Validate (which rejects values Load cannot safely
// normalise, failing the boot fast), these are knobs that DO have correct
// runtime fallbacks — the recorder clamps the coalescing window via
// SafeThrottle, NewAsyncRecorder substitutes a default for a non-positive queue
// size, and normalizeTier maps an unknown tier to the most-constrained one — so
// a bad value must never crash a 5,000-tenant NoOps fleet at startup. But a
// silent fallback hides operator intent, so we surface it here (mirroring the
// "AUTH_JWT_SECRET set but ignored" warning) to catch typos early without
// sacrificing the never-crash-on-config contract. Tier-name validation lives at
// the wiring site, which knows the recognised tiers, rather than here.
func (c Config) Warnings() []string {
	var w []string
	// Both credential keys set: the per-workspace master key wins for new seals
	// (see CredentialEncryptorFromConfig), so any secret previously sealed under
	// the static DEK becomes unreadable until re-sealed. This is a deliberate
	// precedence, not a bug, but it is a migration footgun worth flagging loudly
	// so an operator who added the master key to an existing deployment knows
	// they must re-seal (or remove ACCESS_CREDENTIAL_DEK once migration is done).
	if c.KMSMasterKey != "" && c.CredentialDEK != "" {
		w = append(w, "both ACCESS_KMS_MASTER_KEY and ACCESS_CREDENTIAL_DEK are set; "+
			"the per-workspace master key takes precedence for new seals, so secrets "+
			"sealed earlier under ACCESS_CREDENTIAL_DEK will NOT open until re-sealed "+
			"under the master key (remove ACCESS_CREDENTIAL_DEK once migration is complete)")
	}
	w = append(w, c.Tenancy.Warnings()...)
	// A non-positive usage-metering flush interval has a safe runtime fallback
	// (the aggregator substitutes its built-in default), so this is a warning
	// rather than a fatal Validate error — a 5,000-tenant fleet must boot even
	// with a fat-fingered interval. But a silent fallback hides operator
	// intent, so surface it (mirroring the tenancy knobs above).
	if c.UsageMetering.Enabled && c.UsageMetering.FlushInterval <= 0 {
		w = append(w, fmt.Sprintf(
			"ACCESS_USAGE_METERING_FLUSH_INTERVAL=%s is non-positive; the usage aggregator will use its built-in default flush interval",
			c.UsageMetering.FlushInterval))
	}
	// Billing derives statements and enforcement from the usage rollup, so with
	// metering off the rollup never advances: statements show only the base
	// price and no tenant can ever cross a quota. That is a defensible "billing
	// without usage" posture, but it is almost always a misconfiguration, so
	// surface it loudly rather than silently under-billing.
	if c.Billing.Enabled && !c.UsageMetering.Enabled {
		w = append(w, "ACCESS_BILLING_ENABLED is true but ACCESS_USAGE_METERING_ENABLED is false; "+
			"statements will show no usage and no quota can ever be exceeded because the tenant_usage rollup never advances")
	}
	// A non-positive cache TTL has a safe runtime fallback (the service
	// substitutes its built-in default), mirroring the metering flush-interval
	// warning above; flag it so the silent fallback does not hide operator intent.
	if c.Billing.Enabled && c.Billing.CacheTTL <= 0 {
		w = append(w, fmt.Sprintf(
			"ACCESS_BILLING_CACHE_TTL=%s is non-positive; the billing service will use its built-in default cache TTL",
			c.Billing.CacheTTL))
	}
	// A shared-store flag is meaningless without a store to share: the limiter
	// and usage accumulator both need ACCESS_REDIS_URL. Surface the dropped
	// intent loudly (rather than silently ignoring it) so an operator who asked
	// for globally-exact behaviour but forgot the Redis URL learns at boot that
	// they got the per-replica fallback instead — the never-crash-on-config
	// contract means we fall back rather than fail.
	if c.RedisURL == "" {
		if c.RateLimit.Enabled && c.RateLimit.SharedStore {
			w = append(w, "ACCESS_TENANT_RATE_LIMIT_SHARED_STORE is set but ACCESS_REDIS_URL is empty; "+
				"the rate limiter is falling back to the per-replica in-memory bucket (a tenant's effective ceiling stays N×RPS, not globally exact)")
		}
		if c.UsageMetering.Enabled && c.UsageMetering.SharedStore {
			w = append(w, "ACCESS_USAGE_METERING_SHARED_STORE is set but ACCESS_REDIS_URL is empty; "+
				"usage metering is falling back to the per-replica additive UPSERT into Postgres (still cross-replica correct, just not consolidated through Redis)")
		}
		if c.AgentBroker.CrossReplicaConfigured() && c.AgentBroker.DirectoryRedisFastPath {
			w = append(w, "ACCESS_AGENT_DIRECTORY_REDIS is set but ACCESS_REDIS_URL is empty; "+
				"the session directory is falling back to direct Postgres reads on the cross-replica dial path (correct, just without the Redis owner-lookup cache)")
		}
	}
	// The inter-replica mTLS triad is present but ACCESS_AGENT_FORWARD_ADDR is
	// not: Validate() passes (the triad is internally consistent), yet
	// CrossReplicaConfigured() is false because peers have no address to forward
	// to, so the forward plane stays OFF. Name the missing knob explicitly so a
	// multi-replica operator who configured the certs but forgot the advertise
	// address isn't left guessing why brokered dials still fail closed.
	if c.AgentBroker.ForwardCACert != "" && c.AgentBroker.ForwardCert != "" &&
		c.AgentBroker.ForwardKey != "" && c.AgentBroker.ForwardAddr == "" {
		w = append(w, "ACCESS_AGENT_FORWARD_CA/CERT/KEY are set but ACCESS_AGENT_FORWARD_ADDR is empty; "+
			"the cross-replica forward plane stays OFF (peers have no address to forward to) and a non-local agent fails closed — set the advertised forward address to enable HA brokering")
	}
	return w
}

// RateLimitSharedStoreActive reports whether the globally-exact Redis-backed
// limiter should be wired: the operator opted in AND a Redis URL is present to
// back it. The composition root uses this to choose the backend, keeping the
// "only honoured with ACCESS_REDIS_URL" rule in one place rather than duplicated
// across Warnings and main.
func (c Config) RateLimitSharedStoreActive() bool {
	return c.RateLimit.Enabled && c.RateLimit.SharedStore && c.RedisURL != ""
}

// UsageSharedStoreActive reports whether the Redis-backed usage accumulator
// should be wired: opted in AND a Redis URL is present. Mirrors
// RateLimitSharedStoreActive.
func (c Config) UsageSharedStoreActive() bool {
	return c.UsageMetering.Enabled && c.UsageMetering.SharedStore && c.RedisURL != ""
}

// DirectoryRedisActive reports whether the session-directory Redis fast-path
// should be wired: the cross-replica forward plane is configured, the fast-path
// is opted in, AND a Redis URL is present. Mirrors the other shared-store
// gates; without all three the directory reads Postgres directly.
func (c Config) DirectoryRedisActive() bool {
	return c.AgentBroker.CrossReplicaConfigured() && c.AgentBroker.DirectoryRedisFastPath && c.RedisURL != ""
}

// Warnings reports tenancy knobs whose value will be silently overridden by a
// safe fallback, so the operator learns at boot that their setting did not take
// effect. It deliberately returns notes rather than errors: every case below is
// recoverable at runtime, and a dormant-trial fleet must boot even when a knob
// is fat-fingered. Tier-name checking is omitted here (config is a leaf package
// that does not know the tier ladder); the wiring site logs that separately.
func (c TenancyConfig) Warnings() []string {
	var w []string
	if c.ActivityQueueSize <= 0 {
		w = append(w, fmt.Sprintf(
			"ACCESS_TENANCY_ACTIVITY_QUEUE_SIZE=%d is non-positive; the recorder will use its built-in default queue size",
			c.ActivityQueueSize))
	}
	if c.DormantIdleThreshold <= 0 {
		w = append(w, fmt.Sprintf(
			"ACCESS_TENANCY_DORMANT_IDLE=%s is non-positive; dormancy classification needs a positive idle window to be meaningful",
			c.DormantIdleThreshold))
	}
	if c.ReconcileInterval <= 0 {
		w = append(w, fmt.Sprintf(
			"ACCESS_TENANCY_RECONCILE_INTERVAL=%s is non-positive; the reconcile sweep needs a positive interval to schedule",
			c.ReconcileInterval))
	}
	// The recorder clamps the coalescing window to at most one-tenth of the idle
	// threshold (SafeThrottle) so a wide flush window can never coalesce away a
	// wake-from-dormant. Warn when the configured value would be clamped so the
	// operator knows the effective window differs from what they set.
	if c.DormantIdleThreshold > 0 && c.ActivityFlushInterval > c.DormantIdleThreshold/10 {
		w = append(w, fmt.Sprintf(
			"ACCESS_TENANCY_ACTIVITY_FLUSH=%s exceeds one-tenth of ACCESS_TENANCY_DORMANT_IDLE=%s; the recorder will clamp the coalescing window so it can never mask a wake-from-dormant",
			c.ActivityFlushInterval, c.DormantIdleThreshold))
	}
	return w
}

// parseDatabaseDriver normalises the ACCESS_DATABASE_DRIVER env var (trimmed,
// lower-cased) and maps an empty value to the default. An unrecognised value is
// returned as-typed so Validate can name it in the error rather than silently
// substituting a backend the operator never selected.
func parseDatabaseDriver(v string) DatabaseDriver {
	s := DatabaseDriver(strings.ToLower(strings.TrimSpace(v)))
	if s == "" {
		return defaultDatabaseDriver
	}
	return s
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// getInt reads a non-negative integer env var, returning def when unset, empty,
// unparseable, or negative (a negative pool bound is meaningless and would be a
// silent misconfiguration).
func getInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return n
	}
	return def
}

// getFloat reads a non-negative float env var, returning def when unset, empty,
// unparseable, or negative (a negative rate is meaningless and would be a silent
// misconfiguration). A parseable 0 is returned as-is so Validate can reject it
// with a field-specific message rather than masking it as the default.
func getFloat(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
		return f
	}
	return def
}

// getBool reads a boolean env var, returning def when unset, empty, or
// unparseable. Accepts the strconv.ParseBool set ("1","t","true","0","f",…).
func getBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if b, err := strconv.ParseBool(v); err == nil {
		return b
	}
	return def
}

// getCSV reads a comma-separated env var into a trimmed, non-empty slice,
// returning def when unset or all-empty.
func getCSV(key string, def []string) []string {
	v := os.Getenv(key)
	if strings.TrimSpace(v) == "" {
		return def
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}

func getDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	// Bare integer is interpreted as seconds.
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	return def
}

// String renders a redacted, log-safe summary of the configuration. Secrets
// (ClientSecret, CredentialDEK, KMSMasterKey) are never included — only whether
// they are set.
func (c Config) String() string {
	return fmt.Sprintf(
		"Config{env=%s http=%s db=%t driver=%s redis=%t dek=%t kms=%t kmsver=%d ratelimit=%t/%grps/%dburst/shared=%t usagemetering=%t/%s/shared=%t billing=%t/hardcap=%t/%s hibernation=%t/idle=%s workermetrics=%q iamcore=%t issuer=%q}",
		c.Env, c.HTTPAddr, c.DatabaseConfigured(), c.DatabaseDriver, c.RedisURL != "",
		c.CredentialDEK != "", c.KMSMasterKey != "", c.KMSKeyVersion,
		c.RateLimit.Enabled, c.RateLimit.RequestsPerSecond, c.RateLimit.Burst, c.RateLimitSharedStoreActive(),
		c.UsageMetering.Enabled, c.UsageMetering.FlushInterval, c.UsageSharedStoreActive(),
		c.Billing.Enabled, c.Billing.EnforceHardCap, c.Billing.CacheTTL,
		c.Tenancy.HibernationEnabled, c.Tenancy.DormantIdleThreshold, c.WorkerMetricsAddr,
		c.IAMCore.Configured(), c.IAMCore.Issuer,
	)
}
