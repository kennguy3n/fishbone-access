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
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
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
	// RedisURL is the Redis connection URL used for the worker queue and
	// rate limiting. Optional in degraded mode.
	RedisURL string
	// DBMaxOpenConns bounds the Postgres pool's total open connections.
	// ztna-api and access-connector-worker share a database but run as
	// separate processes, so each sizes its own pool; keeping a bound avoids
	// exhausting Postgres' max_connections under load.
	DBMaxOpenConns int
	// DBPgxMaxConns bounds the secondary pgxpool that the WS10 GORM→pgx
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

	// UsageMetering accumulates per-tenant usage counts (API calls today) and
	// flushes them to the tenant_usage rollup so cost-to-serve is attributable
	// per tenant. It is the "who is using what" half of the cost story; the
	// rate limiter above is the "cap the abuser" half.
	UsageMetering UsageMeteringConfig

	// IAMCore holds the iam-core identity-provider integration settings.
	IAMCore IAMCoreConfig

	// DevAuth holds the non-production HMAC bearer-token settings. It is the
	// developer-convenience identity path used by the blog seed/capture
	// harnesses to drive the real control-plane API without standing up
	// iam-core. It is honoured ONLY in non-production builds and refused when
	// Env is a production label (see DevAuthAllowed); production binaries omit
	// the validator entirely (internal/iamcore/devauth_prod.go).
	DevAuth DevAuthConfig

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
		},
		UsageMetering: UsageMeteringConfig{
			Enabled:       getBool("ACCESS_USAGE_METERING_ENABLED", true),
			FlushInterval: getDuration("ACCESS_USAGE_METERING_FLUSH_INTERVAL", 30*time.Second),
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
	return nil
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
	return w
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
		"Config{env=%s http=%s db=%t driver=%s redis=%t dek=%t kms=%t kmsver=%d ratelimit=%t/%grps/%dburst usagemetering=%t/%s iamcore=%t issuer=%q}",
		c.Env, c.HTTPAddr, c.DatabaseConfigured(), c.DatabaseDriver, c.RedisURL != "",
		c.CredentialDEK != "", c.KMSMasterKey != "", c.KMSKeyVersion,
		c.RateLimit.Enabled, c.RateLimit.RequestsPerSecond, c.RateLimit.Burst,
		c.UsageMetering.Enabled, c.UsageMetering.FlushInterval,
		c.IAMCore.Configured(), c.IAMCore.Issuer,
	)
}
