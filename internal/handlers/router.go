// Package handlers wires the ShieldNet Access HTTP API. NewRouter assembles the
// Gin engine: always-on liveness/readiness probes plus an authenticated
// /api/v1 surface guarded by the iam-core token + tenant-resolution middleware.
//
// The router ships the routing skeleton and the cross-cutting
// middleware; the access-request, connector, policy, and PAM handlers attach
// onto this same group.
package handlers

import (
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/broker"
	"github.com/kennguy3n/fishbone-access/internal/middleware"
	"github.com/kennguy3n/fishbone-access/internal/pkg/aiclient"
	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/pkg/observability"
	"github.com/kennguy3n/fishbone-access/internal/pkg/ratelimit"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
	"github.com/kennguy3n/fishbone-access/internal/services/billing"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
	"github.com/kennguy3n/fishbone-access/internal/services/mfa"
	"github.com/kennguy3n/fishbone-access/internal/services/tenancy"
	"github.com/kennguy3n/fishbone-access/internal/services/usage"
	"github.com/kennguy3n/fishbone-access/internal/webui"
)

// Deps are the runtime dependencies the router needs. Validator may be nil when
// iam-core is not configured (degraded dev boot): in that case the
// authenticated surface returns 503 rather than allowing unauthenticated access.
type Deps struct {
	Validator middleware.TokenValidator
	Ready     *atomic.Bool
	// DB is the shared control-plane connection pool. It is nil in degraded
	// (no-database) dev boots. NewRouter only runs migrations through it; the
	// feature handlers attached to the /api/v1 group query through this same
	// pool, which is owned and closed by the ztna-api main (so it is not a
	// leaked, never-closed pool).
	DB *gorm.DB
	// Encryptor seals/opens the per-user TOTP secrets behind step-up MFA
	// (wired into mfa.NewTOTPMFAVerifier). Connector secret envelopes are NOT
	// handled here — those go through ConnectorEncryptor below. When this is a
	// passthrough/disabled encryptor, stored TOTP secrets are unprotected, so
	// the ztna-api boot warns rather than silently weakening MFA.
	Encryptor crypto.Encryptor
	// Disabler disables (blocks) a user in iam-core for the leaver kill
	// switch (layer 3). Usually the *iamcore.ManagementClient; nil in degraded
	// boots, in which case that kill-switch layer reports "skipped".
	Disabler lifecycle.IdentityDisabler
	// WorkspaceResolver is the tenant→workspace lookup RequireTenant runs on
	// every authenticated request. When set (production wires the pgxpool
	// adapter here) it takes precedence; when nil and DB is present, NewRouter
	// falls back to the GORM-backed resolver so the SQLite test path and
	// degraded boots keep working unchanged.
	WorkspaceResolver middleware.WorkspaceResolver
	// RBAC resolves and mutates workspace memberships for the authorization
	// tier. When nil (degraded boot, or a legacy router construction without an
	// RBAC store) AuthzMiddleware is NOT installed and the per-route
	// RequirePermission gates no-op, preserving the pre-RBAC behavior. The
	// production ztna-api always wires this, so enforcement is always on there.
	RBAC *authz.RBACService
	// StepUpMFA verifies a fresh step-up assertion (TOTP today; WebAuthn-ready)
	// for the highest-risk actions. When nil the RequireStepUpMFA gates are not
	// mounted; production wires the composite verifier.
	StepUpMFA mfa.MFAVerifier
	// ConnectorEncryptor seals/opens connector secrets for the connector
	// management surface. It is the access-stack encryptor (the same one the
	// access-connector-worker uses) so a connector created via the API is
	// syncable by the worker. nil falls back to the fail-closed encryptor.
	ConnectorEncryptor access.CredentialEncryptor
	// AI is the access-ai-agent client (mTLS A2A) shared by the lifecycle risk
	// review (scoring elevation requests server-side) and the connector setup
	// wizard. It may be an unconfigured client (no agent URL): both consumers
	// are fail-OPEN, so risk review degrades to the deterministic fallback and
	// the wizard returns a degraded manual plan instead of panicking.
	AI *aiclient.AIClient
	// ActivityRecorder records tenant activity on the authenticated request
	// path — the LAZY WAKE side of tenant hibernation. When
	// set, ActivityMiddleware is mounted on the tenant-scoped group so a dormant
	// tenant's first API call wakes it. It is wired whenever a DB is present,
	// INDEPENDENT of whether hibernation is enabled: activity is always recorded
	// so the feature can be turned on later with accurate history (see
	// cmd/ztna-api/main.go). It is nil only in a degraded (no-DB) boot, in which
	// case no activity middleware is mounted (no-op).
	ActivityRecorder tenancy.ActivityRecorder
	// Metrics, when set, mounts the Prometheus instrumentation: a request
	// middleware (rate/error/latency by route template) and the /metrics scrape
	// endpoint. nil leaves the router un-instrumented (tests/degraded boots), so
	// existing behavior is unchanged; the production ztna-api always wires it and
	// registers the DB pool's saturation stats on the same registry.
	Metrics *observability.Metrics
	// TracingServiceName, when non-empty, mounts the OpenTelemetry request
	// middleware under this service name. main sets it only when InitTracer
	// installed a real OTLP provider (operator set OTEL_EXPORTER_OTLP_ENDPOINT),
	// so an un-traced deployment pays nothing.
	TracingServiceName string
	// RateLimiter, when set, caps the inbound request rate PER TENANT on the
	// authenticated /api/v1 surface (mounted right after tenant resolution, so
	// the limiter key is the authoritative tenant id). nil leaves the surface
	// un-limited (tests/degraded boots), preserving the pre-feature behaviour.
	// When Metrics is also set, throttled requests are counted on the same
	// registry (by route template) for alerting.
	RateLimiter middleware.RateLimiter
	// UsageMeter, when set, accumulates one per-tenant usage count per
	// authenticated, tenant-scoped request — the write side of usage metering.
	// It is mounted on the tenant-scoped group (after RequireTenant, so it is
	// keyed by the authoritative workspace UUID) and is fire-and-forget, so it
	// adds no latency or failure mode. nil leaves the surface un-metered
	// (tests/degraded boots). Wired whenever metering is enabled and a DB is
	// present (see cmd/ztna-api/main.go).
	UsageMeter usage.Meter
	// UsageReader, when set, backs the authenticated GET /api/v1/usage read
	// endpoint so a tenant can see its own current-period consumption. nil
	// leaves the route unmounted (tests/degraded boots). It reads the same
	// rollup the meter flushes to.
	UsageReader usage.Reader
	// BillingEnforcer, when set, enforces per-tenant plan quotas on the
	// tenant-scoped surface: a quota middleware mounted right after
	// RequireTenant (so it is keyed by the authoritative workspace UUID) that
	// soft-flags over-quota requests and hard-denies (402) those over the hard
	// ceiling BEFORE they reach Postgres. It is fail-open and reads a per-replica
	// TTL cache, so it adds no per-request DB load and a billing outage degrades
	// to "no enforcement". nil leaves the surface un-enforced (tests/degraded
	// boots). Wired from the same *billing.Service as BillingReader.
	BillingEnforcer billing.QuotaEnforcer
	// BillingReader, when set, backs the authenticated billing read/admin
	// endpoints (GET /api/v1/billing/statement, /billing/plan and the owner-only
	// PUT /billing/plan) so a tenant can see its statement/plan and an owner can
	// assign its plan. It derives statements from the SAME usage rollup the meter
	// writes. nil leaves the routes unmounted (tests/degraded boots).
	BillingReader billingService
	// AgentEnrollment, when set, backs the outbound connector agent enrollment:
	// the public token-gated POST /api/v1/agents/enroll endpoint and the
	// authenticated mint-token / revoke management routes. It is wired only when
	// the deployment configured an agent CA (see cmd/ztna-api/main.go); when nil
	// the public route is absent and the management mutations return 503, while
	// the read/bind surface still works off the DB.
	AgentEnrollment *broker.EnrollmentService
	// AgentEnrollIPLimiter, when set, is the per-client-IP token bucket guarding
	// the public enrollment endpoint. The server owner constructs it (via
	// NewAgentEnrollIPLimiter) and Stop()s it on shutdown so its janitor
	// goroutine does not outlive the process. When nil but AgentEnrollment is
	// set, registerAgentEnrollment builds a process-lifetime fallback.
	AgentEnrollIPLimiter *ratelimit.TenantLimiter
	// RotationDialTimeout bounds every upstream connection an API-initiated
	// rotation or ephemeral-credential mint makes. main sets it from
	// cfg.Rotation.DialTimeout (ACCESS_ROTATION_DIAL_TIMEOUT) so "rotate now"
	// honours the SAME timeout as the scheduled sweep in access-workflow-engine;
	// a zero value falls back to the 10s default inside newRotationHandlers.
	RotationDialTimeout time.Duration
}

// NewRouter builds the Gin engine.
func NewRouter(deps Deps) *gin.Engine {
	r := gin.New()
	// Metrics instrumentation is mounted OUTSIDE Recovery so a panicked request
	// is still counted with the 500 status Recovery writes: Recovery recovers
	// and sets the status, then control unwinds back into the metrics
	// middleware's deferred recording. Only mounted when a registry is wired.
	if deps.Metrics != nil {
		r.Use(deps.Metrics.Middleware())
	}
	r.Use(gin.Recovery())
	// Tracing opens a span per request (named by route template); it sits inside
	// Recovery so a panic still closes the span. Only mounted when InitTracer
	// installed a real provider.
	if deps.TracingServiceName != "" {
		r.Use(observability.TracingMiddleware(deps.TracingServiceName))
	}
	if deps.Metrics != nil {
		r.GET("/metrics", gin.WrapH(deps.Metrics.Handler()))
	}

	r.GET("/health", liveness)
	r.GET("/readyz", readiness(deps.Ready))
	// Unauthenticated diagnostics: the registered connector provider keys
	// (drives the connector-count CI guard).
	r.GET("/api/v1/connectors/providers", listProviders)

	// Public, token-gated outbound-agent enrollment endpoint. It is NOT behind
	// the iam-core session auth (an agent has no user session — it proves itself
	// with the one-shot enrollment token), so it is mounted on the engine
	// directly. No-op when no agent CA is configured.
	registerAgentEnrollment(r, deps.AgentEnrollment, deps.AgentEnrollIPLimiter)

	// Tenant-scoped API. With iam-core configured the group is guarded by the
	// auth + tenant-resolution middleware; without it the group fails closed
	// with 503 (the routes still match so the failure is explicit, not a 404).
	// The feature handlers attach to this same group.
	api := r.Group("/api/v1")
	if deps.Validator != nil {
		api.Use(middleware.Auth(deps.Validator), middleware.ResolveTenant())
		// Per-tenant rate limiting sits AFTER tenant resolution so its key is
		// the authoritative tenant id, and only on the authenticated path (the
		// degraded branch already 503s). Throttle events feed the metrics
		// registry by route template when observability is wired.
		if deps.RateLimiter != nil {
			var onThrottle func(string)
			if deps.Metrics != nil {
				onThrottle = deps.Metrics.IncThrottled
			}
			api.Use(middleware.RateLimit(deps.RateLimiter, onThrottle))
		}
	} else {
		api.Use(degraded)
	}
	api.GET("/me", whoami)

	// Tenant-scoped lifecycle surface. RequireTenant maps the verified
	// tenant_id claim to a workspace UUID and fails closed (403) when none
	// resolves, so every handler below is guaranteed a workspace to scope by.
	// It is only mounted when both a validator and a DB are present; without a
	// DB the routes are absent (the /api/v1 group already 503s in degraded
	// mode).
	resolver := deps.WorkspaceResolver
	if resolver == nil && deps.DB != nil {
		resolver = database.NewGormWorkspaceConfigRepo(deps.DB)
	}
	// deps.DB is still required here even when a WorkspaceResolver is supplied:
	// newLifecycleHandlers wires every lifecycle service off deps.DB, so mounting
	// the group without it would hand those constructors a nil *gorm.DB and panic
	// on the first request. RequireTenant runs on the resolver (pgx in
	// production), but the handlers behind it remain GORM-backed until later
	// steps migrate them.
	if deps.Validator != nil && resolver != nil && deps.DB != nil {
		scoped := api.Group("")
		scoped.Use(middleware.RequireTenant(resolver))
		// Record tenant activity right after the workspace is resolved (and
		// before the handlers run) so any authenticated, tenant-scoped call
		// counts as activity and lazily wakes a dormant tenant. Recording is
		// fire-and-forget, so it adds no latency or failure mode; the middleware
		// is a no-op pass-through when the recorder is nil.
		if deps.ActivityRecorder != nil {
			scoped.Use(tenancy.ActivityMiddleware(deps.ActivityRecorder))
		}
		// Enforce per-tenant plan quotas on the same tenant-scoped surface,
		// keyed by the authoritative workspace UUID. It is mounted BEFORE the
		// meter (and before the handlers) so a hard-denied request is rejected
		// before any expensive work AND before it is counted as billable usage:
		// a tenant is never invoiced for requests the platform refused to serve,
		// and a hard-capped tenant cannot feed its own rejected requests back
		// into the usage rollup. The denial is still observable — over-quota
		// decisions feed the aggregate metrics registry by route template (never
		// per tenant) when observability is wired — so dropping it from the
		// per-tenant rollup loses no operational visibility. Fail-open and a
		// no-op pass-through when the enforcer is nil.
		//
		// The self-service billing surface (scoped.BasePath()+"/billing/": the
		// statement/plan reads and the owner-only plan upgrade) is exempted so a
		// hard-capped tenant can still see what it owes and upgrade — the 402
		// body points there, so capping it would be a dead end. Those endpoints
		// are lightweight self-remediation, not the shared work the cap protects.
		if deps.BillingEnforcer != nil {
			var onQuota func(state, route string)
			if deps.Metrics != nil {
				onQuota = deps.Metrics.IncQuotaBreach
			}
			scoped.Use(billing.QuotaMiddleware(deps.BillingEnforcer, onQuota, scoped.BasePath()+"/billing/"))
		}
		// Meter per-tenant usage on the same tenant-scoped surface, keyed by
		// the authoritative workspace UUID (the rollup + RLS key), so
		// cost-to-serve is attributable per tenant. It runs AFTER quota
		// enforcement so only admitted requests (within quota, soft-over, or
		// hard-over in shadow mode) are counted — a hard-denied 402 aborts
		// above this and is never recorded. Like activity recording it is
		// fire-and-forget (a single in-memory increment) and a no-op
		// pass-through when the meter is nil, so it adds no latency or failure
		// mode to the request path.
		if deps.UsageMeter != nil {
			scoped.Use(usage.Middleware(deps.UsageMeter))
		}
		// Install the RBAC tier when an RBAC store is wired. It runs after
		// RequireTenant (it needs the resolved workspace + verified subject) and
		// resolves the caller's role into a permission set for the per-route
		// RequirePermission gates. When deps.RBAC is nil the tier is absent and
		// those gates no-op, preserving pre-RBAC behavior for legacy callers.
		if deps.RBAC != nil {
			scoped.Use(middleware.AuthzMiddleware(deps.RBAC))
			newRBACHandlers(deps.RBAC).register(scoped)
		}
		newLifecycleHandlers(deps).register(scoped, deps.StepUpMFA)
		newConnectorHandlers(deps).register(scoped)
		pamH := newPAMHandlers(deps)
		pamH.register(scoped)
		// Credential rotation reuses the PAM vault + lease service so it
		// re-seals with the same per-workspace key path and validates leases
		// against the same state machine (Session C).
		if rh := newRotationHandlers(deps, pamH.vault, pamH.leases); rh != nil {
			rh.register(scoped)
		}
		newAgentHandlers(deps).register(scoped)
		newWorkflowHandlers(deps).register(scoped)
		newComplianceHandlers(deps).register(scoped)
		if deps.UsageReader != nil {
			newUsageHandlers(deps.UsageReader).register(scoped)
		}
		if deps.BillingReader != nil {
			newBillingHandlers(deps.BillingReader).register(scoped)
		}
	}

	// Serve the embedded Access console (SPA) when the binary was built with
	// the embed_ui tag. No-op otherwise, so the API runs standalone in dev/CI.
	webui.Register(r)

	return r
}

// whoami echoes the resolved identity/tenant — a live check that the iam-core
// token and tenant resolution worked.
func whoami(c *gin.Context) {
	claims := middleware.ClaimsFromContext(c)
	// Fail closed rather than panic: the Auth middleware guarantees non-nil
	// claims today, but if the chain is ever reordered (e.g. a future session
	// mounts whoami without Auth) a nil dereference here would 500 with a stack
	// trace. A 401 is the correct, safe response to "no validated identity".
	if claims == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no authenticated identity"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"user_id":       claims.Subject,
		"tenant_id":     middleware.TenantFromContext(c),
		"roles":         claims.Roles,
		"scopes":        claims.Scopes,
		"mfa_satisfied": claims.MFASatisfied,
	})
}

// listProviders is an unauthenticated diagnostics endpoint returning the
// registered connector provider keys (drives the connector-count CI guard).
func listProviders(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"count":     access.RegisteredCount(),
		"providers": access.ListRegisteredProviders(),
	})
}

// degraded responds 503 on the authenticated surface when iam-core is not
// configured, making the misconfiguration explicit instead of silently
// disabling auth.
func degraded(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
		"error": "iam-core not configured; authenticated API unavailable",
	})
}
