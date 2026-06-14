package billing

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/middleware"
)

// Response headers the enforcement middleware sets to surface a quota decision
// to the client (and to dashboards/log pipelines). They are set on EVERY
// over-quota request — soft, hard-shadow, and hard-denied — so a tenant learns
// it is over its included allowance well before it is ever capped.
const (
	// HeaderQuotaState carries the worst metric's state: "soft_exceeded" or
	// "hard_exceeded".
	HeaderQuotaState = "X-Quota-State"
	// HeaderQuotaMetric names the metric that triggered the state.
	HeaderQuotaMetric = "X-Quota-Metric"
)

// QuotaEnforcer is the decision surface the middleware needs, satisfied by
// *Service. Defined as an interface so the middleware is testable with a fake
// and so the router can hold a nil enforcer to disable enforcement (fail-open).
type QuotaEnforcer interface {
	Decide(ctx context.Context, workspaceID uuid.UUID) (QuotaDecision, error)
}

// QuotaMiddleware enforces per-tenant plan quotas on the tenant-scoped surface.
// Like usage.Middleware and tenancy.ActivityMiddleware it is mounted AFTER
// RequireTenant, so it is keyed by the authoritative workspace UUID (the rollup
// + RLS key) — strictly after ResolveTenant, exactly as the rate limiter is —
// and a tenant can never be enforced against another tenant's consumption.
//
// It fails OPEN at every step, exactly like the rate-limit and metering
// middlewares: a nil enforcer, an unkeyed request (no resolved workspace), or a
// lookup error proceeds untouched, so a billing outage degrades to "no
// enforcement" rather than taking the API down. The decision is read from the
// enforcer's per-workspace TTL cache, so the common path is a pure in-memory
// check with no DB read — and it runs BEFORE the handler, so a hard-denied
// request is rejected before it reaches Postgres or any expensive work.
//
// Decisions:
//   - OK: proceed silently.
//   - SOFT (over included quota, under hard ceiling): set the quota headers and
//     proceed — the request is allowed but flagged and billed as overage.
//   - HARD with enforcement on: reject with 402 Payment Required (the breach is
//     a plan/billing limit, not a per-second rate — 429 is the rate limiter's
//     status — so 402 lets a client distinguish "slow down" from "your plan's
//     allowance for the period is exhausted, upgrade to continue").
//   - HARD in shadow mode (enforcement off): treated like SOFT — headers set,
//     request allowed — so operators can observe who WOULD be capped first.
//
// onDecision, when non-nil, is invoked for every over-quota decision with the
// state string and the matched route TEMPLATE (never the tenant id, which is
// unbounded at 5,000 tenants), so the breach can be metered on the aggregate
// registry. It mirrors the rate limiter's onThrottle hook.
//
// exemptPrefixes name route TEMPLATES (matched by c.FullPath prefix) that are
// NEVER capped, even for a hard-exceeded tenant. The self-service billing
// surface is passed here: a hard-denied 402 tells the tenant to "upgrade the
// plan", so capping the very endpoints that show the bill and change the plan
// would be a Catch-22 with no API-side escape. Those endpoints are lightweight
// reads/writes, not the expensive shared work the hard cap exists to protect,
// so exempting them keeps self-remediation reachable without weakening the cap
// on the resource-consuming surface.
func QuotaMiddleware(enforcer QuotaEnforcer, onDecision func(state, route string), exemptPrefixes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if enforcer == nil {
			c.Next()
			return
		}
		if isExemptRoute(c, exemptPrefixes) {
			c.Next()
			return
		}
		ws, ok := middleware.WorkspaceFromContext(c)
		if !ok {
			c.Next()
			return
		}
		d, err := enforcer.Decide(c.Request.Context(), ws)
		if err != nil || d.State == QuotaOK {
			// Fail open on a lookup error; nothing to flag when within quota.
			c.Next()
			return
		}

		c.Header(HeaderQuotaState, d.State.String())
		c.Header(HeaderQuotaMetric, d.Metric)
		if onDecision != nil {
			onDecision(d.State.String(), routeTemplate(c))
		}

		if d.Deny {
			c.AbortWithStatusJSON(http.StatusPaymentRequired, gin.H{
				"error":    "quota exceeded for the current billing period; upgrade the plan or wait for the period to reset",
				"metric":   d.Metric,
				"plan":     d.Plan,
				"used":     d.Used,
				"hard_cap": d.HardCap,
			})
			return
		}
		c.Next()
	}
}

// isExemptRoute reports whether the matched route template is one the quota cap
// must never block (the self-service billing surface). It matches on the route
// TEMPLATE (c.FullPath, e.g. "/api/v1/billing/plan"), never the raw URL, so an
// id in the path can never widen or evade the exemption.
func isExemptRoute(c *gin.Context, prefixes []string) bool {
	p := c.FullPath()
	if p == "" {
		return false
	}
	for _, pre := range prefixes {
		if pre != "" && strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// routeTemplate returns the matched route template for metric labelling,
// collapsing an unmatched route to "unmatched" so an id in the URL never spawns
// an unbounded series — mirroring observability.Metrics.
func routeTemplate(c *gin.Context) string {
	if r := c.FullPath(); r != "" {
		return r
	}
	return "unmatched"
}
