package middleware

import (
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter is the per-key admission decision the rate-limit middleware needs.
// It is satisfied by *ratelimit.TenantLimiter today; declaring it as an
// interface keeps this middleware decoupled from the limiter implementation (an
// in-memory bucket now, a shared Redis-backed limiter later) and unit-testable
// with a fake.
type RateLimiter interface {
	// Allow reports whether a request for key may proceed, and when denied the
	// estimated wait until it could succeed (for a Retry-After hint).
	Allow(key string) (bool, time.Duration)
}

// RateLimit returns a middleware that caps the inbound request rate per tenant.
// It MUST be mounted after ResolveTenant so the authoritative tenant id is on
// the context; the tenant id (never a client-supplied header) is the limiter
// key, so one tenant can never spend another's budget.
//
// It fails OPEN by design: a nil limiter or an unkeyed request (no resolved
// tenant — e.g. a route mistakenly mounted before ResolveTenant) is allowed
// through rather than throttled, so a wiring mistake degrades to "no limiting"
// instead of collapsing every caller into one shared bucket.
//
// onThrottle, when non-nil, is invoked with the matched route TEMPLATE on each
// throttled request (for a bounded-cardinality metric). It is never passed the
// tenant id, which would be unbounded across 5,000 tenants.
func RateLimit(limiter RateLimiter, onThrottle func(route string)) gin.HandlerFunc {
	return func(c *gin.Context) {
		if limiter == nil {
			c.Next()
			return
		}
		tenant := TenantFromContext(c)
		if tenant == "" {
			c.Next()
			return
		}
		ok, retry := limiter.Allow(tenant)
		if ok {
			c.Next()
			return
		}
		setRetryAfter(c, retry)
		if onThrottle != nil {
			route := c.FullPath()
			if route == "" {
				route = "unmatched"
			}
			onThrottle(route)
		}
		abort(c, http.StatusTooManyRequests, "rate limit exceeded for tenant; retry after the indicated delay")
	}
}

// setRetryAfter writes the Retry-After header in whole seconds (per RFC 7231),
// rounding up so a sub-second delay still advises at least 1s rather than 0
// (which would invite an immediate, certain-to-fail retry).
func setRetryAfter(c *gin.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	secs := int(math.Ceil(d.Seconds()))
	if secs < 1 {
		secs = 1
	}
	c.Header("Retry-After", strconv.Itoa(secs))
}
