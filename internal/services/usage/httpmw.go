package usage

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/middleware"
)

// Meter is the write side of usage metering as the request hot path sees it: a
// fire-and-forget Record that must not block the caller. The middleware depends
// only on this interface (satisfied by *Aggregator), so the buffering and flush
// strategy is an implementation detail and the middleware is unit-testable with
// a fake.
type Meter interface {
	Record(workspaceID uuid.UUID, metric string)
}

// Middleware meters one MetricAPIRequests count per request that has a resolved
// workspace. Like tenancy.ActivityMiddleware it is mounted on the tenant-scoped
// router group AFTER RequireTenant, so the workspace UUID is already resolved
// and authoritative — usage can never be attributed to a workspace the caller
// did not authenticate for. The workspace UUID (never a client-supplied value)
// is the rollup key, mirroring how the rate limiter keys on the authoritative
// tenant id.
//
// It fails OPEN by design, exactly like the rate-limit middleware: a nil meter
// or an unkeyed request (no resolved workspace — e.g. a route mistakenly
// mounted before RequireTenant) proceeds untouched rather than erroring, so a
// metering or wiring problem degrades to "no metering" instead of failing
// requests. Recording is a single in-memory increment, so it adds no latency
// and no database failure mode to the request path.
//
// Metering happens after the handler runs so the request is counted once it has
// been served, and the count is genuinely unconditional: the Record is deferred,
// so it runs even if a downstream handler panics (the panic still propagates to
// the Recovery middleware mounted earlier — we only observe, we do not swallow
// it). A 4xx/5xx — or a panic — still consumes control-plane resources, so it
// still attributes cost-to-serve. Deferring before c.Next() also means the
// workspace is read at the same authoritative point regardless of how the chain
// unwinds.
func Middleware(m Meter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if m != nil {
			defer func() {
				if workspaceID, ok := middleware.WorkspaceFromContext(c); ok {
					m.Record(workspaceID, MetricAPIRequests)
				}
			}()
		}
		c.Next()
	}
}
