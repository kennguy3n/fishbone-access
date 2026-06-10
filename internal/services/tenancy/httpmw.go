package tenancy

import (
	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/fishbone-access/internal/middleware"
)

// ActivityMiddleware records tenant activity for every request that has a
// resolved workspace, which is the LAZY WAKE path: a dormant tenant's first
// authenticated API call records activity and (via the recorder → store) flips
// it back to active, so periodic work resumes without any operator action.
//
// It is mounted on the tenant-scoped router group AFTER RequireTenant, so the
// workspace UUID is already resolved and authoritative — the recorder can never
// be driven for a workspace the caller did not authenticate for. Recording is
// fire-and-forget (the recorder buffers + coalesces), so this adds no latency
// and no failure mode to the request path.
//
// rec may be nil, in which case the middleware is a transparent pass-through —
// the router can mount it unconditionally.
func ActivityMiddleware(rec ActivityRecorder) gin.HandlerFunc {
	return func(c *gin.Context) {
		if rec != nil {
			if workspaceID, ok := middleware.WorkspaceFromContext(c); ok {
				rec.Record(workspaceID, KindAPI)
			}
		}
		c.Next()
	}
}
