package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// WorkspaceResolver maps a verified iam-core tenant id to its ShieldNet
// workspace UUID. It is the one read RequireTenant needs, lifted off the
// concrete *gorm.DB so the middleware is agnostic to whether the lookup runs
// through GORM or the pgxpool adapter — both repositories in
// internal/pkg/database satisfy it and return gorm.ErrRecordNotFound on a miss.
type WorkspaceResolver interface {
	WorkspaceIDByTenant(ctx context.Context, tenantID string) (uuid.UUID, error)
}

// ctxKeyWorkspaceID stores the resolved ShieldNet workspace UUID. It is set
// ONLY by RequireTenant, after the iam-core tenant_id claim has been
// authoritatively resolved. Handlers obtain the workspace id exclusively from
// here (WorkspaceFromContext) and scope every query by it; there is no other
// path by which a handler can learn a workspace id, so a tenant-scoped query
// can never run against a workspace the caller did not authenticate for.
const ctxKeyWorkspaceID = "workspace_id"

// RequireTenant maps the resolved iam-core tenant_id (set by ResolveTenant) to
// its ShieldNet workspace UUID and stores it in the request context. It MUST be
// mounted after Auth and ResolveTenant on every tenant-scoped route and is
// fail-closed:
//
//  1. No resolved tenant_id (ResolveTenant did not run or the token had no
//     tenant claim) → 403.
//  2. No workspace exists for the tenant → 403 (an authenticated principal for
//     an unprovisioned tenant gets no data, never an unscoped query).
//
// Because the workspace id is derived from the verified claim — never from a
// client-supplied value — a handler cannot be tricked into operating on another
// tenant's data.
func RequireTenant(ws WorkspaceResolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant := TenantFromContext(c)
		if tenant == "" {
			abort(c, http.StatusForbidden, "no tenant resolved")
			return
		}
		if ws == nil {
			abort(c, http.StatusServiceUnavailable, "tenant store unavailable")
			return
		}
		id, err := ws.WorkspaceIDByTenant(c.Request.Context(), tenant)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			abort(c, http.StatusForbidden, "no workspace for tenant")
			return
		}
		if err != nil {
			abort(c, http.StatusServiceUnavailable, "tenant lookup failed")
			return
		}
		c.Set(ctxKeyWorkspaceID, id)
		c.Next()
	}
}

// WorkspaceFromContext returns the resolved workspace UUID set by RequireTenant.
// The boolean is false when RequireTenant did not run or resolved nothing;
// handlers MUST treat a false result as fail-closed (do not query).
func WorkspaceFromContext(c *gin.Context) (uuid.UUID, bool) {
	v, ok := c.Get(ctxKeyWorkspaceID)
	if !ok {
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	if !ok || id == uuid.Nil {
		return uuid.Nil, false
	}
	return id, true
}
