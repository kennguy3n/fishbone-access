package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// TenantHeader is an advisory tenant selector. It is NEVER authoritative on its
// own: the iam-core tenant_id claim is the sole source of truth for the
// caller's tenant. When the header is present it must equal the claim, else the
// request is rejected with 403 to stop a token issued for one tenant from being
// used against another.
const TenantHeader = "X-Tenant-ID"

// ResolveTenant returns a middleware that establishes the request's tenant
// (iam-core tenant_id, mapped 1:1 to a ShieldNet workspace). It must run after
// Auth and is fail-closed:
//
//  1. No validated claims → 401.
//  2. No tenant_id claim → 403. The token is not scoped to a tenant; we do NOT
//     fall back to a client-supplied X-Tenant-ID header, because that would let
//     any authenticated principal act as an arbitrary tenant (a tenant-
//     isolation bypass). Cross-tenant / platform operations are a separate,
//     explicitly authorized path (a future management route), never an implicit
//     header fallback here.
//  3. X-Tenant-ID header present and unequal to the claim → 403.
//  4. Otherwise the tenant_id claim is authoritative.
func ResolveTenant() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := ClaimsFromContext(c)
		if claims == nil {
			abort(c, http.StatusUnauthorized, "authentication required")
			return
		}
		claimTenant := claims.TenantID
		if claimTenant == "" {
			// Fail closed: a token with no tenant_id claim cannot be scoped to a
			// tenant via a header supplied by the caller.
			abort(c, http.StatusForbidden, "token is not scoped to a tenant")
			return
		}
		if header := c.GetHeader(TenantHeader); header != "" && header != claimTenant {
			abort(c, http.StatusForbidden, "tenant mismatch between token and header")
			return
		}
		c.Set(ctxKeyTenantID, claimTenant)
		c.Next()
	}
}

// TenantFromContext returns the resolved tenant id, or "" when ResolveTenant
// did not run / did not set one.
func TenantFromContext(c *gin.Context) string {
	v, ok := c.Get(ctxKeyTenantID)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}
