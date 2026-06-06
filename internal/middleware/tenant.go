package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// TenantHeader is the optional explicit tenant selector. When both the header
// and a JWT tenant_id claim are present they MUST match (the claim is
// authoritative); a mismatch is a 403 to prevent a token for one tenant being
// used to act on another.
const TenantHeader = "X-Tenant-ID"

// ResolveTenant returns a middleware that establishes the request's tenant
// (iam-core tenant_id, mapped 1:1 to a ShieldNet workspace). It must run after
// Auth. Resolution order:
//
//  1. tenant_id JWT claim, if present, is authoritative.
//  2. otherwise the X-Tenant-ID header is used.
//  3. header + claim present and unequal → 403.
//  4. neither present → 400.
func ResolveTenant() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := ClaimsFromContext(c)
		if claims == nil {
			abort(c, http.StatusUnauthorized, "authentication required")
			return
		}
		header := c.GetHeader(TenantHeader)
		claimTenant := claims.TenantID

		switch {
		case claimTenant != "" && header != "" && claimTenant != header:
			abort(c, http.StatusForbidden, "tenant mismatch between token and header")
			return
		case claimTenant != "":
			c.Set(ctxKeyTenantID, claimTenant)
		case header != "":
			c.Set(ctxKeyTenantID, header)
		default:
			abort(c, http.StatusBadRequest, "tenant not specified")
			return
		}
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
