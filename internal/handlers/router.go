// Package handlers wires the ShieldNet Access HTTP API. NewRouter assembles the
// Gin engine: always-on liveness/readiness probes plus an authenticated
// /api/v1 surface guarded by the iam-core token + tenant-resolution middleware.
//
// Session 1A intentionally ships the routing skeleton and the cross-cutting
// middleware; the access-request, connector, policy, and PAM handlers are added
// by Sessions 1B-1E onto this same group.
package handlers

import (
	"net/http"
	"sync/atomic"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/fishbone-access/internal/middleware"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// Deps are the runtime dependencies the router needs. Validator may be nil when
// iam-core is not configured (degraded dev boot): in that case the
// authenticated surface returns 503 rather than allowing unauthenticated access.
type Deps struct {
	Validator middleware.TokenValidator
	Ready     *atomic.Bool
}

// NewRouter builds the Gin engine.
func NewRouter(deps Deps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/health", liveness)
	r.GET("/readyz", readiness(deps.Ready))
	// Unauthenticated diagnostics: the registered connector provider keys
	// (drives the connector-count CI guard).
	r.GET("/api/v1/connectors/providers", listProviders)

	// Tenant-scoped API. With iam-core configured the group is guarded by the
	// auth + tenant-resolution middleware; without it the group fails closed
	// with 503 (the routes still match so the failure is explicit, not a 404).
	// Sessions 1B-1E attach their handlers to this same group.
	api := r.Group("/api/v1")
	if deps.Validator != nil {
		api.Use(middleware.Auth(deps.Validator), middleware.ResolveTenant())
	} else {
		api.Use(degraded)
	}
	api.GET("/me", whoami)

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
