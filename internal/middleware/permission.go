package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequirePermission returns a middleware that authorizes a request against a
// required permission scope (e.g. "compliance.export"). It fails closed: the
// request is rejected unless the validated token carries the scope, a matching
// wildcard scope, or the global "*" scope. Must run after Auth.
//
// Matching rules (all against the token's scopes claim):
//   - exact: a scope equal to the required permission grants it.
//   - prefix wildcard: a scope like "compliance.*" grants any "compliance.X".
//   - global: the "*" scope grants everything (reserved for break-glass admin
//     tokens minted by iam-core).
//
// Authorization is scope-based rather than role-based so the access product
// never has to hard-code iam-core's role taxonomy; iam-core decides which roles
// map to which scopes when it mints the token.
func RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := ClaimsFromContext(c)
		if claims == nil {
			abort(c, http.StatusUnauthorized, "authentication required")
			return
		}
		if !hasPermission(claims.Scopes, permission) {
			// Do not echo which scope was required beyond the static message —
			// the client already knows the route it called.
			abort(c, http.StatusForbidden, "insufficient permission")
			return
		}
		c.Next()
	}
}

// hasPermission reports whether scopes satisfies the required permission under
// the exact / prefix-wildcard / global rules described on RequirePermission.
func hasPermission(scopes []string, required string) bool {
	if required == "" {
		return false // fail closed: an empty requirement is a programming error
	}
	for _, s := range scopes {
		if s == required || s == "*" {
			return true
		}
		// Prefix wildcard: "compliance.*" matches "compliance.export".
		if len(s) >= 2 && s[len(s)-2:] == ".*" {
			prefix := s[:len(s)-1] // keep the trailing dot, drop the star
			if len(required) > len(prefix) && required[:len(prefix)] == prefix {
				return true
			}
		}
	}
	return false
}
