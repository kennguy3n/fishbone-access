// Package middleware holds the Gin HTTP middleware for ShieldNet Access:
// iam-core bearer-token authentication and tenant resolution/isolation.
package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
)

// Context keys under which the middleware stores resolved values. Handlers read
// them via the typed accessors below rather than touching the strings.
const (
	ctxKeyClaims   = "iamcore_claims"
	ctxKeyTenantID = "tenant_id"
)

// TokenValidator is the subset of *iamcore.Validator the auth middleware needs.
// Declaring it as an interface keeps the middleware unit-testable with a fake.
type TokenValidator interface {
	Validate(token string) (*iamcore.Claims, error)
}

// Auth returns a Gin middleware that requires a valid iam-core bearer token.
// It fails closed: any missing/invalid token aborts with 401 and the cause is
// never echoed to the client.
func Auth(v TokenValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := bearerToken(c.GetHeader("Authorization"))
		if raw == "" {
			abort(c, http.StatusUnauthorized, "missing bearer token")
			return
		}
		claims, err := v.Validate(raw)
		if err != nil {
			abort(c, http.StatusUnauthorized, "invalid token")
			return
		}
		c.Set(ctxKeyClaims, claims)
		c.Next()
	}
}

// RequireMFA returns a middleware that rejects requests whose token does not
// carry a satisfied-MFA claim. Mount it on sensitive routes (policy promotion,
// connector secret reveal). Must run after Auth.
func RequireMFA() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := ClaimsFromContext(c)
		if claims == nil {
			abort(c, http.StatusUnauthorized, "authentication required")
			return
		}
		if !claims.MFASatisfied {
			abort(c, http.StatusForbidden, "step-up MFA required")
			return
		}
		c.Next()
	}
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if len(header) > len(prefix) && strings.EqualFold(header[:len(prefix)], prefix) {
		return strings.TrimSpace(header[len(prefix):])
	}
	return ""
}

func abort(c *gin.Context, code int, msg string) {
	c.AbortWithStatusJSON(code, gin.H{"error": msg})
}

// ClaimsFromContext returns the validated iam-core claims set by Auth, or nil.
func ClaimsFromContext(c *gin.Context) *iamcore.Claims {
	v, ok := c.Get(ctxKeyClaims)
	if !ok {
		return nil
	}
	claims, _ := v.(*iamcore.Claims)
	return claims
}
