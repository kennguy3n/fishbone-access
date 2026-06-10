package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
)

// Context keys for the RBAC tier. Set by AuthzMiddleware after it resolves the
// caller's workspace membership; read by RequirePermission / the typed
// accessors. Handlers never touch the raw strings.
const (
	ctxKeyRBACRole        = "rbac_role"
	ctxKeyRBACPermissions = "rbac_permissions"

	// ctxKeyAuthzEnabled is a sentinel proving AuthzMiddleware actually ran
	// for this request. RequirePermission distinguishes "RBAC is wired and
	// this principal lacks the permission" (deny) from "RBAC is not installed
	// on this router at all" (no-op) by this key's presence. Without the
	// sentinel a RequirePermission mounted on a router that has no
	// AuthzMiddleware (e.g. a legacy handler test that constructs Deps without
	// an RBAC resolver) would deny every request, which would be a silent
	// fail-shut regression rather than the intended additive behavior.
	ctxKeyAuthzEnabled = "rbac_authz_enabled"
)

// PermissionResolver is the subset of *authz.RBACService that AuthzMiddleware
// needs. Declared as an interface so the middleware is unit-testable with a
// fake and so the wiring is optional (a nil resolver simply leaves the RBAC
// tier uninstalled).
type PermissionResolver interface {
	GetMembership(ctx context.Context, workspaceID uuid.UUID, userID string) (*authz.Membership, error)
}

// AuthzMiddleware resolves the caller's workspace role into a permission set
// and stashes it on the request context for RequirePermission to consult. It
// MUST run after Auth → ResolveTenant → RequireTenant (it needs both the
// verified subject claim and the resolved workspace), and is fail-closed:
//
//  1. No validated claims / empty subject → 401.
//  2. No resolved workspace → 403.
//  3. Caller is not a member of the workspace → 403 (fail closed: a valid JWT
//     for a workspace the user was never added to grants nothing).
//  4. Resolver infrastructure error → 503 (deny, but signal retryable rather
//     than masquerading as an authorization decision).
//
// On success it sets the role, the role's permission set, and the
// authz-enabled sentinel, then calls Next.
func AuthzMiddleware(resolver PermissionResolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := ClaimsFromContext(c)
		if claims == nil || claims.Subject == "" {
			abort(c, http.StatusUnauthorized, "authentication required")
			return
		}
		workspaceID, ok := WorkspaceFromContext(c)
		if !ok {
			abort(c, http.StatusForbidden, "no workspace resolved")
			return
		}

		membership, err := resolver.GetMembership(c.Request.Context(), workspaceID, claims.Subject)
		if err != nil {
			if errors.Is(err, authz.ErrMembershipNotFound) {
				logger.Warnf(c.Request.Context(), "authz: membership denied workspace_id=%s user_id=%s path=%s", workspaceID, claims.Subject, c.FullPath())
				abort(c, http.StatusForbidden, "not a member of this workspace")
				return
			}
			logger.Errorf(c.Request.Context(), "authz: resolve membership failed workspace_id=%s user_id=%s: %v", workspaceID, claims.Subject, err)
			abort(c, http.StatusServiceUnavailable, "authorization unavailable")
			return
		}

		c.Set(ctxKeyRBACRole, membership.Role)
		c.Set(ctxKeyRBACPermissions, authz.PermissionsForRole(membership.Role))
		c.Set(ctxKeyAuthzEnabled, true)
		c.Next()
	}
}

// RequirePermission returns a middleware that denies the request (403, fail
// closed) unless the caller's resolved permission set contains perm. Mount it
// per route after AuthzMiddleware:
//
//	g.POST("/policies/:id/promote", RequirePermission(authz.PermPolicyPromote), h.promotePolicy)
//
// When AuthzMiddleware did NOT run for this request (the sentinel is absent —
// i.e. the router was constructed without an RBAC resolver), RequirePermission
// is a deliberate no-op so the gate can be added to shared routes additively
// without breaking routers that have not yet wired RBAC. In production the API
// always installs AuthzMiddleware, so the gate is always enforced there; the
// no-op path exists only for partial/legacy router constructions.
func RequirePermission(perm authz.Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !authzInstalled(c) {
			c.Next()
			return
		}
		perms, ok := PermissionsFromContext(c)
		if !ok || !perms.Has(perm) {
			denyPermission(c, perm)
			return
		}
		c.Next()
	}
}

// RequireAnyPermission denies unless the caller holds AT LEAST ONE of perms
// (OR-disjunction), for routes reachable under multiple distinct authorities
// (e.g. a resource readable by either its owner-permission or a broad
// audit-read permission). No-ops when AuthzMiddleware did not run, like
// RequirePermission. Calling it with no permissions denies unconditionally
// (an empty disjunction is false) rather than accidentally allowing all.
func RequireAnyPermission(perms ...authz.Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !authzInstalled(c) {
			c.Next()
			return
		}
		held, ok := PermissionsFromContext(c)
		if ok {
			for _, p := range perms {
				if held.Has(p) {
					c.Next()
					return
				}
			}
		}
		denyPermission(c, perms...)
	}
}

// denyPermission emits a structured deny log (so an operator can see exactly
// which principal/role was refused which permission on which route) and aborts
// 403. The required permissions are logged but never echoed to the client,
// which only learns it was forbidden.
func denyPermission(c *gin.Context, required ...authz.Permission) {
	role, _ := RoleFromContext(c)
	logger.Warnf(c.Request.Context(),
		"authz: permission denied role=%s required=%v path=%s method=%s",
		role, required, c.FullPath(), c.Request.Method)
	abort(c, http.StatusForbidden, "insufficient permissions")
}

// authzInstalled reports whether AuthzMiddleware ran for this request.
func authzInstalled(c *gin.Context) bool {
	v, ok := c.Get(ctxKeyAuthzEnabled)
	if !ok {
		return false
	}
	enabled, _ := v.(bool)
	return enabled
}

// RoleFromContext returns the caller's resolved WorkspaceRole. The boolean is
// false when AuthzMiddleware did not run.
func RoleFromContext(c *gin.Context) (authz.WorkspaceRole, bool) {
	v, ok := c.Get(ctxKeyRBACRole)
	if !ok {
		return "", false
	}
	role, ok := v.(authz.WorkspaceRole)
	return role, ok
}

// PermissionsFromContext returns the caller's resolved permission set. The
// boolean is false when AuthzMiddleware did not run. The returned set is the
// shared read-only set cached at init() — callers MUST NOT mutate it.
func PermissionsFromContext(c *gin.Context) (authz.PermissionSet, bool) {
	v, ok := c.Get(ctxKeyRBACPermissions)
	if !ok {
		return nil, false
	}
	perms, ok := v.(authz.PermissionSet)
	return perms, ok
}
