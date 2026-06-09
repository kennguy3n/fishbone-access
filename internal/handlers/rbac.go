package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/fishbone-access/internal/middleware"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
)

// rbacHandlers serves the workspace role/permission administration surface
// (the "Roles & Permissions" Settings screen). Every handler derives the
// workspace from the request context (set by RequireTenant) and the actor +
// actor-role from the authz context (set by AuthzMiddleware) — never from the
// request body — so a caller cannot administer another tenant or spoof a
// privilege level.
type rbacHandlers struct {
	rbac *authz.RBACService
}

func newRBACHandlers(rbac *authz.RBACService) *rbacHandlers {
	return &rbacHandlers{rbac: rbac}
}

// register mounts the RBAC routes on the tenant-scoped group. The group must
// already carry Auth → ResolveTenant → RequireTenant → AuthzMiddleware.
//
// Read endpoints require rbac.read; mutations require rbac.manage. The
// owner-escalation rule (only an owner may grant owner or modify an existing
// owner) is enforced inside the service inside the write transaction, since a
// flat permission cannot express that row-conditional rule.
func (h *rbacHandlers) register(g *gin.RouterGroup) {
	g.GET("/rbac/roles", middleware.RequirePermission(authz.PermRBACRead), h.listRoles)
	g.GET("/rbac/members", middleware.RequirePermission(authz.PermRBACRead), h.listMembers)
	g.PUT("/rbac/members/:userID", middleware.RequirePermission(authz.PermRBACManage), h.upsertMember)
	g.DELETE("/rbac/members/:userID", middleware.RequirePermission(authz.PermRBACManage), h.deleteMember)
}

// roleView is the wire representation of one role and the permissions it holds.
type roleView struct {
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

// memberView is the wire representation of one workspace membership.
type memberView struct {
	UserID    string `json:"user_id"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// listRoles returns the full role catalogue, each role's permission set, and
// the flat permission catalogue, so the UI can render the read-only
// role × permission matrix without hardcoding the model. The mapping is static
// (code-defined), so this endpoint is workspace-agnostic in its payload but
// still gated by workspace membership + rbac.read.
func (h *rbacHandlers) listRoles(c *gin.Context) {
	roles := make([]roleView, 0, len(authz.AllWorkspaceRoles))
	for _, role := range authz.AllWorkspaceRoles {
		perms := authz.PermissionsForRole(role).Slice()
		strs := make([]string, 0, len(perms))
		for _, p := range perms {
			strs = append(strs, string(p))
		}
		roles = append(roles, roleView{Role: string(role), Permissions: strs})
	}

	allPerms := make([]string, 0, len(authz.AllPermissions))
	for _, p := range authz.AllPermissions {
		allPerms = append(allPerms, string(p))
	}

	c.JSON(http.StatusOK, gin.H{
		"roles":       roles,
		"permissions": allPerms,
	})
}

// listMembers returns every membership in the caller's workspace.
func (h *rbacHandlers) listMembers(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	members, err := h.rbac.ListMembers(c.Request.Context(), ws)
	if err != nil {
		h.fail(c, err)
		return
	}
	out := make([]memberView, 0, len(members))
	for _, m := range members {
		out = append(out, memberView{
			UserID:    m.UserID,
			Role:      string(m.Role),
			CreatedAt: m.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt: m.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	c.JSON(http.StatusOK, gin.H{"members": out})
}

type upsertMemberBody struct {
	Role string `json:"role" binding:"required"`
}

// upsertMember assigns (creates or updates) the role of a member in the
// caller's workspace. The target user id comes from the path; the role from the
// body; the actor + actor-role from the authz context. The service enforces the
// last-owner and owner-escalation invariants inside the write transaction.
func (h *rbacHandlers) upsertMember(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	targetUserID := c.Param("userID")
	if targetUserID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "user id is required"})
		return
	}
	var body upsertMemberBody
	if !bind(c, &body) {
		return
	}
	role, err := authz.ParseWorkspaceRole(body.Role)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actorRole, ok := middleware.RoleFromContext(c)
	if !ok {
		// AuthzMiddleware must have run for this route to be reachable; absence
		// is a wiring bug — fail closed.
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "no authorization context"})
		return
	}

	if err := h.rbac.UpsertMemberAs(c.Request.Context(), ws, targetUserID, role, actorRole, actor(c)); err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, memberView{UserID: targetUserID, Role: string(role)})
}

// deleteMember removes a member from the caller's workspace. Idempotent: a
// delete against a non-member returns 204. The service rejects removing the
// last owner.
func (h *rbacHandlers) deleteMember(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	targetUserID := c.Param("userID")
	if targetUserID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "user id is required"})
		return
	}
	if err := h.rbac.DeleteMember(c.Request.Context(), ws, targetUserID, actor(c)); err != nil {
		h.fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// fail maps authz service sentinel errors to HTTP status codes, mirroring the
// lifecycle handlers' convention. Unknown errors are 500 and logged, never
// echoed.
func (h *rbacHandlers) fail(c *gin.Context, err error) {
	switch {
	case errors.Is(err, authz.ErrValidation), errors.Is(err, authz.ErrInvalidRole):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, authz.ErrMembershipNotFound):
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, authz.ErrOwnerEscalationForbidden):
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": err.Error()})
	case errors.Is(err, authz.ErrLastOwnerProtected):
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": err.Error()})
	default:
		logger.Errorf(c.Request.Context(), "rbac: unhandled error: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}
