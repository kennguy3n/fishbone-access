package handlers

import (
	"context"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/middleware"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
	"github.com/kennguy3n/fishbone-access/internal/services/billing"
)

// billingService is the slice of *billing.Service the read/admin handlers need.
// Declared as an interface so the handlers are decoupled from the concrete
// service and unit-testable with a fake.
type billingService interface {
	CurrentStatement(ctx context.Context, workspaceID uuid.UUID) (billing.Statement, error)
	StatementFor(ctx context.Context, workspaceID uuid.UUID, period string) (billing.Statement, error)
	QuotaStatus(ctx context.Context, workspaceID uuid.UUID) (billing.PlanStatus, error)
	SetPlan(ctx context.Context, p billing.TenantPlan) error
}

// periodPattern matches the "YYYY-MM" billing-period key produced by
// usage.PeriodOf, so a client-supplied ?period= is validated before it reaches
// the store rather than silently returning an empty statement for garbage.
var periodPattern = regexp.MustCompile(`^\d{4}-\d{2}$`)

// billingHandlers serves the authenticated per-tenant billing surface: a tenant
// reads its OWN current/period statement and plan/quota status, and an owner
// assigns its plan. Like every other handler the workspace is derived from the
// request context (never the body), so a caller can only ever read or change
// its own billing; RLS on tenant_plan is the database-tier backstop on the same
// connection.
type billingHandlers struct {
	svc billingService
}

func newBillingHandlers(svc billingService) *billingHandlers {
	return &billingHandlers{svc: svc}
}

// register mounts the billing routes on the tenant-scoped group. The reads are
// gated by billing.read (owner/admin — cost/account data, like usage.read); the
// plan write is gated by billing.manage (owner-only, like workspace.manage).
func (h *billingHandlers) register(g *gin.RouterGroup) {
	g.GET("/billing/statement", middleware.RequirePermission(authz.PermBillingRead), h.statement)
	g.GET("/billing/plan", middleware.RequirePermission(authz.PermBillingRead), h.plan)
	g.PUT("/billing/plan", middleware.RequirePermission(authz.PermBillingManage), h.setPlan)
}

// statement returns the calling tenant's statement for the current period, or
// for an explicit ?period=YYYY-MM. A period with no usage is a valid, fully
// determined statement (base price, zero overage), not an error.
func (h *billingHandlers) statement(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var (
		st  billing.Statement
		err error
	)
	if period := c.Query("period"); period != "" {
		if !periodPattern.MatchString(period) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid period; expected YYYY-MM"})
			return
		}
		st, err = h.svc.StatementFor(c.Request.Context(), ws, period)
	} else {
		st, err = h.svc.CurrentStatement(c.Request.Context(), ws)
	}
	if err != nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "statement generation failed"})
		return
	}
	c.JSON(http.StatusOK, st)
}

// plan returns the calling tenant's plan and current-period quota status.
func (h *billingHandlers) plan(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	status, err := h.svc.QuotaStatus(c.Request.Context(), ws)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "plan lookup failed"})
		return
	}
	c.JSON(http.StatusOK, status)
}

// setPlanRequest is the body for assigning the calling tenant's plan. The two
// override fields are optional; zero means "inherit the plan default" at resolve
// time, matching the tenant_plan column semantics.
type setPlanRequest struct {
	Plan                string `json:"plan" binding:"required"`
	APIRequestsIncluded int64  `json:"api_requests_included"`
	APIRequestsHardCap  int64  `json:"api_requests_hard_cap"`
}

// setPlan assigns the calling tenant's plan (owner-only). It validates the plan
// against the known tier ladder and rejects negative overrides rather than
// silently clamping, so a malformed request is an explicit 400. It deliberately
// sets only the CALLER's own plan: the authenticated request path is RLS-scoped
// to the caller's workspace, so a cross-tenant assignment is not expressible
// here — that is a provisioning/worker concern running on the unscoped context,
// exactly like the usage flush.
func (h *billingHandlers) setPlan(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var req setPlanRequest
	if !bind(c, &req) {
		return
	}
	if !billing.IsKnownPlan(req.Plan) {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "unknown plan; expected one of trial, base, pro, enterprise"})
		return
	}
	if req.APIRequestsIncluded < 0 || req.APIRequestsHardCap < 0 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "quota overrides must be non-negative"})
		return
	}
	plan := billing.TenantPlan{
		WorkspaceID:         ws,
		Plan:                req.Plan,
		APIRequestsIncluded: req.APIRequestsIncluded,
		APIRequestsHardCap:  req.APIRequestsHardCap,
	}
	// Reject an override whose effective hard cap would sit below the included
	// allowance (e.g. raising Included past the inherited cap, or lowering the
	// cap below the inherited Included): that would hard-deny the tenant before
	// it consumes the quota it is entitled to, so it is an explicit 400 rather
	// than a silently broken cap.
	if err := billing.ValidateOverrides(plan); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.svc.SetPlan(c.Request.Context(), plan); err != nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "plan update failed"})
		return
	}
	status, err := h.svc.QuotaStatus(c.Request.Context(), ws)
	if err != nil {
		// The write succeeded; only the read-back failed. Report success
		// without the echo rather than misleading the caller into a retry.
		c.JSON(http.StatusOK, gin.H{"plan": billing.NormalizePlan(req.Plan)})
		return
	}
	c.JSON(http.StatusOK, status)
}
