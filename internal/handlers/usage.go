package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/fishbone-access/internal/middleware"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
	"github.com/kennguy3n/fishbone-access/internal/services/usage"
)

// usageHandlers serves the authenticated per-tenant usage read surface: a
// tenant reads its OWN current-period metering counters (the cost-to-serve
// attribution behind the rollup). Like every other handler it derives the
// workspace from the request context (never the body), so a caller can only
// ever read its own usage; RLS on tenant_usage is the database-tier backstop on
// the same connection.
type usageHandlers struct {
	reader usage.Reader
}

func newUsageHandlers(reader usage.Reader) *usageHandlers {
	return &usageHandlers{reader: reader}
}

// register mounts the usage read route on the tenant-scoped group. The group
// already carries Auth + ResolveTenant + RequireTenant, and (in production)
// AuthzMiddleware so the RequirePermission gate enforces; when RBAC is not
// wired RequirePermission no-ops, preserving the pre-RBAC behaviour.
//
// The route is gated by usage.read — a billing/account-administration surface
// held by the governance roles (owner/admin), not the operational or audit
// seats — because a tenant's consumption is account data, not part of the
// access-review or audit surface.
func (h *usageHandlers) register(g *gin.RouterGroup) {
	g.GET("/usage", middleware.RequirePermission(authz.PermUsageRead), h.currentUsage)
}

// usageMetric is one metered counter in the read response.
type usageMetric struct {
	Metric    string `json:"metric"`
	Count     int64  `json:"count"`
	UpdatedAt string `json:"updated_at"`
}

// currentUsage returns the calling tenant's usage for the current billing
// period as a stable, metric-keyed list. An absent or empty rollup is a
// successful empty response (the tenant simply has no recorded usage yet), not
// an error.
func (h *usageHandlers) currentUsage(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	rows, err := h.reader.GetCurrentUsage(c.Request.Context(), ws)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "usage lookup failed"})
		return
	}
	metrics := make([]usageMetric, 0, len(rows))
	// Default to the current period so an empty rollup still reports which
	// period the (zero) usage is for; a present row pins the exact period.
	period := usage.PeriodOf(time.Now())
	for _, r := range rows {
		period = r.Period
		metrics = append(metrics, usageMetric{
			Metric:    r.Metric,
			Count:     r.Count,
			UpdatedAt: r.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"period":  period,
		"metrics": metrics,
	})
}
