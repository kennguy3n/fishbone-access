package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/packs"
)

// registerPacks mounts the policy-pack routes on the tenant-scoped group.
// Listing the catalog is tenant-agnostic but stays behind auth for a uniform
// surface; applying materializes drafts into the caller's workspace.
func (h *lifecycleHandlers) registerPacks(g *gin.RouterGroup) {
	g.GET("/packs", h.listPacks)
	g.GET("/packs/:id", h.getPack)
	// Apply only creates DRAFTS (no data-plane change), so — like POST
	// /policies — it does not require step-up MFA. Each draft still has to be
	// simulated and promoted (MFA-gated) before it can ever take effect.
	g.POST("/packs/:id/apply", h.applyPack)
}

func (h *lifecycleHandlers) listPacks(c *gin.Context) {
	filter := packs.Filter{
		Region:    c.Query("region"),
		Industry:  c.Query("industry"),
		Framework: c.Query("framework"),
	}
	if t := c.Query("tier"); t != "" {
		// An unparseable tier is a client error rather than a silent no-filter.
		n, err := strconv.Atoi(t)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid tier"})
			return
		}
		filter.Tier = n
	}
	c.JSON(http.StatusOK, gin.H{"packs": packs.ListPacks(filter)})
}

func (h *lifecycleHandlers) getPack(c *gin.Context) {
	pack, ok := packs.FindPack(c.Param("id"))
	if !ok {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": packs.ErrPackNotFound.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"pack": pack})
}

type applyPackBody struct {
	// TemplateKeys selects which templates to materialize. Empty/omitted means
	// apply every template in the pack.
	TemplateKeys []string `json:"template_keys"`
}

func (h *lifecycleHandlers) applyPack(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var body applyPackBody
	if !bindOptional(c, &body) {
		return
	}
	applied, err := h.packs.Apply(c.Request.Context(), ws, c.Param("id"), body.TemplateKeys, actor(c))
	if err != nil {
		h.failPack(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"applied": applied, "count": len(applied)})
}

// failPack maps pack sentinel errors to status codes, deferring anything from
// the underlying policy lifecycle (raised while materializing drafts) to fail.
func (h *lifecycleHandlers) failPack(c *gin.Context, err error) {
	switch {
	case errors.Is(err, packs.ErrPackNotFound):
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, packs.ErrNoTemplates), errors.Is(err, packs.ErrTemplateNotInPack):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	default:
		// Could be a lifecycle validation/transition error from CreatePolicy, or
		// a genuine internal fault; reuse the shared mapper which logs + 500s
		// anything unknown without leaking it.
		logger.Errorf(c.Request.Context(), "packs: apply error: %v", err)
		h.fail(c, err)
	}
}
