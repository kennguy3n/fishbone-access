package handlers

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/broker"
	"github.com/kennguy3n/fishbone-access/internal/middleware"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/pkg/ratelimit"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
)

// agentHandlers serve the outbound connector agent surface: minting one-shot
// enrollment tokens, listing agents with derived health, viewing the targets an
// agent can reach, binding/unbinding PAM targets to an agent, and revoking an
// agent. The public, unauthenticated enrollment endpoint that an agent redeems
// its token against is mounted separately (registerAgentEnrollment) because it
// is token-gated rather than tenant-session gated.
//
// Reads are gated by pam.target.read and mutations by pam.target.write — agents
// are target-connectivity configuration, so they reuse the PAM target RBAC
// tier rather than introducing a parallel permission set. The gates no-op when
// the RBAC tier is absent (legacy/test boots), exactly like the PAM handlers.
type agentHandlers struct {
	enroll *broker.EnrollmentService // nil when no agent CA is configured
	dir    *broker.AgentDirectory
}

// newAgentHandlers wires the directory (always, when a DB is present) and the
// enrollment service (only when the deployment configured an agent CA). When
// enroll is nil the read/bind surface still works; mint/revoke return 503.
func newAgentHandlers(deps Deps) *agentHandlers {
	return &agentHandlers{
		enroll: deps.AgentEnrollment,
		dir:    broker.NewAgentDirectory(deps.DB),
	}
}

// register mounts the tenant-scoped agent management routes. The group must
// already carry Auth + ResolveTenant + RequireTenant.
func (h *agentHandlers) register(g *gin.RouterGroup) {
	ag := g.Group("/agents")
	ag.GET("", middleware.RequirePermission(authz.PermPAMTargetRead), h.listAgents)
	ag.GET("/:id", middleware.RequirePermission(authz.PermPAMTargetRead), h.getAgent)
	ag.GET("/:id/reachable", middleware.RequirePermission(authz.PermPAMTargetRead), h.listReachable)
	ag.GET("/:id/targets", middleware.RequirePermission(authz.PermPAMTargetRead), h.listBoundTargets)

	ag.POST("", middleware.RequirePermission(authz.PermPAMTargetWrite), h.mintToken)
	ag.POST("/:id/revoke", middleware.RequirePermission(authz.PermPAMTargetWrite), h.revokeAgent)
	ag.POST("/:id/targets", middleware.RequirePermission(authz.PermPAMTargetWrite), h.bindTarget)
	ag.DELETE("/:id/targets/:targetId", middleware.RequirePermission(authz.PermPAMTargetWrite), h.unbindTarget)
}

// registerAgentEnrollment mounts the public, token-gated enrollment endpoint on
// the engine (outside the authenticated /api/v1 group). It is a no-op when no
// enrollment service is configured, so the route only exists where the agent CA
// is wired.
func registerAgentEnrollment(r *gin.Engine, enroll *broker.EnrollmentService) {
	if enroll == nil {
		return
	}
	// The endpoint is public (no tenant session to key the per-tenant limiter
	// on), so guard it with a small per-client-IP token bucket. Brute force is
	// already infeasible (256-bit secrets, stored hashed), but this caps the
	// anonymous request volume so the per-request DB lookup can't be used for
	// resource exhaustion. In-memory and fail-open, matching the house limiter.
	ipLimiter := ratelimit.New(ratelimit.Config{RPS: 5, Burst: 20})
	r.POST("/api/v1/agents/enroll", enrollIPThrottle(ipLimiter), func(c *gin.Context) {
		var body broker.EnrollHTTPRequest
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		res, err := enroll.Enroll(c.Request.Context(), broker.EnrollInput{
			RawToken:     body.Token,
			CSRPEM:       []byte(body.CSR),
			AgentVersion: body.AgentVersion,
			Platform:     body.Platform,
		})
		if err != nil {
			// Coarse, constant response for any token failure so an
			// unauthenticated caller cannot distinguish unknown/expired/used.
			if errors.Is(err, broker.ErrEnrollment) || errors.Is(err, broker.ErrValidation) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired enrollment token"})
				return
			}
			logger.Errorf(c.Request.Context(), "agent: enroll: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "enrollment failed"})
			return
		}
		c.JSON(http.StatusOK, broker.EnrollHTTPResponse{
			AgentID:    res.AgentID.String(),
			ClientCert: string(res.ClientCertPEM),
			CACert:     string(res.CACertPEM),
			RelayAddr:  res.RelayAddr,
			NotAfter:   res.NotAfter,
		})
	})
}

// ipThrottler is the slice of a rate limiter the enrollment throttle needs.
type ipThrottler interface {
	Allow(key string) (bool, time.Duration)
}

// enrollIPThrottle caps the public enrollment endpoint per client IP. It fails
// open (nil limiter admits) and advertises Retry-After on a throttle, mirroring
// the authenticated rate-limit middleware's posture.
func enrollIPThrottle(limiter ipThrottler) gin.HandlerFunc {
	return func(c *gin.Context) {
		if limiter == nil {
			c.Next()
			return
		}
		ok, retry := limiter.Allow(c.ClientIP())
		if ok {
			c.Next()
			return
		}
		if secs := int(math.Ceil(retry.Seconds())); secs > 0 {
			c.Header("Retry-After", strconv.Itoa(secs))
		}
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too many enrollment attempts; retry later"})
	}
}

// --- reads ---

func (h *agentHandlers) listAgents(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	agents, err := h.dir.ListAgents(c.Request.Context(), ws)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"agents": agents})
}

func (h *agentHandlers) getAgent(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	view, err := h.dir.GetAgent(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, view)
}

func (h *agentHandlers) listReachable(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	rows, err := h.dir.Reachable(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"reachable": rows})
}

func (h *agentHandlers) listBoundTargets(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	rows, err := h.dir.BoundTargets(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"targets": rows})
}

// --- mutations ---

type mintTokenBody struct {
	Name string `json:"name" binding:"required"`
	// TTLSeconds optionally overrides the default token lifetime; 0 keeps the
	// service default (short by design).
	TTLSeconds int `json:"ttl_seconds"`
}

func (h *agentHandlers) mintToken(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	if h.enroll == nil {
		h.enrollmentUnavailable(c)
		return
	}
	var body mintTokenBody
	if !bind(c, &body) {
		return
	}
	raw, token, err := h.enroll.MintToken(c.Request.Context(), broker.MintTokenInput{
		WorkspaceID: ws,
		Name:        body.Name,
		Actor:       actor(c),
		TTL:         time.Duration(body.TTLSeconds) * time.Second,
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	// The raw token is returned exactly once — only its hash is persisted.
	c.JSON(http.StatusCreated, gin.H{
		"token":      raw,
		"token_id":   token.ID,
		"name":       token.Name,
		"expires_at": token.ExpiresAt,
	})
}

func (h *agentHandlers) revokeAgent(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	if h.enroll == nil {
		h.enrollmentUnavailable(c)
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	if err := h.enroll.Revoke(c.Request.Context(), ws, id, actor(c)); err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked", "agent_id": id})
}

type bindTargetBody struct {
	TargetID string `json:"target_id" binding:"required"`
}

func (h *agentHandlers) bindTarget(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	agentID, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	var body bindTargetBody
	if !bind(c, &body) {
		return
	}
	targetID, err := uuid.Parse(body.TargetID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid target_id"})
		return
	}
	if err := h.dir.BindTarget(c.Request.Context(), ws, agentID, targetID, actor(c)); err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "bound", "agent_id": agentID, "target_id": targetID})
}

func (h *agentHandlers) unbindTarget(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	targetID, ok := pathUUID(c, "targetId")
	if !ok {
		return
	}
	if err := h.dir.UnbindTarget(c.Request.Context(), ws, targetID, actor(c)); err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "unbound", "target_id": targetID})
}

// --- helpers ---

func (h *agentHandlers) enrollmentUnavailable(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
		"error": "agent enrollment is not configured on this deployment",
	})
}

func (h *agentHandlers) fail(c *gin.Context, err error) {
	switch {
	case errors.Is(err, broker.ErrValidation):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case broker.IsNotFound(err):
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "not found"})
	case errors.Is(err, broker.ErrEnrollment):
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired enrollment token"})
	default:
		logger.Errorf(c.Request.Context(), "agent: unhandled error: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}
