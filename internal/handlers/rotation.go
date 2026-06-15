package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/middleware"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// rotationHandlers serves the credential-rotation REST surface: per-target
// rotation policy CRUD, rotation history, on-demand "rotate now", and minting
// of ephemeral (dynamic) database credentials for a live JIT lease. Workspace
// and actor are always derived from the authenticated context, never from
// client input — identical to pamHandlers.
type rotationHandlers struct {
	vault    *pam.Vault
	policies *pam.RotationPolicyService
	engine   *pam.RotationEngine
	dynamic  *pam.DynamicCredentialService
	leases   *pam.PAMLeaseService
}

// newRotationHandlers wires the rotation services from shared Deps, reusing the
// exact vault/encryptor construction the PAM handlers use so rotation re-seals
// with the same per-workspace key path. Returns nil when no DB is wired (the
// scoped block gates on DB presence, so routes are simply not mounted then).
func newRotationHandlers(deps Deps, vault *pam.Vault, leases *pam.PAMLeaseService) *rotationHandlers {
	if deps.DB == nil || vault == nil {
		return nil
	}
	// Honour ACCESS_ROTATION_DIAL_TIMEOUT (threaded through Deps) so an
	// API-initiated "rotate now" / mint uses the SAME upstream dial timeout as
	// the scheduled sweep in access-workflow-engine. Zero means main did not
	// wire it (tests/degraded boots) — fall back to the shared 10s default.
	dialTimeout := deps.RotationDialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	registry := pam.NewExecutorRegistry(dialTimeout)
	engine := pam.NewRotationEngine(deps.DB, vault, registry)
	return &rotationHandlers{
		vault:    vault,
		policies: pam.NewRotationPolicyService(deps.DB, vault, registry),
		engine:   engine,
		dynamic:  pam.NewDynamicCredentialService(deps.DB, vault, dialTimeout),
		leases:   leases,
	}
}

// register mounts rotation routes on the tenant-scoped group. The group must
// already carry Auth + ResolveTenant + RequireTenant (+ RBAC when wired). The
// routes live under the existing /pam namespace so the console talks to one
// PAM API surface.
func (h *rotationHandlers) register(g *gin.RouterGroup) {
	rg := g.Group("/pam")

	// Workspace-wide policy listing for the Rotation console landing page.
	rg.GET("/rotation/policies", middleware.RequirePermission(authz.PermPAMTargetRead), h.listPolicies)

	// Per-target rotation status (policy + recent history + live ephemeral
	// credentials) and policy management. Reads need target.read; writing a
	// policy or rotating now mutates privileged credentials so they need
	// target.write, and "rotate now" additionally carries step-up MFA because
	// it changes an upstream secret immediately.
	rg.GET("/targets/:id/rotation", middleware.RequirePermission(authz.PermPAMTargetRead), h.getStatus)
	rg.PUT("/targets/:id/rotation", middleware.RequirePermission(authz.PermPAMTargetWrite), h.upsertPolicy)
	rg.DELETE("/targets/:id/rotation", middleware.RequirePermission(authz.PermPAMTargetWrite), h.deletePolicy)
	rg.GET("/targets/:id/rotation/events", middleware.RequirePermission(authz.PermPAMTargetRead), h.listEvents)
	rg.POST("/targets/:id/rotate", middleware.RequirePermission(authz.PermPAMTargetWrite), middleware.RequireMFA(), h.rotateNow)

	// Mint an ephemeral DB credential for a live lease (operator brokering
	// action, like minting a connect token).
	rg.POST("/targets/:id/dynamic-credentials", middleware.RequirePermission(authz.PermPAMConnect), h.mintDynamic)
}

// rotationStatusResponse is the per-target rotation view the console renders.
type rotationStatusResponse struct {
	TargetID    uuid.UUID                  `json:"target_id"`
	Protocol    string                     `json:"protocol"`
	Rotatable   bool                       `json:"rotatable"`
	Policy      *models.RotationPolicy     `json:"policy"`
	Events      []models.RotationEvent     `json:"events"`
	DynamicCred []models.DynamicCredential `json:"dynamic_credentials"`
}

func (h *rotationHandlers) listPolicies(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	rows, err := h.policies.ListPolicies(c.Request.Context(), ws)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"policies": rows})
}

func (h *rotationHandlers) getStatus(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	// Confirm the target exists in this workspace (404 maps cleanly) and learn
	// its protocol so the UI can show whether rotation is even possible.
	target, terr := h.vault.GetTarget(ctx, ws, id)
	if terr != nil {
		h.fail(c, terr)
		return
	}
	policy, err := h.policies.GetPolicy(ctx, ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	events, err := h.policies.ListEvents(ctx, ws, id, 20)
	if err != nil {
		h.fail(c, err)
		return
	}
	creds, err := h.policies.ListActiveDynamicCredentials(ctx, ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, rotationStatusResponse{
		TargetID:    id,
		Protocol:    target.Protocol,
		Rotatable:   h.policies.RotatableProtocol(target.Protocol),
		Policy:      policy,
		Events:      events,
		DynamicCred: creds,
	})
}

type upsertPolicyBody struct {
	Mode              string `json:"mode" binding:"required"`
	IntervalSeconds   int64  `json:"interval_seconds"`
	RotateOnCheckin   bool   `json:"rotate_on_checkin"`
	DynamicEnabled    bool   `json:"dynamic_enabled"`
	DynamicTTLSeconds int64  `json:"dynamic_ttl_seconds"`
	Enabled           bool   `json:"enabled"`
}

func (h *rotationHandlers) upsertPolicy(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	var body upsertPolicyBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	policy, err := h.policies.UpsertPolicy(c.Request.Context(), ws, id, pam.PolicyInput{
		Mode:              body.Mode,
		IntervalSeconds:   body.IntervalSeconds,
		RotateOnCheckin:   body.RotateOnCheckin,
		DynamicEnabled:    body.DynamicEnabled,
		DynamicTTLSeconds: body.DynamicTTLSeconds,
		Enabled:           body.Enabled,
	}, actor(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, policy)
}

func (h *rotationHandlers) deletePolicy(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	if err := h.policies.DeletePolicy(c.Request.Context(), ws, id, actor(c)); err != nil {
		h.fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *rotationHandlers) listEvents(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	events, err := h.policies.ListEvents(c.Request.Context(), ws, id, 100)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": events})
}

func (h *rotationHandlers) rotateNow(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	event, err := h.engine.RotateTarget(c.Request.Context(), ws, id, models.RotationTriggerManual, actor(c), nil)
	if err != nil {
		// Two failure shapes come back here. A PREFLIGHT failure (validation,
		// target-not-found, or a protocol with no executor) never touched the
		// upstream and recorded no event (event == nil) — map it to an HTTP
		// status. An OPERATIONAL failure (upstream unreachable, auth/verify/
		// reseal failed) DID run and is recorded as a RotationEvent with
		// status=failed and a descriptive Error; return it 200 so the console
		// shows the specific reason instead of a generic "internal error".
		if event == nil || errors.Is(err, pam.ErrRotationUnsupported) {
			h.fail(c, err)
			return
		}
	}
	c.JSON(http.StatusOK, event)
}

type mintDynamicBody struct {
	LeaseID uuid.UUID `json:"lease_id" binding:"required"`
}

func (h *rotationHandlers) mintDynamic(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	var body mintDynamicBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx := c.Request.Context()
	// The lease must be live and bound to this actor + target before we mint a
	// credential against it — reuse the same guard the connect-token broker uses.
	if h.leases != nil {
		if err := h.leases.ValidateActiveLease(ctx, ws, body.LeaseID, actor(c), id); err != nil {
			h.fail(c, err)
			return
		}
	}
	cred, err := h.dynamic.MintForLease(ctx, ws, id, body.LeaseID, actor(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, cred)
}

// fail maps service errors to HTTP status codes, mirroring pamHandlers.fail.
func (h *rotationHandlers) fail(c *gin.Context, err error) {
	switch {
	case errors.Is(err, pam.ErrValidation), errors.Is(err, pam.ErrDynamicUnsupported):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, pam.ErrDynamicNotEnabled):
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, pam.ErrTargetNotFound), errors.Is(err, pam.ErrLeaseNotFound):
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, pam.ErrRotationUnsupported):
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
	case errors.Is(err, pam.ErrLeaseTerminal), errors.Is(err, pam.ErrLeaseNotApproved):
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, pam.ErrStepUpRequired), errors.Is(err, pam.ErrStepUpInvalid):
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": err.Error()})
	default:
		logger.Errorf(c.Request.Context(), "rotation: unhandled error: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}
