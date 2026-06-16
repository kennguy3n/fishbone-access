package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/broker"
	"github.com/kennguy3n/fishbone-access/internal/middleware"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
	"github.com/kennguy3n/fishbone-access/internal/services/discovery"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// discoveryHandlers serves Feature E — account/asset auto-discovery and
// auto-onboarding. Like the rest of the API every operation derives the
// workspace from the verified tenant context and the actor from the validated
// token subject (never from client input), so a tenant can neither read nor
// mutate another tenant's discovered inventory.
//
// The active agent network sweep dials THROUGH a bound agent, and the agent
// tunnels terminate only in the pam-gateway's relay — not in this API process —
// so the engine here is constructed without a dialer. The API exposes the
// always-available agent source instead (importing the reachable-target specs an
// agent self-reports); active probing runs in the gateway/workflow-engine where
// the relay lives. Connector inventory and DB account enumeration run inline
// here because they use the connector's own credentials / a leased DB
// connection and need no relay.
type discoveryHandlers struct {
	engine *discovery.Engine
}

// newDiscoveryHandlers wires the discovery engine off the shared DB pool. It
// reuses the access-stack credential encryptor (so a policy onboarding
// credential seals with the same per-workspace key path as connector/PAM
// secrets), the PAM vault (so a manual onboard creates a real, sealed PAMTarget
// through the exact same service the PAM surface uses), the lifecycle connector
// resolver (so connector inventory unseals config/secrets the same way the
// JML/reconciler do), and the broker agent directory (so an onboarded asset can
// be pre-bound to the agent that discovered it).
func newDiscoveryHandlers(deps Deps) *discoveryHandlers {
	enc := deps.ConnectorEncryptor
	if enc == nil {
		enc = access.NewDisabledEncryptor()
	}
	var stepUp *pam.StepUpGate
	if deps.Validator != nil {
		stepUp = pam.NewStepUpGate(deps.Validator, 5*time.Minute)
	}
	vault := pam.NewVault(deps.DB, enc, stepUp)
	engine := discovery.NewEngine(deps.DB, vault,
		discovery.WithConfig(deps.Discovery),
		discovery.WithEncryptor(enc),
		discovery.WithConnectorResolver(lifecycle.NewDBConnectorResolver(deps.DB, enc)),
		discovery.WithBinder(broker.NewAgentDirectory(deps.DB)),
	)
	return &discoveryHandlers{engine: engine}
}

// register mounts the tenant-scoped discovery routes. The group must already
// carry Auth + ResolveTenant + RequireTenant + AuthzMiddleware. Reads require
// pam.target.read; every mutation (running a scan, onboarding, dispositioning,
// editing the policy) requires pam.target.write, so a read-only role can browse
// the inventory but cannot change managed state.
func (h *discoveryHandlers) register(g *gin.RouterGroup) {
	d := g.Group("/discovery")
	d.GET("/summary", middleware.RequirePermission(authz.PermPAMTargetRead), h.summary)

	d.GET("/assets", middleware.RequirePermission(authz.PermPAMTargetRead), h.listAssets)
	d.GET("/assets/:assetID", middleware.RequirePermission(authz.PermPAMTargetRead), h.getAsset)
	d.POST("/assets/:assetID/onboard", middleware.RequirePermission(authz.PermPAMTargetWrite), h.onboardAsset)
	d.POST("/assets/:assetID/ignore", middleware.RequirePermission(authz.PermPAMTargetWrite), h.ignoreAsset)

	d.GET("/accounts", middleware.RequirePermission(authz.PermPAMTargetRead), h.listAccounts)
	d.POST("/accounts/:accountID/disposition", middleware.RequirePermission(authz.PermPAMTargetWrite), h.dispositionAccount)

	d.GET("/scans", middleware.RequirePermission(authz.PermPAMTargetRead), h.listScans)
	d.POST("/scans/agent", middleware.RequirePermission(authz.PermPAMTargetWrite), h.scanAgent)
	d.POST("/scans/connector/:connectorID", middleware.RequirePermission(authz.PermPAMTargetWrite), h.scanConnector)
	d.POST("/scans/db/:targetID", middleware.RequirePermission(authz.PermPAMTargetWrite), h.scanDBAccounts)

	d.GET("/policy", middleware.RequirePermission(authz.PermPAMTargetRead), h.getPolicy)
	d.PUT("/policy", middleware.RequirePermission(authz.PermPAMTargetWrite), h.savePolicy)
}

// --- reads ---

func (h *discoveryHandlers) summary(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	s, err := h.engine.Summary(c.Request.Context(), ws)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, s)
}

func (h *discoveryHandlers) listAssets(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	assets, err := h.engine.ListAssets(c.Request.Context(), ws, discovery.AssetFilter{
		Source:   strings.TrimSpace(c.Query("source")),
		Protocol: strings.TrimSpace(c.Query("protocol")),
		Status:   strings.TrimSpace(c.Query("status")),
		Limit:    queryInt(c, "limit"),
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"assets": assets})
}

func (h *discoveryHandlers) getAsset(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "assetID")
	if !ok {
		return
	}
	asset, err := h.engine.GetAsset(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, asset)
}

func (h *discoveryHandlers) listAccounts(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var targetID *uuid.UUID
	if raw := strings.TrimSpace(c.Query("target_id")); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid target_id"})
			return
		}
		targetID = &parsed
	}
	accounts, err := h.engine.ListAccounts(c.Request.Context(), ws, targetID, queryInt(c, "limit"))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"accounts": accounts})
}

func (h *discoveryHandlers) listScans(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	scans, err := h.engine.ListScans(c.Request.Context(), ws, queryInt(c, "limit"))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"scans": scans})
}

// --- scans ---

type scanAgentRequest struct {
	AgentID string `json:"agent_id"`
}

// scanAgent imports the reachable-target specs the named agent self-reported.
// Active port probing through the agent runs in the gateway/workflow-engine
// where the relay lives (see the type doc); this API surface ingests the
// agent's advertised reachability, which needs no relay.
func (h *discoveryHandlers) scanAgent(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var req scanAgentRequest
	if !bindDiscoveryJSON(c, &req) {
		return
	}
	agentID, err := uuid.Parse(strings.TrimSpace(req.AgentID))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
		return
	}
	res, err := h.engine.ImportAgentReachable(c.Request.Context(), ws, agentID, actor(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

func (h *discoveryHandlers) scanConnector(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	connectorID, ok := pathUUID(c, "connectorID")
	if !ok {
		return
	}
	res, err := h.engine.ConnectorInventory(c.Request.Context(), ws, connectorID, actor(c), "manual")
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

func (h *discoveryHandlers) scanDBAccounts(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	targetID, ok := pathUUID(c, "targetID")
	if !ok {
		return
	}
	res, err := h.engine.EnumerateAccounts(c.Request.Context(), ws, targetID, actor(c), "manual")
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

// --- onboarding / disposition ---

type onboardAssetRequest struct {
	Name            string `json:"name"`
	Protocol        string `json:"protocol"`
	Address         string `json:"address"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	PrivateKey      string `json:"private_key"`
	Token           string `json:"token"`
	AgentID         string `json:"agent_id"`
	RequireMFA      bool   `json:"require_mfa"`
	LeaseTTLSeconds int    `json:"lease_ttl_seconds"`
}

func (h *discoveryHandlers) onboardAsset(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	assetID, ok := pathUUID(c, "assetID")
	if !ok {
		return
	}
	var req onboardAssetRequest
	if !bindDiscoveryJSON(c, &req) {
		return
	}
	in := discovery.OnboardAssetInput{
		Name:       strings.TrimSpace(req.Name),
		Protocol:   strings.TrimSpace(req.Protocol),
		Address:    strings.TrimSpace(req.Address),
		Username:   strings.TrimSpace(req.Username),
		Secret:     pam.Secret{Username: strings.TrimSpace(req.Username), Password: req.Password, PrivateKey: req.PrivateKey, Token: req.Token},
		RequireMFA: req.RequireMFA,
		LeaseTTL:   time.Duration(req.LeaseTTLSeconds) * time.Second,
		Actor:      actor(c),
	}
	if raw := strings.TrimSpace(req.AgentID); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
			return
		}
		in.AgentID = &parsed
	}
	target, err := h.engine.OnboardAsset(c.Request.Context(), ws, assetID, in)
	if err != nil {
		// Partial success: the target was created and the asset linked + audited,
		// but binding it to the agent failed. The onboard itself succeeded (the
		// target is usable direct-dial and the bind can be retried), so return
		// 201 with the target plus a warning header instead of a 500 that hides
		// the created target and leaves a retry to hit 409 Conflict.
		if errors.Is(err, discovery.ErrAgentBindFailed) && target != nil {
			// Record the bind failure server-side so ops dashboards can track
			// its frequency: this branch bypasses h.fail (the usual logging
			// path), and the X-Discovery-Warning response header alone is
			// invisible to log-based monitoring.
			logger.Warnf(c.Request.Context(), "discovery: onboard partial success (agent bind failed) asset=%s target=%s: %v", assetID, target.ID, err)
			c.Header("X-Discovery-Warning", "agent-bind-failed: target created with direct dial; re-bind from target settings")
			c.JSON(http.StatusCreated, target)
			return
		}
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, target)
}

func (h *discoveryHandlers) ignoreAsset(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	assetID, ok := pathUUID(c, "assetID")
	if !ok {
		return
	}
	if err := h.engine.IgnoreAsset(c.Request.Context(), ws, assetID, actor(c)); err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ignored"})
}

type dispositionAccountRequest struct {
	Status string `json:"status"`
}

func (h *discoveryHandlers) dispositionAccount(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	accountID, ok := pathUUID(c, "accountID")
	if !ok {
		return
	}
	var req dispositionAccountRequest
	if !bindDiscoveryJSON(c, &req) {
		return
	}
	status := strings.TrimSpace(req.Status)
	if err := h.engine.DispositionAccount(c.Request.Context(), ws, accountID, status, actor(c)); err != nil {
		h.fail(c, err)
		return
	}
	// Echo the normalized status the engine actually persisted, not the raw
	// request body, so a client syncing its cache from the response can't drift.
	c.JSON(http.StatusOK, gin.H{"status": status})
}

// --- policy ---

func (h *discoveryHandlers) getPolicy(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	view, err := h.engine.GetPolicy(c.Request.Context(), ws)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, view)
}

type savePolicyRequest struct {
	Enabled        bool                        `json:"enabled"`
	CreateTargets  bool                        `json:"create_targets"`
	Rules          []discovery.AutoOnboardRule `json:"rules"`
	DefaultAgentID string                      `json:"default_agent_id"`
	// Credential is optional. When present it sets/replaces the sealed
	// onboarding credential; an explicit empty password/key/token clears it.
	Credential *policyCredential `json:"credential"`
}

type policyCredential struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
	Token      string `json:"token"`
}

func (h *discoveryHandlers) savePolicy(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var req savePolicyRequest
	if !bindDiscoveryJSON(c, &req) {
		return
	}
	in := discovery.PolicyInput{
		Enabled:       req.Enabled,
		CreateTargets: req.CreateTargets,
		Rules:         req.Rules,
		Actor:         actor(c),
	}
	if raw := strings.TrimSpace(req.DefaultAgentID); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid default_agent_id"})
			return
		}
		in.DefaultAgentID = &parsed
	}
	if req.Credential != nil {
		in.Credential = &pam.Secret{
			Username:   strings.TrimSpace(req.Credential.Username),
			Password:   req.Credential.Password,
			PrivateKey: req.Credential.PrivateKey,
			Token:      req.Credential.Token,
		}
	}
	view, err := h.engine.SavePolicy(c.Request.Context(), ws, in)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, view)
}

// --- helpers ---

func (h *discoveryHandlers) fail(c *gin.Context, err error) {
	switch {
	case errors.Is(err, discovery.ErrValidation):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, discovery.ErrNotFound):
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, discovery.ErrConflict):
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, discovery.ErrUnsupported):
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
	default:
		logger.Errorf(c.Request.Context(), "discovery: unhandled error: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}

func bindDiscoveryJSON(c *gin.Context, dst any) bool {
	if err := c.ShouldBindJSON(dst); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return false
	}
	return true
}

func queryInt(c *gin.Context, name string) int {
	if raw := strings.TrimSpace(c.Query(name)); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			return n
		}
	}
	return 0
}
