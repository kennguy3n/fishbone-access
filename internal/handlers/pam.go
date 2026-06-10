package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/gateway"
	"github.com/kennguy3n/fishbone-access/internal/middleware"
	"github.com/kennguy3n/fishbone-access/internal/pkg/aiclient"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// pamHandlers serves the PAM REST surface: targets, JIT leases, sessions,
// session replay, and live session control. Every handler derives its workspace
// from the RequireTenant context and the actor from the validated iam-core
// token — never from client-supplied input.
type pamHandlers struct {
	vault    *pam.Vault
	broker   *pam.Broker
	sessions *pam.SessionManager
	leases   *pam.PAMLeaseService
	replays  gateway.ReplayReader
}

// newPAMHandlers wires the PAM services from shared Deps and the runtime
// environment. When the DB is nil the caller must not mount PAM routes at all
// (the scoped block in NewRouter gates on DB presence). The AI client, StepUp
// gate, and replay reader degrade gracefully when their environment variables
// are absent, so the API boots in every deployment topology and fails closed on
// the operations that require a missing component.
func newPAMHandlers(deps Deps) *pamHandlers {
	db := deps.DB

	enc, err := access.CredentialEncryptorFromKey(os.Getenv("ACCESS_CREDENTIAL_DEK"))
	if err != nil {
		logger.Errorf(context.Background(), "pam: credential encryptor init: %v (vault operations will fail closed)", err)
		enc = access.NewDisabledEncryptor()
	}

	var stepUp *pam.StepUpGate
	if deps.Validator != nil {
		stepUp = pam.NewStepUpGate(deps.Validator, 5*time.Minute)
	}

	vault := pam.NewVault(db, enc, stepUp)
	broker := pam.NewBroker(db, vault, stepUp)
	evaluator := pam.NewCommandPolicyEvaluator(db, 5*time.Second)
	sessions := pam.NewSessionManager(db, evaluator, nil)

	ai, aiErr := aiclient.NewAIClientFromEnv()
	if aiErr != nil {
		// A half-configured mTLS setup is the only error path; degrade to an
		// unconfigured client so lease risk scoring uses the deterministic
		// fallback (fail-OPEN advisory) rather than failing the whole API boot.
		logger.Errorf(context.Background(), "pam: AI client init: %v (risk scoring degrades to fallback)", aiErr)
		ai = aiclient.NewAIClient("", nil, "")
	}
	leases := pam.NewPAMLeaseService(db, ai)
	leases.SetSessionTerminator(sessions)

	broker.SetLeaseValidator(leases)

	replays := buildReplayReader()

	return &pamHandlers{
		vault:    vault,
		broker:   broker,
		sessions: sessions,
		leases:   leases,
		replays:  replays,
	}
}

// buildReplayReader selects a replay backend from the environment, matching the
// gateway's buildReplayStore logic so the API retrieves from the same path the
// gateway wrote to. Returns nil when no backend is configured (replay
// retrieval returns 503).
func buildReplayReader() gateway.ReplayReader {
	if bucket := os.Getenv("PAM_REPLAY_S3_BUCKET"); bucket != "" {
		region := os.Getenv("PAM_REPLAY_S3_REGION")
		var opts []gateway.S3Option
		if ep := os.Getenv("PAM_REPLAY_S3_ENDPOINT"); ep != "" {
			opts = append(opts, gateway.WithEndpointURL(ep), gateway.WithForcePathStyle(true))
		}
		store, err := gateway.NewS3ReplayStore(context.Background(), bucket, region, opts...)
		if err != nil {
			logger.Errorf(context.Background(), "pam: S3 replay store init: %v", err)
			return nil
		}
		return store
	}
	dir := os.Getenv("PAM_REPLAY_DIR")
	if dir == "" {
		dir = "./pam-replays"
	}
	store, err := gateway.NewFilesystemReplayStore(dir)
	if err != nil {
		logger.Warnf(context.Background(), "pam: filesystem replay store init: %v (replay retrieval unavailable)", err)
		return nil
	}
	return store
}

// register mounts PAM routes on the tenant-scoped group. The group must already
// carry Auth + ResolveTenant + RequireTenant.
func (h *pamHandlers) register(g *gin.RouterGroup) {
	pamG := g.Group("/pam")

	// Targets.
	pamG.GET("/targets", h.listTargets)
	pamG.GET("/targets/:id", h.getTarget)
	pamG.POST("/targets", h.createTarget)

	// Leases. Approve and revoke open and close a privileged access window, so
	// they are step-up-MFA gated (mirroring policies/:id/promote); request,
	// list, get, and the operator-triggered expire sweep are not. Finer-grained
	// RBAC (a distinct approver permission / separation-of-duties) is layered on
	// at integration alongside the other cross-workspace RBAC wiring.
	pamG.POST("/leases", h.requestLease)
	pamG.GET("/leases", h.listLeases)
	pamG.GET("/leases/:id", h.getLease)
	pamG.POST("/leases/:id/approve", middleware.RequireMFA(), h.approveLease)
	pamG.POST("/leases/:id/revoke", middleware.RequireMFA(), h.revokeLease)
	pamG.POST("/leases/expire", h.expireLeases)

	// Connect tokens (mint).
	pamG.POST("/connect-tokens", h.mintConnectToken)

	// Sessions.
	pamG.GET("/sessions", h.listSessions)
	pamG.GET("/sessions/:id", h.getSession)
	pamG.GET("/sessions/:id/replay", h.getReplay)

	// Live session control: RequirePermission(pam.takeover) + step-up MFA.
	ctrl := pamG.Group("/sessions/:id", middleware.RequirePermission(authz.PermPAMTakeover), middleware.RequireMFA())
	ctrl.POST("/pause", h.pauseSession)
	ctrl.POST("/resume", h.resumeSession)
	ctrl.POST("/terminate", h.terminateSession)
}

// --- targets ---

func (h *pamHandlers) listTargets(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	rows, err := h.vault.ListTargets(c.Request.Context(), ws, 200)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"targets": rows})
}

func (h *pamHandlers) getTarget(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	t, err := h.vault.GetTarget(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, t)
}

type createTargetBody struct {
	Name       string `json:"name" binding:"required"`
	Protocol   string `json:"protocol" binding:"required"`
	Address    string `json:"address" binding:"required"`
	Username   string `json:"username"`
	RequireMFA bool   `json:"require_mfa"`
	LeaseTTL   int    `json:"lease_ttl_seconds"`
	Secret     struct {
		Username   string `json:"username,omitempty"`
		Password   string `json:"password,omitempty"`
		PrivateKey string `json:"private_key,omitempty"`
		Token      string `json:"token,omitempty"`
	} `json:"secret" binding:"required"`
}

func (h *pamHandlers) createTarget(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var body createTargetBody
	if !bind(c, &body) {
		return
	}
	t, err := h.vault.CreateTarget(c.Request.Context(), pam.CreateTargetInput{
		WorkspaceID: ws,
		Name:        body.Name,
		Protocol:    body.Protocol,
		Address:     body.Address,
		Username:    body.Username,
		RequireMFA:  body.RequireMFA,
		LeaseTTL:    time.Duration(body.LeaseTTL) * time.Second,
		Secret: pam.Secret{
			Username:   body.Secret.Username,
			Password:   body.Secret.Password,
			PrivateKey: body.Secret.PrivateKey,
			Token:      body.Secret.Token,
		},
		Actor: actor(c),
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, t)
}

// --- leases ---

type requestLeaseBody struct {
	TargetID  string `json:"target_id" binding:"required"`
	Subject   string `json:"subject"`
	TTL       int    `json:"ttl_seconds"`
	Reason    string `json:"reason"`
	RequestID string `json:"request_id"`
}

func (h *pamHandlers) requestLease(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var body requestLeaseBody
	if !bind(c, &body) {
		return
	}
	targetID, err := uuid.Parse(body.TargetID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid target_id"})
		return
	}
	sub := body.Subject
	if sub == "" {
		sub = actor(c)
	}
	in := pam.RequestLeaseInput{
		WorkspaceID: ws,
		TargetID:    targetID,
		Subject:     sub,
		RequestedBy: actor(c),
		TTL:         time.Duration(body.TTL) * time.Second,
		Reason:      body.Reason,
	}
	if body.RequestID != "" {
		rid, err := uuid.Parse(body.RequestID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid request_id"})
			return
		}
		in.RequestID = &rid
	}
	lease, err := h.leases.RequestLease(c.Request.Context(), in)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, lease)
}

func (h *pamHandlers) listLeases(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	f := pam.ListLeasesFilters{}
	if tid := c.Query("target_id"); tid != "" {
		id, err := uuid.Parse(tid)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid target_id"})
			return
		}
		f.TargetID = id
	}
	f.Subject = c.Query("subject")
	if c.Query("active_only") == "true" {
		f.ActiveOnly = true
	}
	leases, err := h.leases.ListLeases(c.Request.Context(), ws, f)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"leases": leases})
}

func (h *pamHandlers) getLease(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	lease, err := h.leases.GetLease(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, lease)
}

type approveLeaseBody struct {
	DurationOverride int `json:"duration_override_seconds"`
}

func (h *pamHandlers) approveLease(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	var body approveLeaseBody
	if !bindOptional(c, &body) {
		return
	}
	lease, err := h.leases.ApproveLease(c.Request.Context(), ws, id, actor(c), time.Duration(body.DurationOverride)*time.Second)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, lease)
}

type revokeLeaseBody struct {
	Reason string `json:"reason"`
}

func (h *pamHandlers) revokeLease(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	var body revokeLeaseBody
	if !bindOptional(c, &body) {
		return
	}
	lease, err := h.leases.RevokeLease(c.Request.Context(), ws, id, actor(c), body.Reason)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, lease)
}

func (h *pamHandlers) expireLeases(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	n, err := h.leases.ExpireLeases(c.Request.Context(), ws)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"expired": n})
}

// --- connect tokens ---

type mintConnectTokenBody struct {
	TargetID    string `json:"target_id" binding:"required"`
	StepUpToken string `json:"step_up_token"`
	LeaseID     string `json:"lease_id"`
}

func (h *pamHandlers) mintConnectToken(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var body mintConnectTokenBody
	if !bind(c, &body) {
		return
	}
	targetID, err := uuid.Parse(body.TargetID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid target_id"})
		return
	}
	in := pam.MintInput{
		WorkspaceID: ws,
		TargetID:    targetID,
		Subject:     actor(c),
		StepUpToken: body.StepUpToken,
		Actor:       actor(c),
	}
	if body.LeaseID != "" {
		lid, err := uuid.Parse(body.LeaseID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid lease_id"})
			return
		}
		in.LeaseID = &lid
	}
	raw, tok, err := h.broker.MintConnectToken(c.Request.Context(), in)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"raw_token": raw,
		"token":     tok,
	})
}

// --- sessions ---

func (h *pamHandlers) listSessions(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	f := pam.ListSessionsFilters{}
	if tid := c.Query("target_id"); tid != "" {
		id, err := uuid.Parse(tid)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid target_id"})
			return
		}
		f.TargetID = id
	}
	f.Subject = c.Query("subject")
	if c.Query("active_only") == "true" {
		f.ActiveOnly = true
	}
	sessions, err := h.sessions.ListSessions(c.Request.Context(), ws, f)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

func (h *pamHandlers) getSession(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	session, err := h.sessions.GetSession(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, session)
}

func (h *pamHandlers) getReplay(c *gin.Context) {
	if h.replays == nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "replay retrieval not configured"})
		return
	}
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	session, err := h.sessions.GetSession(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	rc, err := h.replays.GetReplay(c.Request.Context(), session.ID.String())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "replay not found"})
			return
		}
		h.fail(c, err)
		return
	}
	defer rc.Close()

	frames, err := gateway.ParseReplay(rc)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"session_id": session.ID,
		"frames":     frames,
		"truncated":  errors.Is(err, io.ErrUnexpectedEOF),
	})
}

// --- live session control ---

func (h *pamHandlers) pauseSession(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	if err := h.sessions.PauseSession(c.Request.Context(), ws, id, actor(c)); err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "paused"})
}

func (h *pamHandlers) resumeSession(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	if err := h.sessions.ResumeSession(c.Request.Context(), ws, id, actor(c)); err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "resumed"})
}

func (h *pamHandlers) terminateSession(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	if err := h.sessions.TerminateSession(c.Request.Context(), ws, id, actor(c)); err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "terminated"})
}

// --- error mapping ---

func (h *pamHandlers) fail(c *gin.Context, err error) {
	switch {
	case errors.Is(err, pam.ErrValidation):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, pam.ErrTargetNotFound),
		errors.Is(err, pam.ErrLeaseNotFound),
		errors.Is(err, pam.ErrSessionNotFound):
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, pam.ErrLeaseTerminal),
		errors.Is(err, pam.ErrSessionNotActive):
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, pam.ErrLeaseNotApproved):
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, pam.ErrConnectToken):
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired connect token"})
	case errors.Is(err, pam.ErrStepUpRequired):
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": err.Error()})
	case errors.Is(err, pam.ErrStepUpInvalid):
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("step-up MFA: %v", err)})
	default:
		logger.Errorf(c.Request.Context(), "pam: unhandled error: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}
