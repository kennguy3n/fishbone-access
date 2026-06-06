package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/middleware"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// lifecycleHandlers holds the access-lifecycle services and serves their REST
// surface. Every handler derives the workspace from the request context
// (set by RequireTenant after the iam-core tenant claim is verified) and the
// actor from the validated token subject — never from client-supplied input —
// so a caller cannot operate on another tenant's data or spoof an actor.
type lifecycleHandlers struct {
	requests *lifecycle.AccessRequestService
	workflow *lifecycle.WorkflowService
	policies *lifecycle.PolicyService
	prov     *lifecycle.AccessProvisioningService
	reviews  *lifecycle.ReviewService
	jml      *lifecycle.JMLService
	orphans  *lifecycle.OrphanReconciler
	expiry   *lifecycle.ExpiryEnforcer
	sso      *lifecycle.SSOEnforcementChecker
}

// newLifecycleHandlers wires the lifecycle services off the shared DB pool, the
// connector resolver (DB-backed, opening sealed secrets with the encryptor),
// and the iam-core identity disabler used by the leaver kill switch.
func newLifecycleHandlers(deps Deps) *lifecycleHandlers {
	db := deps.DB
	resolver := lifecycle.NewDBConnectorResolver(db, deps.Encryptor)
	requests := lifecycle.NewAccessRequestService(db)
	workflow := lifecycle.NewWorkflowService(requests)
	prov := lifecycle.NewAccessProvisioningService(db, requests, resolver)
	return &lifecycleHandlers{
		requests: requests,
		workflow: workflow,
		policies: lifecycle.NewPolicyService(db),
		prov:     prov,
		reviews:  lifecycle.NewReviewService(db, prov),
		jml:      lifecycle.NewJMLService(db, requests, workflow, prov, resolver, deps.Disabler),
		orphans:  lifecycle.NewOrphanReconciler(db, resolver),
		expiry:   lifecycle.NewExpiryEnforcer(db, prov),
		sso:      lifecycle.NewSSOEnforcementChecker(db, resolver),
	}
}

// register mounts the lifecycle routes on the tenant-scoped group. The group
// must already carry Auth + ResolveTenant + RequireTenant.
func (h *lifecycleHandlers) register(g *gin.RouterGroup) {
	// Access requests.
	g.POST("/access-requests", h.createRequest)
	g.GET("/access-requests", h.listRequests)
	g.GET("/access-requests/:id", h.getRequest)
	g.GET("/access-requests/:id/history", h.requestHistory)
	g.POST("/access-requests/:id/approve", h.approveRequest)
	g.POST("/access-requests/:id/deny", h.denyRequest)
	g.POST("/access-requests/:id/cancel", h.cancelRequest)
	g.POST("/access-requests/:id/provision", h.provisionRequest)

	// Grants.
	g.POST("/grants/:id/revoke", h.revokeGrant)
	g.POST("/grants/expiry-enforce", h.enforceExpiry)

	// Policies.
	g.POST("/policies", h.createPolicy)
	g.GET("/policies", h.listPolicies)
	g.GET("/policies/:id", h.getPolicy)
	g.PUT("/policies/:id", h.updatePolicy)
	g.POST("/policies/:id/simulate", h.simulatePolicy)
	// Promotion mutates the data plane: require step-up MFA.
	g.POST("/policies/:id/promote", middleware.RequireMFA(), h.promotePolicy)
	g.POST("/policies/:id/archive", h.archivePolicy)

	// Access review campaigns.
	g.POST("/access-reviews", h.startReview)
	g.GET("/access-reviews/:id", h.reviewReport)
	g.GET("/access-reviews/:id/items", h.reviewItems)
	g.POST("/access-reviews/:id/items/:itemID/decision", h.reviewDecision)
	g.POST("/access-reviews/:id/complete", h.completeReview)

	// JML / SCIM inbound.
	g.POST("/scim/events", h.scimEvent)

	// Orphan reconciliation.
	g.POST("/connectors/:connectorID/orphan-scan", h.orphanScan)
	g.GET("/orphan-accounts", h.listOrphans)
	g.POST("/orphan-accounts/:id/disposition", h.orphanDisposition)

	// SSO enforcement.
	g.GET("/connectors/:connectorID/sso-status", h.ssoStatus)
}

// --- access requests ---

type createRequestBody struct {
	TargetUserID  string     `json:"target_user_id" binding:"required"`
	ConnectorID   *uuid.UUID `json:"connector_id"`
	ResourceRef   string     `json:"resource_ref" binding:"required"`
	Role          string     `json:"role"`
	Justification string     `json:"justification"`
	RiskLevel     string     `json:"risk_level"`
	RiskFactors   []string   `json:"risk_factors"`
}

func (h *lifecycleHandlers) createRequest(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var body createRequestBody
	if !bind(c, &body) {
		return
	}
	req, err := h.requests.CreateRequest(c.Request.Context(), lifecycle.CreateAccessRequestInput{
		WorkspaceID:   ws,
		RequesterID:   actor(c),
		TargetUserID:  body.TargetUserID,
		ConnectorID:   body.ConnectorID,
		ResourceRef:   body.ResourceRef,
		Role:          body.Role,
		Justification: body.Justification,
		RiskLevel:     body.RiskLevel,
		RiskFactors:   body.RiskFactors,
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	// Risk-based routing: low-risk auto-approves, otherwise the request is
	// parked for the appropriate human gate. A workflow failure must not lose
	// the already-created request, so surface the decision best-effort.
	decision, werr := h.workflow.ExecuteWorkflow(c.Request.Context(), ws, req, actor(c))
	if werr != nil {
		logger.Warnf(c.Request.Context(), "lifecycle: workflow routing for request %s: %v", req.ID, werr)
	}
	// Reload to reflect any state change made by the workflow.
	if updated, gerr := h.requests.GetRequest(c.Request.Context(), ws, req.ID); gerr == nil {
		req = updated
	}
	c.JSON(http.StatusCreated, gin.H{"request": req, "workflow": decision})
}

func (h *lifecycleHandlers) listRequests(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	rows, err := h.requests.ListRequests(c.Request.Context(), ws)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"requests": rows})
}

func (h *lifecycleHandlers) getRequest(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	req, err := h.requests.GetRequest(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"request": req})
}

func (h *lifecycleHandlers) requestHistory(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	hist, err := h.requests.History(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"history": hist})
}

type decisionBody struct {
	Reason string `json:"reason"`
}

// transitionFn is the shared shape of Approve/Deny/CancelRequest.
type transitionFn func(ctx context.Context, workspaceID, requestID uuid.UUID, actor, reason string) error

func (h *lifecycleHandlers) approveRequest(c *gin.Context) {
	h.requestTransition(c, h.requests.ApproveRequest)
}

func (h *lifecycleHandlers) denyRequest(c *gin.Context) {
	h.requestTransition(c, h.requests.DenyRequest)
}

func (h *lifecycleHandlers) cancelRequest(c *gin.Context) {
	h.requestTransition(c, h.requests.CancelRequest)
}

func (h *lifecycleHandlers) requestTransition(c *gin.Context, fn transitionFn) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	var body decisionBody
	if !bindOptional(c, &body) {
		return
	}
	if err := fn(c.Request.Context(), ws, id, actor(c), body.Reason); err != nil {
		h.fail(c, err)
		return
	}
	req, err := h.requests.GetRequest(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"request": req})
}

func (h *lifecycleHandlers) provisionRequest(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	grant, err := h.prov.Provision(c.Request.Context(), ws, id, actor(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"grant": grant})
}

// --- grants ---

func (h *lifecycleHandlers) revokeGrant(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	var body decisionBody
	if !bindOptional(c, &body) {
		return
	}
	if err := h.prov.RevokeGrant(c.Request.Context(), ws, id, actor(c), body.Reason); err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

func (h *lifecycleHandlers) enforceExpiry(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	res, err := h.expiry.EnforceExpired(c.Request.Context(), ws)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": res})
}

// --- policies ---

type policyBody struct {
	Name       string          `json:"name" binding:"required"`
	Definition json.RawMessage `json:"definition" binding:"required"`
}

func (h *lifecycleHandlers) createPolicy(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var body policyBody
	if !bind(c, &body) {
		return
	}
	pol, err := h.policies.CreatePolicy(c.Request.Context(), lifecycle.CreatePolicyInput{
		WorkspaceID: ws,
		Name:        body.Name,
		Definition:  body.Definition,
		Actor:       actor(c),
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"policy": pol})
}

func (h *lifecycleHandlers) listPolicies(c *gin.Context) {
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

func (h *lifecycleHandlers) getPolicy(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	pol, err := h.policies.GetPolicy(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"policy": pol})
}

func (h *lifecycleHandlers) updatePolicy(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	var body policyBody
	if !bind(c, &body) {
		return
	}
	pol, err := h.policies.UpdateDraft(c.Request.Context(), ws, id, body.Name, body.Definition, actor(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"policy": pol})
}

func (h *lifecycleHandlers) simulatePolicy(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	sim, err := h.policies.Simulate(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"simulation": sim})
}

func (h *lifecycleHandlers) promotePolicy(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	pol, err := h.policies.Promote(c.Request.Context(), ws, id, actor(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"policy": pol})
}

func (h *lifecycleHandlers) archivePolicy(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	pol, err := h.policies.Archive(c.Request.Context(), ws, id, actor(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"policy": pol})
}

// --- reviews ---

type startReviewBody struct {
	Name string `json:"name" binding:"required"`
}

func (h *lifecycleHandlers) startReview(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var body startReviewBody
	if !bind(c, &body) {
		return
	}
	rev, n, err := h.reviews.StartCampaign(c.Request.Context(), ws, body.Name, actor(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"review": rev, "item_count": n})
}

func (h *lifecycleHandlers) reviewReport(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	report, err := h.reviews.Report(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"report": report})
}

func (h *lifecycleHandlers) reviewItems(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	items, err := h.reviews.ListItems(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

type reviewDecisionBody struct {
	Decision string `json:"decision" binding:"required"`
	Reason   string `json:"reason"`
}

func (h *lifecycleHandlers) reviewDecision(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	reviewID, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	itemID, ok := pathUUID(c, "itemID")
	if !ok {
		return
	}
	var body reviewDecisionBody
	if !bind(c, &body) {
		return
	}
	if err := h.reviews.SubmitDecision(c.Request.Context(), ws, reviewID, itemID, body.Decision, actor(c), body.Reason); err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "recorded"})
}

func (h *lifecycleHandlers) completeReview(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	report, err := h.reviews.CompleteCampaign(c.Request.Context(), ws, id, actor(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"report": report})
}

// --- JML / SCIM ---

type scimEventBody struct {
	Method         string     `json:"method" binding:"required"`
	UserExternalID string     `json:"user_external_id" binding:"required"`
	Active         *bool      `json:"active"`
	Email          string     `json:"email"`
	DisplayName    string     `json:"display_name"`
	GroupsChanged  bool       `json:"groups_changed"`
	ResourceRef    string     `json:"resource_ref"`
	Role           string     `json:"role"`
	ConnectorID    *uuid.UUID `json:"connector_id"`
}

func (h *lifecycleHandlers) scimEvent(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var body scimEventBody
	if !bind(c, &body) {
		return
	}
	lane, err := h.jml.HandleEvent(c.Request.Context(), ws, lifecycle.SCIMEvent{
		Method:         body.Method,
		UserExternalID: body.UserExternalID,
		Active:         body.Active,
		Email:          body.Email,
		DisplayName:    body.DisplayName,
		GroupsChanged:  body.GroupsChanged,
		ResourceRef:    body.ResourceRef,
		Role:           body.Role,
		ConnectorID:    body.ConnectorID,
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"lane": lane})
}

// --- orphans ---

type orphanScanBody struct {
	DryRun bool `json:"dry_run"`
}

func (h *lifecycleHandlers) orphanScan(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	connID, ok := pathUUID(c, "connectorID")
	if !ok {
		return
	}
	var body orphanScanBody
	if !bindOptional(c, &body) {
		return
	}
	res, err := h.orphans.Scan(c.Request.Context(), ws, connID, body.DryRun)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"scan": res})
}

func (h *lifecycleHandlers) listOrphans(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	rows, err := h.orphans.ListOrphans(c.Request.Context(), ws)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"orphans": rows})
}

type dispositionBody struct {
	Disposition string `json:"disposition" binding:"required"`
}

func (h *lifecycleHandlers) orphanDisposition(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	var body dispositionBody
	if !bind(c, &body) {
		return
	}
	if err := h.orphans.SetDisposition(c.Request.Context(), ws, id, body.Disposition, actor(c)); err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// --- SSO ---

func (h *lifecycleHandlers) ssoStatus(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	connID, ok := pathUUID(c, "connectorID")
	if !ok {
		return
	}
	status, err := h.sso.Check(c.Request.Context(), ws, connID)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"sso": status})
}

// --- shared helpers ---

// workspace returns the tenant-scoped workspace id set by RequireTenant, or
// aborts 403 (fail-closed) when absent. A handler that loses this guard cannot
// learn a workspace id any other way, so no unscoped query is possible.
func workspace(c *gin.Context) (uuid.UUID, bool) {
	ws, ok := middleware.WorkspaceFromContext(c)
	if !ok {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "no workspace resolved"})
		return uuid.Nil, false
	}
	return ws, true
}

// actor is the validated iam-core subject performing the action.
func actor(c *gin.Context) string {
	if claims := middleware.ClaimsFromContext(c); claims != nil {
		return claims.Subject
	}
	return ""
}

func pathUUID(c *gin.Context, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param(name))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid " + name})
		return uuid.Nil, false
	}
	return id, true
}

// bind decodes a required JSON body; on failure it aborts 400 and returns false.
func bind(c *gin.Context, dst any) bool {
	if err := c.ShouldBindJSON(dst); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return false
	}
	return true
}

// bindOptional decodes a body that may be empty (e.g. an action with only an
// optional reason). It attempts to bind and treats an empty body (io.EOF) as
// success, so it works regardless of how the client framed the request: an
// absent body, an explicit Content-Length: 0, OR a chunked Transfer-Encoding
// body (where ContentLength is -1 but real JSON may still be present — a
// Content-Length check would silently drop it). A non-empty but malformed body
// is the only thing that 400s.
func bindOptional(c *gin.Context, dst any) bool {
	if c.Request == nil || c.Request.Body == nil {
		return true
	}
	if err := c.ShouldBindJSON(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return true // empty body — nothing to bind, which is allowed here
		}
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return false
	}
	return true
}

// fail maps service sentinel errors to HTTP status codes. Unknown errors are
// 500 and logged (never echoed) so an internal fault is not leaked to clients.
func (h *lifecycleHandlers) fail(c *gin.Context, err error) {
	switch {
	case errors.Is(err, lifecycle.ErrValidation):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, lifecycle.ErrRequestNotFound),
		errors.Is(err, lifecycle.ErrPolicyNotFound),
		errors.Is(err, lifecycle.ErrReviewNotFound),
		errors.Is(err, lifecycle.ErrGrantNotFound),
		errors.Is(err, lifecycle.ErrOrphanNotFound):
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, lifecycle.ErrInvalidStateTransition),
		errors.Is(err, lifecycle.ErrReviewClosed),
		errors.Is(err, lifecycle.ErrPolicyNotPromotable),
		errors.Is(err, lifecycle.ErrPolicyNotEditable):
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, lifecycle.ErrConnectorNotConfigured):
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
	default:
		logger.Errorf(c.Request.Context(), "lifecycle: unhandled error: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}
