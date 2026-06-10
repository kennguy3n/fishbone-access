package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/middleware"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/aiclient"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
	"github.com/kennguy3n/fishbone-access/internal/services/mfa"
	"github.com/kennguy3n/fishbone-access/internal/services/packs"
)

// lifecycleHandlers holds the access-lifecycle services and serves their REST
// surface. Every handler derives the workspace from the request context
// (set by RequireTenant after the iam-core tenant claim is verified) and the
// actor from the validated token subject — never from client-supplied input —
// so a caller cannot operate on another tenant's data or spoof an actor.
type lifecycleHandlers struct {
	requests    *lifecycle.AccessRequestService
	workflow    *lifecycle.WorkflowService
	riskReview  *lifecycle.RiskReviewService
	policies    *lifecycle.PolicyService
	prov        *lifecycle.AccessProvisioningService
	reviews     *lifecycle.ReviewService
	jml         *lifecycle.JMLService
	orphans     *lifecycle.OrphanReconciler
	expiry      *lifecycle.ExpiryEnforcer
	sso         *lifecycle.SSOEnforcementChecker
	packs       *packs.ApplyService
	sod         *lifecycle.SodService
	anomalies   *lifecycle.AnomalyDetector
	contractors *lifecycle.ContractorService
}

// newLifecycleHandlers wires the lifecycle services off the shared DB pool, the
// connector resolver (DB-backed, opening sealed secrets with the encryptor),
// and the iam-core identity disabler used by the leaver kill switch.
func newLifecycleHandlers(deps Deps) *lifecycleHandlers {
	db := deps.DB
	resolver := lifecycle.NewDBConnectorResolver(db, deps.ConnectorEncryptor)
	requests := lifecycle.NewAccessRequestService(db)
	workflow := lifecycle.NewWorkflowService(requests)
	prov := lifecycle.NewAccessProvisioningService(db, requests, resolver)
	policies := lifecycle.NewPolicyService(db)
	// The risk review needs a non-nil client; substitute an unconfigured one
	// (→ ErrAIUnconfigured → fail-open deterministic fallback) when no agent is
	// wired, so a degraded boot scores requests "needs human review" rather than
	// panicking on a nil client.
	ai := deps.AI
	if ai == nil {
		ai = aiclient.NewAIClient("", nil, "")
	}
	return &lifecycleHandlers{
		requests:    requests,
		workflow:    workflow,
		riskReview:  lifecycle.NewRiskReviewService(db, requests, ai),
		policies:    policies,
		prov:        prov,
		reviews:     lifecycle.NewReviewService(db, prov),
		jml:         lifecycle.NewJMLService(db, requests, workflow, prov, resolver, deps.Disabler),
		orphans:     lifecycle.NewOrphanReconciler(db, resolver),
		expiry:      lifecycle.NewExpiryEnforcer(db, prov),
		sso:         lifecycle.NewSSOEnforcementChecker(db, resolver),
		packs:       packs.NewApplyService(policies),
		sod:         lifecycle.NewSodService(db),
		anomalies:   lifecycle.NewAnomalyDetector(db),
		contractors: lifecycle.NewContractorService(db, prov),
	}
}

// register mounts the lifecycle routes on the tenant-scoped group. The group
// must already carry Auth + ResolveTenant + RequireTenant (and, in production,
// AuthzMiddleware so the RequirePermission gates below enforce; when RBAC is
// not installed those gates no-op).
//
// stepUp verifies a fresh step-up MFA assertion on the highest-risk action
// (policy promotion). When nil, the route falls back to the session-level
// RequireMFA claim gate only.
func (h *lifecycleHandlers) register(g *gin.RouterGroup, stepUp mfa.MFAVerifier) {
	// Access requests. Reads require request.read; mutations require the
	// matching verb permission so a viewer/auditor cannot approve or provision.
	g.POST("/access-requests", middleware.RequirePermission(authz.PermRequestCreate), h.createRequest)
	g.GET("/access-requests", middleware.RequirePermission(authz.PermRequestRead), h.listRequests)
	g.GET("/access-requests/:id", middleware.RequirePermission(authz.PermRequestRead), h.getRequest)
	g.GET("/access-requests/:id/history", middleware.RequirePermission(authz.PermRequestRead), h.requestHistory)
	g.POST("/access-requests/:id/approve", middleware.RequirePermission(authz.PermRequestApprove), h.approveRequest)
	g.POST("/access-requests/:id/deny", middleware.RequirePermission(authz.PermRequestDeny), h.denyRequest)
	g.POST("/access-requests/:id/cancel", middleware.RequirePermission(authz.PermRequestCancel), h.cancelRequest)
	g.POST("/access-requests/:id/provision", middleware.RequirePermission(authz.PermRequestProvision), h.provisionRequest)

	// Grants.
	g.POST("/grants/:id/revoke", middleware.RequirePermission(authz.PermGrantRevoke), h.revokeGrant)
	g.POST("/grants/expiry-enforce", middleware.RequirePermission(authz.PermGrantAdmin), h.enforceExpiry)

	// Policies.
	g.POST("/policies", middleware.RequirePermission(authz.PermPolicyWrite), h.createPolicy)
	g.GET("/policies", middleware.RequirePermission(authz.PermPolicyRead), h.listPolicies)
	g.GET("/policies/:id", middleware.RequirePermission(authz.PermPolicyRead), h.getPolicy)
	g.PUT("/policies/:id", middleware.RequirePermission(authz.PermPolicyWrite), h.updatePolicy)
	g.POST("/policies/:id/simulate", middleware.RequirePermission(authz.PermPolicySimulate), h.simulatePolicy)
	// Promotion mutates the data plane: it is gated by the policy.promote
	// permission, the session-level MFA claim, AND a fresh step-up assertion
	// (composite verifier) when one is wired — the strongest gate in the API.
	g.POST("/policies/:id/promote",
		middleware.RequirePermission(authz.PermPolicyPromote),
		middleware.RequireMFA(),
		stepUpGate(stepUp, string(authz.PermPolicyPromote)),
		h.promotePolicy)
	g.POST("/policies/:id/archive", middleware.RequirePermission(authz.PermPolicyArchive), h.archivePolicy)
	// Ad-hoc what-if for a bulk role change: the same simulation a draft runs
	// (blast radius, conflicts, SoD violations, catastrophic verdict) against an
	// un-persisted definition, so an operator previews a sweeping change before
	// touching the data plane.
	g.POST("/policies/simulate-definition", middleware.RequirePermission(authz.PermPolicySimulate), h.simulateDefinition)

	// Separation-of-Duties toxic-combination ruleset.
	g.POST("/sod-rules", middleware.RequirePermission(authz.PermPolicyWrite), h.createSodRule)
	g.GET("/sod-rules", middleware.RequirePermission(authz.PermPolicyRead), h.listSodRules)
	g.DELETE("/sod-rules/:id", middleware.RequirePermission(authz.PermPolicyWrite), h.deleteSodRule)
	// Standing SoD anomalies surfaced as dispositioned evidence (CC7.3).
	g.GET("/sod-anomalies", middleware.RequirePermission(authz.PermOrphanRead), h.listAnomalies)

	// Time-boxed contractor / external access lifecycle.
	g.POST("/contractor-grants", middleware.RequirePermission(authz.PermRequestCreate), h.createContractorGrant)
	g.GET("/contractor-grants", middleware.RequirePermission(authz.PermRequestRead), h.listContractorGrants)
	g.GET("/contractor-grants/:id", middleware.RequirePermission(authz.PermRequestRead), h.getContractorGrant)
	g.POST("/contractor-grants/:id/approve", middleware.RequirePermission(authz.PermRequestApprove), h.approveContractorGrant)
	g.POST("/contractor-grants/:id/reject", middleware.RequirePermission(authz.PermRequestDeny), h.rejectContractorGrant)
	g.POST("/contractor-grants/:id/revoke", middleware.RequirePermission(authz.PermGrantRevoke), h.revokeContractorGrant)
	g.POST("/contractor-grants/:id/extend", middleware.RequirePermission(authz.PermRequestApprove), h.extendContractorGrant)

	// Access review campaigns.
	g.POST("/access-reviews", middleware.RequirePermission(authz.PermReviewStart), h.startReview)
	g.GET("/access-reviews/:id", middleware.RequirePermission(authz.PermReviewRead), h.reviewReport)
	g.GET("/access-reviews/:id/items", middleware.RequirePermission(authz.PermReviewRead), h.reviewItems)
	g.POST("/access-reviews/:id/items/:itemID/decision", middleware.RequirePermission(authz.PermReviewRespond), h.reviewDecision)
	g.POST("/access-reviews/:id/complete", middleware.RequirePermission(authz.PermReviewComplete), h.completeReview)

	// JML / SCIM inbound.
	g.POST("/scim/events", middleware.RequirePermission(authz.PermJMLEventWrite), h.scimEvent)

	// Orphan reconciliation.
	g.POST("/connectors/:connectorID/orphan-scan", middleware.RequirePermission(authz.PermOrphanScan), h.orphanScan)
	g.GET("/orphan-accounts", middleware.RequirePermission(authz.PermOrphanRead), h.listOrphans)
	g.POST("/orphan-accounts/:id/disposition", middleware.RequirePermission(authz.PermOrphanDisposition), h.orphanDisposition)

	// SSO enforcement.
	g.GET("/connectors/:connectorID/sso-status", middleware.RequirePermission(authz.PermConnectorSSORead), h.ssoStatus)

	// Policy packs (curated templates that materialize as drafts).
	h.registerPacks(g)
}

// stepUpGate returns the RequireStepUpMFA middleware for scope when a verifier
// is wired, or a pass-through no-op when it is not, so the promote route mounts
// the same shape regardless of whether the composite verifier is configured.
func stepUpGate(verifier mfa.MFAVerifier, scope string) gin.HandlerFunc {
	if verifier == nil {
		return func(c *gin.Context) { c.Next() }
	}
	return middleware.RequireStepUpMFA(verifier, scope)
}

// --- access requests ---

// createRequestBody is the elevation-request submission. Risk is NEVER accepted
// from the client: the server-side AI risk review derives the verdict. The
// optional resource_tags / duration_hours are advisory model-input signals that
// can only raise the assessed risk (a "sensitive" tag forces security review),
// so they cannot be used to dodge review.
type createRequestBody struct {
	// TargetUserID is optional: an omitted target means a self-service
	// elevation and the service defaults it to the authenticated requester.
	TargetUserID  string     `json:"target_user_id"`
	ConnectorID   *uuid.UUID `json:"connector_id"`
	ResourceRef   string     `json:"resource_ref" binding:"required"`
	Role          string     `json:"role" binding:"required"`
	Justification string     `json:"justification"`
	ResourceTags  []string   `json:"resource_tags"`
	DurationHours int        `json:"duration_hours"`
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
		// RiskLevel/RiskFactors intentionally omitted: the AI review below is the
		// sole source of the request's risk, so a client cannot self-assert a low
		// score to fast-track a privileged grant.
	})
	if err != nil {
		h.fail(c, err)
		return
	}

	// First-class, audited AI risk gate: score the request server-side, persist
	// the verdict (+ inputs + rationale) for audit, and move it
	// requested → ai_reviewed. Fail-OPEN — an unreachable agent yields a
	// medium/needs_review verdict rather than blocking — but a hard persistence
	// failure must surface, so the request does not silently skip the gate.
	review, rerr := h.riskReview.ReviewRequest(c.Request.Context(), lifecycle.RiskReviewInput{
		WorkspaceID:   ws,
		RequestID:     req.ID,
		Actor:         actor(c),
		Role:          body.Role,
		ResourceRef:   body.ResourceRef,
		Justification: body.Justification,
		ResourceTags:  body.ResourceTags,
		DurationHours: body.DurationHours,
	})
	if rerr != nil {
		h.fail(c, rerr)
		return
	}
	req = review.Request

	// Risk-based routing on the AI-derived verdict: an auto_approve_eligible
	// (low) request fast-tracks to approved; medium/high stay parked in
	// ai_reviewed for the manager / security gate. A routing failure must not
	// lose the reviewed request, so surface the decision best-effort.
	decision, werr := h.workflow.ExecuteWorkflow(c.Request.Context(), ws, req, actor(c))
	if werr != nil {
		logger.Warnf(c.Request.Context(), "lifecycle: workflow routing for request %s: %v", req.ID, werr)
	}
	// Reload to reflect any state change made by the workflow.
	if updated, gerr := h.requests.GetRequest(c.Request.Context(), ws, req.ID); gerr == nil {
		req = updated
	}
	// A fast-tracked (auto-approved) elevation is fed to the anomaly skill so
	// any flags surface on the request + in access reviews (advisory, fail-open).
	if decision.Approved {
		h.runAnomalyHook(c, ws, req)
	}
	c.JSON(http.StatusCreated, gin.H{"request": req, "risk": review.Verdict, "workflow": decision})
}

// anomalyHookTimeout bounds the out-of-band anomaly-detection round trip + flag
// persistence so a slow or unreachable agent can never leak the detached
// goroutine. It sits comfortably above the aiclient request timeout.
const anomalyHookTimeout = 30 * time.Second

// runAnomalyHook feeds a just-approved elevation to the anomaly-detection skill
// and persists any flags. It is advisory and fail-open, so it must never add
// latency to the approval response or block on the AI round trip: the work runs
// in a detached goroutine on a context that survives the request
// (context.WithoutCancel keeps request-scoped values but drops cancellation)
// and is bounded by anomalyHookTimeout. Any failure is only logged; a flag
// never changes the request's FSM state, so this can neither block nor reverse
// the approval.
func (h *lifecycleHandlers) runAnomalyHook(c *gin.Context, ws uuid.UUID, req *models.AccessRequest) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), anomalyHookTimeout)
	go func() {
		defer cancel()
		if err := h.riskReview.RecordApprovalAnomalies(ctx, ws, req, nil); err != nil {
			logger.Warnf(ctx, "lifecycle: anomaly hook for request %s: %v", req.ID, err)
		}
	}()
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
	// Surface the AI verdict + any anomaly flags so the approver view shows the
	// rationale and risk factors alongside the request. Both are best-effort:
	// a request created before WS5 has no verdict (omitted), and the flag list
	// is simply empty when none were detected.
	resp := gin.H{"request": req}
	if verdict, verr := h.riskReview.LatestVerdict(c.Request.Context(), ws, id); verr == nil {
		resp["risk"] = verdict
	}
	if flags, ferr := h.riskReview.ListAnomalyFlags(c.Request.Context(), ws, id); ferr == nil && len(flags) > 0 {
		resp["anomalies"] = flags
	}
	c.JSON(http.StatusOK, resp)
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

// approveRequest approves an elevation. High-risk requests (AI verdict →
// high_risk: a high score or a sensitive-resource factor) require step-up MFA:
// the gate is fail-CLOSED, so an approver whose token does not carry a
// satisfied MFA claim is rejected 403 and the request stays parked. The AI
// recommendation never silently auto-approves a high-risk request here — a
// human with elevated assurance must act. After a successful approval the
// elevation is fed to the anomaly skill (advisory, fail-open).
func (h *lifecycleHandlers) approveRequest(c *gin.Context) {
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
	req, err := h.requests.GetRequest(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	if lifecycle.RequiresStepUp(req) && !mfaSatisfied(c) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":            "step-up MFA required to approve a high-risk request",
			"step_up_required": true,
			"recommendation":   lifecycle.RecommendationHighRisk,
		})
		return
	}
	if err := h.requests.ApproveRequest(c.Request.Context(), ws, id, actor(c), body.Reason); err != nil {
		h.fail(c, err)
		return
	}
	approved, err := h.requests.GetRequest(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	h.runAnomalyHook(c, ws, approved)
	c.JSON(http.StatusOK, gin.H{"request": approved})
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

type promoteBody struct {
	Force  bool   `json:"force"`
	Reason string `json:"reason"`
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
	var body promoteBody
	if !bindOptional(c, &body) {
		return
	}
	pol, err := h.policies.Promote(c.Request.Context(), ws, id, actor(c), lifecycle.PromoteOptions{
		Force:  body.Force,
		Reason: body.Reason,
	})
	if err != nil {
		// A conflict block carries the offending conflicts so the operator can
		// review them before overriding with {"force":true,"reason":"..."}.
		var ce *lifecycle.PromoteConflictError
		if errors.As(err, &ce) {
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{
				"error":     ce.Error(),
				"conflicts": ce.Conflicts,
			})
			return
		}
		// A SoD catastrophic-change block carries the introduced toxic
		// combinations so the operator can review them before overriding with
		// {"force":true,"reason":"..."}.
		var se *lifecycle.PromoteSodError
		if errors.As(err, &se) {
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{
				"error":          se.Error(),
				"sod_violations": se.Violations,
			})
			return
		}
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"policy": pol})
}

// --- ad-hoc bulk-change simulation ---

func (h *lifecycleHandlers) simulateDefinition(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var body struct {
		Definition json.RawMessage `json:"definition" binding:"required"`
	}
	if !bind(c, &body) {
		return
	}
	def, err := lifecycle.ParsePolicyDefinition(body.Definition)
	if err != nil {
		h.fail(c, err)
		return
	}
	sim, err := h.policies.SimulateDefinition(c.Request.Context(), ws, def)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"simulation": sim})
}

// --- separation of duties ---

type createSodRuleBody struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	ResourceA   string `json:"resource_a"`
	RoleA       string `json:"role_a"`
	ResourceB   string `json:"resource_b"`
	RoleB       string `json:"role_b"`
}

func (h *lifecycleHandlers) createSodRule(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var body createSodRuleBody
	if !bind(c, &body) {
		return
	}
	rule, err := h.sod.CreateRule(c.Request.Context(), lifecycle.CreateSodRuleInput{
		WorkspaceID: ws,
		Name:        body.Name,
		Description: body.Description,
		Severity:    body.Severity,
		ResourceA:   body.ResourceA,
		RoleA:       body.RoleA,
		ResourceB:   body.ResourceB,
		RoleB:       body.RoleB,
		Actor:       actor(c),
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"rule": rule})
}

func (h *lifecycleHandlers) listSodRules(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	rows, err := h.sod.ListRules(c.Request.Context(), ws)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"rules": rows})
}

func (h *lifecycleHandlers) deleteSodRule(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	if err := h.sod.DeleteRule(c.Request.Context(), ws, id, actor(c)); err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func (h *lifecycleHandlers) listAnomalies(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	rows, err := h.anomalies.ListAnomalies(c.Request.Context(), ws)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"anomalies": rows})
}

// --- contractor access lifecycle ---

type createContractorGrantBody struct {
	ContractorUserID string    `json:"contractor_user_id" binding:"required"`
	DisplayName      string    `json:"display_name"`
	ConnectorID      uuid.UUID `json:"connector_id" binding:"required"`
	ResourceRef      string    `json:"resource_ref" binding:"required"`
	Role             string    `json:"role"`
	SponsorID        string    `json:"sponsor_id" binding:"required"`
	Justification    string    `json:"justification"`
	ExpiresAt        time.Time `json:"expires_at" binding:"required"`
}

func (h *lifecycleHandlers) createContractorGrant(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var body createContractorGrantBody
	if !bind(c, &body) {
		return
	}
	grant, err := h.contractors.CreateGrant(c.Request.Context(), lifecycle.CreateContractorGrantInput{
		WorkspaceID:      ws,
		ContractorUserID: body.ContractorUserID,
		DisplayName:      body.DisplayName,
		ConnectorID:      body.ConnectorID,
		ResourceRef:      body.ResourceRef,
		Role:             body.Role,
		SponsorID:        body.SponsorID,
		RequestedBy:      actor(c),
		Justification:    body.Justification,
		ExpiresAt:        body.ExpiresAt,
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"contractor_grant": grant})
}

func (h *lifecycleHandlers) listContractorGrants(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	rows, err := h.contractors.ListGrants(c.Request.Context(), ws)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"contractor_grants": rows})
}

func (h *lifecycleHandlers) getContractorGrant(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	grant, err := h.contractors.GetGrant(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"contractor_grant": grant})
}

func (h *lifecycleHandlers) approveContractorGrant(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	grant, err := h.contractors.ApproveGrant(c.Request.Context(), ws, id, actor(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"contractor_grant": grant})
}

func (h *lifecycleHandlers) rejectContractorGrant(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if !bindOptional(c, &body) {
		return
	}
	grant, err := h.contractors.RejectGrant(c.Request.Context(), ws, id, actor(c), body.Reason)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"contractor_grant": grant})
}

func (h *lifecycleHandlers) revokeContractorGrant(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if !bindOptional(c, &body) {
		return
	}
	grant, err := h.contractors.RevokeGrant(c.Request.Context(), ws, id, actor(c), body.Reason)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"contractor_grant": grant})
}

type extendContractorGrantBody struct {
	ExpiresAt time.Time `json:"expires_at" binding:"required"`
	Reason    string    `json:"reason"`
}

func (h *lifecycleHandlers) extendContractorGrant(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	var body extendContractorGrantBody
	if !bind(c, &body) {
		return
	}
	grant, err := h.contractors.ExtendExpiry(c.Request.Context(), ws, id, actor(c), body.ExpiresAt, body.Reason)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"contractor_grant": grant})
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
	lane, leaver, err := h.jml.HandleEvent(c.Request.Context(), ws, lifecycle.SCIMEvent{
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
		// A leaver kill switch that ran every layer but had one or more layers
		// fail is not an opaque internal error: return the per-layer breakdown
		// (which layers ran, which failed, and why) so an operator can act on it.
		if leaver != nil && leaver.Errored {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"lane": lane, "leaver": leaver, "error": err.Error()})
			return
		}
		h.fail(c, err)
		return
	}
	resp := gin.H{"lane": lane}
	if leaver != nil {
		resp["leaver"] = leaver
	}
	c.JSON(http.StatusOK, resp)
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

// mfaSatisfied reports whether the validated token carries a satisfied step-up
// MFA claim. It reads the verified claims (never client input), so the
// high-risk approval gate cannot be spoofed from the request body.
func mfaSatisfied(c *gin.Context) bool {
	if claims := middleware.ClaimsFromContext(c); claims != nil {
		return claims.MFASatisfied
	}
	return false
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
		errors.Is(err, lifecycle.ErrReviewItemNotFound),
		errors.Is(err, lifecycle.ErrGrantNotFound),
		errors.Is(err, lifecycle.ErrOrphanNotFound),
		errors.Is(err, lifecycle.ErrSodRuleNotFound),
		errors.Is(err, lifecycle.ErrContractorGrantNotFound):
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, lifecycle.ErrInvalidStateTransition),
		errors.Is(err, lifecycle.ErrReviewClosed),
		errors.Is(err, lifecycle.ErrReviewItemDecided),
		errors.Is(err, lifecycle.ErrPolicyNotPromotable),
		errors.Is(err, lifecycle.ErrPolicyNotEditable),
		errors.Is(err, lifecycle.ErrPolicyNotSimulated),
		errors.Is(err, lifecycle.ErrPolicyHasConflicts),
		errors.Is(err, lifecycle.ErrPolicyHasSodViolations),
		errors.Is(err, lifecycle.ErrContractorState):
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, lifecycle.ErrConnectorNotConfigured):
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
	default:
		logger.Errorf(c.Request.Context(), "lifecycle: unhandled error: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}
