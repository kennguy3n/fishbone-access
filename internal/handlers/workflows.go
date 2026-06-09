package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/middleware"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
	"github.com/kennguy3n/fishbone-access/internal/services/workflow"
)

// workflowHandlers serves the JML no-code workflow builder: the draft → simulate
// → publish lifecycle, manual live runs, the standalone emergency-offboard kill
// switch, and the dashboard's run history. Like the lifecycle handlers, every
// handler derives the workspace from the verified tenant context and the actor
// from the validated token subject — never from the request body.
type workflowHandlers struct {
	svc   *workflow.Service
	steps workflow.StepServices
	db    *gorm.DB
}

func newWorkflowHandlers(deps Deps) *workflowHandlers {
	db := deps.DB
	resolver := lifecycle.NewDBConnectorResolver(db, deps.Encryptor)
	requests := lifecycle.NewAccessRequestService(db)
	wfRouter := lifecycle.NewWorkflowService(requests)
	prov := lifecycle.NewAccessProvisioningService(db, requests, resolver)
	jml := lifecycle.NewJMLService(db, requests, wfRouter, prov, resolver, deps.Disabler)
	reviews := lifecycle.NewReviewService(db, prov)
	return &workflowHandlers{
		svc: workflow.NewService(db),
		steps: workflow.StepServices{
			Requests: requests,
			Prov:     prov,
			Reviews:  reviews,
			JML:      jml,
		},
		db: db,
	}
}

// register mounts the workflow-builder routes on the tenant-scoped group (which
// already carries Auth + ResolveTenant + RequireTenant). Publishing and running
// mutate enforcement, so they require step-up MFA — mirroring policy promotion.
func (h *workflowHandlers) register(g *gin.RouterGroup) {
	g.POST("/workflows", h.create)
	g.GET("/workflows", h.list)
	g.GET("/workflows/:id", h.get)
	g.PUT("/workflows/:id", h.update)
	g.POST("/workflows/:id/simulate", h.simulate)
	g.POST("/workflows/:id/publish", middleware.RequireMFA(), h.publish)
	g.POST("/workflows/:id/archive", h.archive)
	g.POST("/workflows/:id/run", middleware.RequireMFA(), h.run)

	// JML dashboard: recent runs + per-run step audit.
	g.GET("/workflow-runs", h.listRuns)
	g.GET("/workflow-runs/:id", h.getRun)

	// Standalone emergency offboard: the six-layer leaver kill switch, gated by
	// step-up MFA.
	g.POST("/emergency-offboard", middleware.RequireMFA(), h.emergencyOffboard)
}

type workflowBody struct {
	Name       string          `json:"name"`
	Definition json.RawMessage `json:"definition"`
}

type subjectBody struct {
	ExternalID  string            `json:"external_id"`
	Email       string            `json:"email"`
	DisplayName string            `json:"display_name"`
	Department  string            `json:"department"`
	Groups      []string          `json:"groups"`
	Attributes  map[string]string `json:"attributes"`
}

func (b subjectBody) toSubject() workflow.Subject {
	return workflow.Subject{
		ExternalID:  b.ExternalID,
		Email:       b.Email,
		DisplayName: b.DisplayName,
		Department:  b.Department,
		Groups:      b.Groups,
		Attributes:  b.Attributes,
	}
}

func (h *workflowHandlers) create(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var body workflowBody
	if !bind(c, &body) {
		return
	}
	wf, err := h.svc.Create(c.Request.Context(), workflow.CreateInput{
		WorkspaceID: ws,
		Name:        body.Name,
		Definition:  body.Definition,
		Actor:       actor(c),
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"workflow": wf})
}

func (h *workflowHandlers) list(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	rows, err := h.svc.List(c.Request.Context(), ws)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"workflows": rows})
}

func (h *workflowHandlers) get(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	wf, err := h.svc.Get(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"workflow": wf})
}

func (h *workflowHandlers) update(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	var body workflowBody
	if !bind(c, &body) {
		return
	}
	wf, err := h.svc.UpdateDraft(c.Request.Context(), ws, id, body.Name, body.Definition, actor(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"workflow": wf})
}

func (h *workflowHandlers) simulate(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	var body subjectBody
	if !bind(c, &body) {
		return
	}
	result, err := h.svc.Simulate(c.Request.Context(), ws, id, body.toSubject())
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"simulation": result})
}

func (h *workflowHandlers) publish(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	wf, err := h.svc.Publish(c.Request.Context(), ws, id, actor(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"workflow": wf})
}

func (h *workflowHandlers) archive(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	wf, err := h.svc.Archive(c.Request.Context(), ws, id, actor(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"workflow": wf})
}

func (h *workflowHandlers) run(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	var body subjectBody
	if !bind(c, &body) {
		return
	}
	act := actor(c)
	deps := workflow.BuildStepDeps(h.db, h.steps, ws, act)
	result, err := h.svc.Run(c.Request.Context(), ws, id, body.toSubject(), act, deps)
	if err != nil {
		h.fail(c, err)
		return
	}
	// A live run that completed but had any step failure (all steps failed =
	// StatusFailed, or a mix = StatusPartial) is not an opaque 500: return the
	// per-step breakdown so an operator can act on it. Both map to 500 to honor
	// the OpenAPI contract that a completed-with-failures run is a server error.
	if result != nil && (result.Status == workflow.StatusFailed || result.Status == workflow.StatusPartial) {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"run": result})
		return
	}
	c.JSON(http.StatusOK, gin.H{"run": result})
}

func (h *workflowHandlers) listRuns(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	limit := 0
	if q := c.Query("limit"); q != "" {
		// An unparseable limit is a client error, not a silent default
		// (mirrors listPacks' tier handling).
		n, err := strconv.Atoi(q)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid limit"})
			return
		}
		limit = n
	}
	rows, err := h.svc.ListRuns(c.Request.Context(), ws, limit)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"runs": rows})
}

func (h *workflowHandlers) getRun(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	run, err := h.svc.GetRun(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"run": run})
}

type emergencyOffboardBody struct {
	UserExternalID string `json:"user_external_id" binding:"required"`
	Reason         string `json:"reason"`
}

// emergencyOffboard runs the six-layer leaver kill switch directly for a user,
// outside any workflow — the "break glass" path gated by step-up MFA. It is
// fail-closed and returns the full per-layer breakdown even on partial failure
// so an operator can see exactly which layers ran.
func (h *workflowHandlers) emergencyOffboard(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var body emergencyOffboardBody
	if !bind(c, &body) {
		return
	}
	res, err := h.steps.JML.RunKillSwitch(c.Request.Context(), ws, body.UserExternalID, actor(c))
	if err != nil {
		if res != nil && res.Errored {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"leaver": res, "error": err.Error()})
			return
		}
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"leaver": res})
}

// fail maps sentinel errors to HTTP status codes. It bridges two packages: the
// workflow service's own sentinels and the lifecycle sentinels that surface
// through the emergency-offboard / run paths (which call JML + provisioning
// services). Unknown errors are 500 and logged (never echoed) so an internal
// fault is not leaked.
func (h *workflowHandlers) fail(c *gin.Context, err error) {
	switch {
	case errors.Is(err, workflow.ErrValidation),
		errors.Is(err, lifecycle.ErrValidation):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, workflow.ErrNotFound):
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, workflow.ErrNotEditable),
		errors.Is(err, workflow.ErrNotSimulated),
		errors.Is(err, workflow.ErrNotPublishable),
		errors.Is(err, workflow.ErrSimulationFailed),
		errors.Is(err, workflow.ErrSimulationNotMatched),
		errors.Is(err, workflow.ErrNotRunnable):
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": err.Error()})
	default:
		logger.Errorf(c.Request.Context(), "workflow: unhandled error: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}
