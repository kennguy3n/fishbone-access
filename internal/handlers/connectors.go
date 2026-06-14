package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/middleware"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
	"github.com/kennguy3n/fishbone-access/internal/services/connectorsetup"
	"github.com/kennguy3n/fishbone-access/internal/workers"
)

// connectorHandlers serves the connector-fabric surface: the capability-matrix
// catalogue (every provider the binary ships + what each can do), the
// AI-assisted setup wizard, and the connector-instance lifecycle (create / test
// / sync / disconnect). Like the lifecycle handlers, every operation derives the
// workspace from the verified tenant context and the actor from the validated
// token subject — never from client input — so a tenant can neither read nor
// mutate another tenant's connectors.
type connectorHandlers struct {
	catalogue *access.AccessConnectorCatalogueService
	mgmt      *access.ConnectorManagementService
	setup     *connectorsetup.Service
}

// newConnectorHandlers wires the connector services off the shared DB pool. It
// uses the access-stack credential encryptor (the same one the
// access-connector-worker seals/opens secrets with, so a connector created here
// is syncable there) and a workspace-scoped Postgres job queue filtered to the
// connector job types, so triggering a sync enqueues durable work the worker
// drains rather than running it inline on the request goroutine.
func newConnectorHandlers(deps Deps) *connectorHandlers {
	queue := workers.NewPostgresQueue(deps.DB, workers.WithJobTypes(
		access.JobTypeSyncIdentities,
		access.JobTypeProvision,
		access.JobTypeRevoke,
	))
	return &connectorHandlers{
		catalogue: access.NewAccessConnectorCatalogueService(deps.DB),
		mgmt:      access.NewConnectorManagementService(deps.DB, deps.ConnectorEncryptor, queue),
		setup:     connectorsetup.NewService(deps.DB, deps.AI),
	}
}

// register mounts the connector routes on the tenant-scoped group, which must
// already carry Auth + ResolveTenant + RequireTenant + AuthzMiddleware.
//
// The catalogue routes live under the static /connectors/catalogue prefix so
// they never collide with the /connectors/:connectorID instance routes: the
// catalogue is keyed by provider key (a string like "microsoft"), while the
// instance routes are keyed by a connector-row UUID. Keeping them on disjoint
// path prefixes makes the two namespaces unambiguous.
//
// Reads require connector.read; every mutation of the workspace's connections
// (create / test / sync / disconnect) requires connector.manage, so a read-only
// role (operator/security_admin) cannot alter connectors and a compliance
// auditor — which holds neither connector permission — cannot reach the surface
// at all. The setup wizard is part of the connect-a-provider authoring flow, so
// it is gated by connector.manage even though it only returns an advisory plan.
func (h *connectorHandlers) register(g *gin.RouterGroup) {
	// Capability matrix / gallery (provider-keyed, read-only).
	g.GET("/connectors", middleware.RequirePermission(authz.PermConnectorRead), h.listCatalogue)
	g.GET("/connectors/catalogue/facets", middleware.RequirePermission(authz.PermConnectorRead), h.catalogueFacets)
	g.GET("/connectors/catalogue/:provider", middleware.RequirePermission(authz.PermConnectorRead), h.catalogueDetail)
	// Structured guided-setup schema for a provider (curated, deterministic).
	g.GET("/connectors/catalogue/:provider/setup-schema", middleware.RequirePermission(authz.PermConnectorRead), h.catalogueSetupSchema)
	// AI-assisted setup wizard for a provider (advisory, fail-OPEN).
	g.POST("/connectors/catalogue/:provider/setup-wizard", middleware.RequirePermission(authz.PermConnectorManage), h.setupWizard)

	// Connector instances (UUID-keyed, mutate the workspace's connections).
	g.POST("/connectors", middleware.RequirePermission(authz.PermConnectorManage), h.createConnector)
	g.GET("/connectors/:connectorID", middleware.RequirePermission(authz.PermConnectorRead), h.getConnector)
	g.POST("/connectors/:connectorID/test", middleware.RequirePermission(authz.PermConnectorManage), h.testConnector)
	g.POST("/connectors/:connectorID/sync", middleware.RequirePermission(authz.PermConnectorManage), h.syncConnector)
	g.DELETE("/connectors/:connectorID", middleware.RequirePermission(authz.PermConnectorManage), h.disconnectConnector)
}

// --- capability matrix / catalogue ---

func (h *connectorHandlers) listCatalogue(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	q := access.ConnectorCatalogueQuery{
		WorkspaceID: ws,
		Capability:  strings.TrimSpace(c.Query("capability")),
		Tier:        strings.TrimSpace(c.Query("tier")),
		Category:    strings.TrimSpace(c.Query("category")),
	}
	if connected := strings.TrimSpace(c.Query("connected")); connected != "" {
		// An unparseable connected= filter is a client bug; reject it loudly
		// rather than silently treating it as "all".
		v, err := strconv.ParseBool(connected)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid connected filter (want true/false)"})
			return
		}
		// Tri-state: connected=true → connected-only, connected=false →
		// disconnected-only, omitted → all. A pointer is required so false is
		// distinguishable from the omitted/zero-value case.
		q.Connected = &v
	}
	entries, err := h.catalogue.ListCatalogue(c.Request.Context(), q)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"connectors": entries})
}

func (h *connectorHandlers) catalogueFacets(c *gin.Context) {
	if _, ok := workspace(c); !ok {
		return
	}
	c.JSON(http.StatusOK, h.catalogue.Facets())
}

func (h *connectorHandlers) catalogueDetail(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	provider := strings.TrimSpace(c.Param("provider"))
	entry, found, err := h.catalogue.CatalogueEntryFor(c.Request.Context(), ws, provider)
	if err != nil {
		h.fail(c, err)
		return
	}
	if !found {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "unknown connector provider"})
		return
	}
	c.JSON(http.StatusOK, entry)
}

// catalogueSetupSchema returns the curated, deterministic guided-setup schema
// for a provider: the supported auth method(s) and, for each, the typed fields
// to collect with inline "where do I find this?" help. It is what lets the
// connect UI render a labelled form instead of a raw key/value editor.
//
// An unknown provider is a 404. A known provider with no curated schema yet is
// a 200 with {"schema": null} (not a 404) so the client can cleanly fall back
// to the manual editor without treating "no guided flow" as an error.
func (h *connectorHandlers) catalogueSetupSchema(c *gin.Context) {
	if _, ok := workspace(c); !ok {
		return
	}
	provider := strings.TrimSpace(c.Param("provider"))
	if _, ok := access.CapabilityDescriptorFor(provider); !ok {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "unknown connector provider"})
		return
	}
	schema, ok := access.SetupSchemaFor(provider)
	if !ok {
		c.JSON(http.StatusOK, gin.H{"schema": nil})
		return
	}
	c.JSON(http.StatusOK, gin.H{"schema": schema})
}

// --- AI-assisted setup wizard ---

type setupWizardBody struct {
	AdminIntent string     `json:"admin_intent"`
	ConnectorID *uuid.UUID `json:"connector_id"`
}

// setupWizard consults the connector_setup_assistant skill for a guided plan.
// It is advisory and fail-OPEN: a model outage yields a degraded manual plan
// (HTTP 200), never a 5xx, so a human is never blocked from configuring a
// connector by an AI dependency being down.
func (h *connectorHandlers) setupWizard(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	provider := strings.TrimSpace(c.Param("provider"))
	var body setupWizardBody
	if !bindOptional(c, &body) {
		return
	}
	res, err := h.setup.Suggest(c.Request.Context(), connectorsetup.SuggestInput{
		WorkspaceID: ws,
		Actor:       actor(c),
		Provider:    provider,
		AdminIntent: strings.TrimSpace(body.AdminIntent),
		ConnectorID: body.ConnectorID,
		// WorkspaceAITier is left at the default (""): the agent routes to its
		// default model. The per-workspace tier is config-sourced (mirroring the
		// workflow engine), not derived from request state, so we do not invent a
		// plan→tier mapping here.
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

// --- connector instances ---

type createConnectorBody struct {
	Provider    string                 `json:"provider" binding:"required"`
	DisplayName string                 `json:"display_name"`
	Config      map[string]interface{} `json:"config"`
	Secrets     map[string]interface{} `json:"secrets"`
}

func (h *connectorHandlers) createConnector(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var body createConnectorBody
	if !bind(c, &body) {
		return
	}
	row, err := h.mgmt.Create(c.Request.Context(), access.CreateConnectorInput{
		WorkspaceID: ws,
		Provider:    strings.TrimSpace(body.Provider),
		DisplayName: strings.TrimSpace(body.DisplayName),
		Config:      body.Config,
		Secrets:     body.Secrets,
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, row)
}

func (h *connectorHandlers) getConnector(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "connectorID")
	if !ok {
		return
	}
	row, err := h.mgmt.Get(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, row)
}

type testConnectorBody struct {
	Capabilities []string `json:"capabilities"`
}

// testConnector runs the provider's live connectivity check (and, when
// capabilities are supplied, a permission probe). It returns 200 with the set
// of missing capabilities when the connection works but lacks scopes, and maps
// a hard connectivity failure to 502 so the client can distinguish "your
// credentials are wrong" from "the platform broke".
func (h *connectorHandlers) testConnector(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "connectorID")
	if !ok {
		return
	}
	var body testConnectorBody
	if !bindOptional(c, &body) {
		return
	}
	missing, err := h.mgmt.TestConnectivity(c.Request.Context(), ws, id, body.Capabilities)
	// The OpenAPI schema types `missing` as a non-nullable array, but a Go nil
	// slice (no capabilities probed, or Connect failed before VerifyPermissions)
	// marshals to JSON null. Coalesce to an empty array so both the 200 and 502
	// bodies always carry a valid [] and strict client-side schema validators
	// don't reject the response.
	if missing == nil {
		missing = []string{}
	}
	if err != nil {
		// Only a provider-side failure (tagged ErrConnectorConnectivity by
		// TestConnectivity) is a 502: the raw diagnostic + missing capabilities
		// are actionable for the operator fixing their credentials/scopes. Every
		// other error — not-found/registry (4xx) or an internal fault such as
		// secret decryption or config unmarshal — is routed through fail, which
		// maps it to the right status and returns a generic message for 500s so
		// encryption-layer internals never leak to the client.
		if errors.Is(err, access.ErrConnectorConnectivity) {
			// AbortWithStatusJSON (not plain JSON) so this path matches every
			// other error path here and in the lifecycle handlers: it calls
			// Abort(), so downstream middleware that branches on c.IsAborted()
			// (response logging, metrics) treats the 502 like any other failure.
			c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{
				"ok":      false,
				"error":   err.Error(),
				"missing": missing,
			})
			return
		}
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "missing": missing})
}

func (h *connectorHandlers) syncConnector(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "connectorID")
	if !ok {
		return
	}
	jobID, err := h.mgmt.TriggerSync(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"job_id": jobID})
}

func (h *connectorHandlers) disconnectConnector(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "connectorID")
	if !ok {
		return
	}
	if err := h.mgmt.Disconnect(c.Request.Context(), ws, id); err != nil {
		h.fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// fail maps connector/catalogue/setup sentinel errors to HTTP status codes.
// Unknown errors are logged (never echoed) and returned as 500 so an internal
// fault is not leaked to clients.
func (h *connectorHandlers) fail(c *gin.Context, err error) {
	switch {
	case errors.Is(err, access.ErrValidation), errors.Is(err, connectorsetup.ErrValidation):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, access.ErrConnectorRowNotFound):
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, access.ErrConnectorNotFound):
		// The provider key is not registered in this binary: the client asked
		// for a connector that does not exist, which is a bad request.
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
	default:
		logger.Errorf(c.Request.Context(), "connectors: unhandled error: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}
