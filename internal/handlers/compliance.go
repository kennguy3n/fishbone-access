package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/middleware"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
	"github.com/kennguy3n/fishbone-access/internal/services/compliance"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// Evidence-timeline read bounds. The dashboard timeline is always capped so a
// single request can never materialise a whole workspace's audit chain: an
// absent or 0 limit falls back to evidenceDefaultLimit, and any explicit limit
// is clamped to evidenceMaxLimit (full-history export goes through the streamed
// pack writer, not this endpoint).
const (
	evidenceDefaultLimit = 200
	evidenceMaxLimit     = 1000
)

// complianceHandlers serves the WS6 compliance surface: the evidence stream /
// coverage / chain-verification read APIs, full certification campaigns, and
// the framework-mapped evidence-pack export. Like the lifecycle handlers, every
// handler derives workspace + actor from the request context (never the body),
// so a caller cannot cross tenants or spoof an actor.
type complianceHandlers struct {
	db        *gorm.DB
	evidence  *compliance.EvidenceService
	campaigns *compliance.CertificationService
	packs     *compliance.PackWriter
}

// newComplianceHandlers wires the compliance services off the shared DB pool.
// The certification service reuses the provisioning service as its grant
// revoker so a campaign close drives the same idempotent connector teardown the
// 1C review path uses, rather than a parallel one.
func newComplianceHandlers(deps Deps) *complianceHandlers {
	db := deps.DB
	resolver := lifecycle.NewDBConnectorResolver(db, deps.Encryptor)
	requests := lifecycle.NewAccessRequestService(db)
	prov := lifecycle.NewAccessProvisioningService(db, requests, resolver)
	ev := compliance.NewEvidenceService(db)
	return &complianceHandlers{
		db:        db,
		evidence:  ev,
		campaigns: compliance.NewCertificationService(db, prov),
		packs:     compliance.NewPackWriter(db, ev),
	}
}

// register mounts the compliance routes on the tenant-scoped group. The group
// must already carry Auth + ResolveTenant + RequireTenant, and (in production)
// AuthzMiddleware so the RequirePermission gates below enforce; when RBAC is
// not wired RequirePermission no-ops, preserving pre-RBAC behavior.
//
// Every route is permission-gated (fail-closed). Two permission families apply:
//
//   - The evidence-dashboard read surface (raw evidence stream, control
//     coverage, chain verification) is the compliance/auditor view, so it
//     requires PermComplianceRead — deliberately NOT held by RoleOperator, so a
//     plain member cannot read the tamper-evident chain or coverage of a
//     workspace.
//   - Certification campaigns are the compliance-domain expansion of access
//     reviews, built on the same review-service primitives, so they mirror the
//     existing /access-reviews gating exactly (PermReviewRead/Start/Respond/
//     Complete/Admin). This keeps the reviewer worklist reachable by an
//     operator who is assigned as a campaign reviewer (RoleOperator holds
//     PermReviewRead+PermReviewRespond) — gating campaign reads on
//     PermComplianceRead instead would lock those reviewers out of their own
//     queue.
//
// Export stays the most-privileged path: PermComplianceExport AND step-up MFA.
func (h *complianceHandlers) register(g *gin.RouterGroup) {
	// Compliance evidence dashboard read surface (auditor/compliance view).
	g.GET("/compliance/evidence", middleware.RequirePermission(authz.PermComplianceRead), h.listEvidence)
	g.GET("/compliance/coverage", middleware.RequirePermission(authz.PermComplianceRead), h.coverage)
	g.GET("/compliance/chain/verify", middleware.RequirePermission(authz.PermComplianceRead), h.verifyChain)

	// Certification campaigns — mirror the /access-reviews permission family.
	g.POST("/compliance/campaigns", middleware.RequirePermission(authz.PermReviewStart), h.startCampaign)
	g.GET("/compliance/campaigns", middleware.RequirePermission(authz.PermReviewRead), h.listCampaigns)
	g.GET("/compliance/campaigns/:id", middleware.RequirePermission(authz.PermReviewRead), h.campaignReport)
	g.GET("/compliance/campaigns/:id/items", middleware.RequirePermission(authz.PermReviewRead), h.campaignItems)
	g.POST("/compliance/campaigns/:id/items/:itemID/decision", middleware.RequirePermission(authz.PermReviewRespond), h.campaignDecision)
	// Dry-run preview of the destructive close (test-before-effect guardrail).
	g.GET("/compliance/campaigns/:id/revocation-preview", middleware.RequirePermission(authz.PermReviewRead), h.previewRevocations)
	g.POST("/compliance/campaigns/:id/close", middleware.RequirePermission(authz.PermReviewComplete), h.closeCampaign)
	g.POST("/compliance/campaigns/overdue-enforce", middleware.RequirePermission(authz.PermReviewAdmin), h.enforceOverdue)

	// Evidence-pack export: gated by the authz.PermComplianceExport
	// ("compliance.export") RBAC permission AND step-up MFA, and itself
	// audited. Both gates fail closed.
	g.POST("/compliance/export",
		middleware.RequirePermission(authz.PermComplianceExport),
		middleware.RequireMFA(),
		h.exportPack)
}

// --- evidence stream / coverage / verification ---

func (h *complianceHandlers) listEvidence(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	filter := compliance.EvidenceFilter{ControlledOnly: c.Query("controlled_only") == "true"}
	// order=desc returns the most-recent events first (the dashboard timeline);
	// the default ascending order walks the chain from its start. Any other
	// value is rejected rather than silently ignored so the contract is explicit.
	switch order := c.Query("order"); order {
	case "", "asc":
		filter.Newest = false
	case "desc":
		filter.Newest = true
	default:
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid order (want asc or desc)"})
		return
	}
	if t, ok := parseTimeQuery(c, "from"); ok {
		filter.From = t
	} else if c.Query("from") != "" {
		return // parseTimeQuery already aborted
	}
	if t, ok := parseTimeQuery(c, "to"); ok {
		filter.To = t
	} else if c.Query("to") != "" {
		return
	}
	if raw := c.Query("kinds"); raw != "" {
		for _, k := range strings.Split(raw, ",") {
			if k = strings.TrimSpace(k); k != "" {
				filter.Kinds = append(filter.Kinds, compliance.EvidenceKind(k))
			}
		}
	}
	// The timeline read is always bounded: an absent or 0 limit falls back to
	// the default, and any request is capped at the hard ceiling so no caller
	// (incl. limit=0) can stream a whole workspace's chain unbounded.
	filter.Limit = evidenceDefaultLimit
	if raw := c.Query("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid limit"})
			return
		}
		if n > 0 {
			filter.Limit = n
		}
	}
	if filter.Limit > evidenceMaxLimit {
		filter.Limit = evidenceMaxLimit
	}

	records, err := h.evidence.Stream(c.Request.Context(), ws, filter)
	if err != nil {
		failCompliance(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"records": records, "count": len(records)})
}

func (h *complianceHandlers) coverage(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	framework, ok := compliance.ValidFramework(c.Query("framework"))
	if !ok {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "unknown or missing framework"})
		return
	}
	var from, to *time.Time
	if t, ok := parseTimeQuery(c, "from"); ok {
		from = t
	} else if c.Query("from") != "" {
		return
	}
	if t, ok := parseTimeQuery(c, "to"); ok {
		to = t
	} else if c.Query("to") != "" {
		return
	}
	cov, err := h.evidence.Coverage(c.Request.Context(), ws, framework, from, to)
	if err != nil {
		failCompliance(c, err)
		return
	}
	c.JSON(http.StatusOK, cov)
}

func (h *complianceHandlers) verifyChain(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	v, err := h.evidence.VerifyChain(c.Request.Context(), ws)
	if err != nil {
		failCompliance(c, err)
		return
	}
	c.JSON(http.StatusOK, v)
}

// --- certification campaigns ---

type startCampaignBody struct {
	Name             string     `json:"name" binding:"required"`
	Framework        string     `json:"framework"`
	ScopeResource    string     `json:"scope_resource"`
	ScopeRole        string     `json:"scope_role"`
	ScopeConnectorID *uuid.UUID `json:"scope_connector_id"`
	Reviewers        []string   `json:"reviewers"`
	DueAt            *time.Time `json:"due_at"`
}

func (h *complianceHandlers) startCampaign(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var body startCampaignBody
	if !bind(c, &body) {
		return
	}
	in := compliance.CampaignInput{
		Name:          body.Name,
		Framework:     body.Framework,
		ScopeResource: body.ScopeResource,
		ScopeRole:     body.ScopeRole,
		Reviewers:     body.Reviewers,
		DueAt:         body.DueAt,
	}
	in.ScopeConnectorID = body.ScopeConnectorID
	campaign, items, err := h.campaigns.StartCampaign(c.Request.Context(), ws, in, actor(c))
	if err != nil {
		failCompliance(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"campaign": campaign, "item_count": items})
}

func (h *complianceHandlers) listCampaigns(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	campaigns, err := h.campaigns.ListCampaigns(c.Request.Context(), ws)
	if err != nil {
		failCompliance(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"campaigns": campaigns})
}

func (h *complianceHandlers) campaignReport(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	report, err := h.campaigns.Report(c.Request.Context(), ws, id)
	if err != nil {
		failCompliance(c, err)
		return
	}
	c.JSON(http.StatusOK, report)
}

func (h *complianceHandlers) campaignItems(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	items, err := h.campaigns.ListItems(c.Request.Context(), ws, id, c.Query("reviewer"))
	if err != nil {
		failCompliance(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

type campaignDecisionBody struct {
	Decision string `json:"decision" binding:"required"`
	Reason   string `json:"reason"`
}

func (h *complianceHandlers) campaignDecision(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	itemID, ok := pathUUID(c, "itemID")
	if !ok {
		return
	}
	var body campaignDecisionBody
	if !bind(c, &body) {
		return
	}
	if err := h.campaigns.SubmitDecision(c.Request.Context(), ws, id, itemID, body.Decision, actor(c), body.Reason); err != nil {
		failCompliance(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "recorded"})
}

func (h *complianceHandlers) previewRevocations(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	preview, err := h.campaigns.PreviewRevocations(c.Request.Context(), ws, id)
	if err != nil {
		failCompliance(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"revocations": preview, "count": len(preview)})
}

func (h *complianceHandlers) closeCampaign(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	report, err := h.campaigns.CloseCampaign(c.Request.Context(), ws, id, actor(c))
	if err != nil {
		failCompliance(c, err)
		return
	}
	c.JSON(http.StatusOK, report)
}

func (h *complianceHandlers) enforceOverdue(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	marked, err := h.campaigns.EnforceOverdue(c.Request.Context(), ws)
	if err != nil {
		failCompliance(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"marked_overdue": marked})
}

// --- evidence-pack export ---

type exportBody struct {
	Framework string     `json:"framework" binding:"required"`
	From      *time.Time `json:"from"`
	To        *time.Time `json:"to"`
}

// exportPack assembles a framework-mapped evidence pack and streams it as a ZIP.
// The pack is written to a temp file first so its content digest is known
// BEFORE the export is recorded: the compliance.export event (with the digest,
// framework, period, and mfa flag) is appended to the workspace audit chain,
// and only then is the pack delivered. If the audit append fails the export
// fails closed and nothing is delivered.
func (h *complianceHandlers) exportPack(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var body exportBody
	if !bind(c, &body) {
		return
	}
	framework, ok := compliance.ValidFramework(body.Framework)
	if !ok {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "unknown framework"})
		return
	}

	tmp, err := os.CreateTemp("", "evidence-pack-*.zip")
	if err != nil {
		failCompliance(c, err)
		return
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	defer func() { _ = tmp.Close() }()

	manifest, err := h.packs.WritePack(c.Request.Context(), tmp, compliance.ExportOptions{
		WorkspaceID: ws,
		Framework:   framework,
		From:        body.From,
		To:          body.To,
		GeneratedBy: actor(c),
	})
	if err != nil {
		failCompliance(c, err)
		return
	}

	// Record the export in the tamper-evident chain BEFORE delivering it. The
	// content digest anchors exactly which bytes were exported.
	meta := map[string]any{
		"framework":      string(framework),
		"content_sha256": manifest.ContentSHA256,
		"evidence_total": manifest.EvidenceTotal,
		"chain_status":   manifest.ChainVerification.Status,
		"mfa_satisfied":  true, // RequireMFA gated this route
	}
	if body.From != nil {
		meta["from"] = body.From.UTC()
	}
	if body.To != nil {
		meta["to"] = body.To.UTC()
	}
	if err := lifecycle.AppendAudit(c.Request.Context(), h.db, time.Now(), lifecycle.AuditInput{
		WorkspaceID: ws,
		Actor:       actor(c),
		Action:      "compliance.export",
		TargetRef:   string(framework),
		Metadata:    marshalJSON(meta),
	}); err != nil {
		failCompliance(c, err)
		return
	}

	// The pack is fully written to the temp file, so its exact size is known.
	// Advertise it as Content-Length (instead of falling back to chunked
	// transfer encoding) so clients can show download progress for large
	// multi-year evidence packs.
	info, err := tmp.Stat()
	if err != nil {
		failCompliance(c, err)
		return
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		failCompliance(c, err)
		return
	}
	filename := "evidence-pack-" + strings.ReplaceAll(string(framework), " ", "_") + ".zip"
	// Set Content-Type explicitly: the body is a ZIP, not the gin default of
	// text/plain. Set before WriteHeader so it is not sniffed from the payload.
	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", "attachment; filename=\""+filename+"\"")
	c.Header("Content-Length", strconv.FormatInt(info.Size(), 10))
	c.Header("X-Evidence-Pack-Digest", manifest.ContentSHA256)
	c.Status(http.StatusOK)
	if _, err := io.Copy(c.Writer, tmp); err != nil {
		// Headers/body already partially sent; log and stop. The export is
		// already audited, so this is a delivery failure, not a missing record.
		logger.Errorf(c.Request.Context(), "compliance: stream evidence pack: %v", err)
	}
}

// --- helpers ---

// marshalJSON serialises export-audit metadata. The inputs are server-built
// scalars, so marshaling cannot fail in practice; fall back to an empty object
// rather than dropping the audit record on a theoretical error.
func marshalJSON(v map[string]any) datatypes.JSON {
	b, err := json.Marshal(v)
	if err != nil {
		return datatypes.JSON([]byte("{}"))
	}
	return datatypes.JSON(b)
}

func failCompliance(c *gin.Context, err error) {
	switch {
	case errors.Is(err, compliance.ErrValidation):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, compliance.ErrUnknownFramework):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, compliance.ErrCampaignNotFound),
		errors.Is(err, compliance.ErrItemNotFound):
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, compliance.ErrCampaignClosed),
		errors.Is(err, compliance.ErrItemDecided):
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, compliance.ErrNoRevoker):
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
	default:
		logger.Errorf(c.Request.Context(), "compliance: unhandled error: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}

// parseTimeQuery parses an RFC3339 query param. Returns (nil,false) when the
// param is absent; aborts 400 and returns (nil,false) when present but invalid.
func parseTimeQuery(c *gin.Context, name string) (*time.Time, bool) {
	raw := c.Query(name)
	if raw == "" {
		return nil, false
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid " + name + " (want RFC3339)"})
		return nil, false
	}
	return &t, true
}
