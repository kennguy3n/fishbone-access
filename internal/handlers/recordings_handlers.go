package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/fishbone-access/internal/middleware"
	"github.com/kennguy3n/fishbone-access/internal/services/authz"
	"github.com/kennguy3n/fishbone-access/internal/services/recordings"
)

// recordingsHandlers serves the searchable session-recording forensic store:
// full-text + faceted search across a workspace's recordings, one recording's
// metadata + command timeline, the decoded frame stream the replay player
// animates (with a live tamper verdict), and the per-workspace retention policy.
// Every handler derives its workspace from RequireTenant and the actor from the
// validated iam-core token — never from client input.
type recordingsHandlers struct {
	svc *recordings.Service
}

// newRecordingsHandlers wires the recordings service from shared Deps and the
// runtime environment. The replay reader is built from the same PAM_REPLAY_*
// environment the gateway and the PAM replay handler use, so the control plane
// reads recordings from the identical backend the gateway wrote them to. When
// the DB is nil the caller must not mount these routes (NewRouter gates on DB
// presence). A nil reader degrades the frame-stream endpoint to "blob
// unavailable" while search/metadata still work from the indexed rows.
func newRecordingsHandlers(deps Deps) *recordingsHandlers {
	var opts []recordings.Option
	// Prefer the shared replay backend wired by main (env-selected store wrapped
	// in per-workspace at-rest decryption when a KMS key is configured) so the
	// forensic store decodes the exact bytes the gateway wrote. Fall back to the
	// env builder for bare-Deps callers (tests/degraded boots).
	reader := deps.ReplayReader
	if reader == nil {
		reader = buildReplayReader()
	}
	if reader != nil {
		opts = append(opts, recordings.WithReplayReader(reader))
	}
	if deps.Metrics != nil {
		opts = append(opts, recordings.WithMetrics(deps.Metrics))
	}
	return &recordingsHandlers{svc: recordings.NewService(deps.DB, opts...)}
}

// register mounts the recordings routes on the tenant-scoped group (already
// carrying Auth + ResolveTenant + RequireTenant). Reads need pam.session.read
// (the same auditor permission as session replay); changing the retention
// policy is an administrative action gated on pam.session.admin.
func (h *recordingsHandlers) register(g *gin.RouterGroup) {
	recG := g.Group("/pam/recordings")
	recG.GET("", middleware.RequirePermission(authz.PermPAMSessionRead), h.search)
	recG.GET("/retention-policy", middleware.RequirePermission(authz.PermPAMSessionRead), h.getRetention)
	recG.PUT("/retention-policy", middleware.RequirePermission(authz.PermPAMSessionAdmin), h.setRetention)
	recG.GET("/:id", middleware.RequirePermission(authz.PermPAMSessionRead), h.getRecording)
	recG.GET("/:id/frames", middleware.RequirePermission(authz.PermPAMSessionRead), h.getFrames)
}

func (h *recordingsHandlers) search(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	q := recordings.SearchQuery{
		Text:          c.Query("q"),
		Operator:      c.Query("operator"),
		Protocol:      c.Query("protocol"),
		Target:        c.Query("target"),
		IncludePruned: c.Query("include_pruned") == "true",
	}
	from, ferr := parseOptionalTime(c.Query("from"))
	if ferr != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid from (want RFC3339)"})
		return
	}
	to, terr := parseOptionalTime(c.Query("to"))
	if terr != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid to (want RFC3339)"})
		return
	}
	q.From, q.To = from, to
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			q.Limit = n
		}
	}
	if v := c.Query("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			q.Offset = n
		}
	}

	res, err := h.svc.Search(c.Request.Context(), ws, q)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"recordings": res.Recordings,
		"total":      res.Total,
		"limit":      res.Limit,
		"offset":     res.Offset,
	})
}

func (h *recordingsHandlers) getRecording(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	detail, err := h.svc.GetRecording(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, detail)
}

func (h *recordingsHandlers) getFrames(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	stream, err := h.svc.LoadFrames(c.Request.Context(), ws, id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, stream)
}

func (h *recordingsHandlers) getRetention(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	policy, set, err := h.svc.GetRetentionPolicy(c.Request.Context(), ws)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"retention_days": policy.RetentionDays,
		"is_default":     !set,
		"updated_by":     policy.UpdatedBy,
		"updated_at":     policy.UpdatedAt,
	})
}

type setRetentionBody struct {
	// RetentionDays is the number of days a recording's blob is kept before the
	// retention sweep tiers it out. 0 means "retain indefinitely". Pointer so an
	// omitted field is a 400 rather than a silent 0 (indefinite) — changing the
	// retention window is deliberate.
	RetentionDays *int `json:"retention_days" binding:"required"`
}

func (h *recordingsHandlers) setRetention(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var body setRetentionBody
	if !bind(c, &body) {
		return
	}
	policy, err := h.svc.SetRetentionPolicy(c.Request.Context(), ws, *body.RetentionDays, actor(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"retention_days": policy.RetentionDays,
		"is_default":     false,
		"updated_by":     policy.UpdatedBy,
		"updated_at":     policy.UpdatedAt,
	})
}

// fail maps recordings sentinel errors to HTTP status codes. Unknown errors are
// 500 and logged by the central error path (never echoed) so an internal fault
// is not leaked to clients.
func (h *recordingsHandlers) fail(c *gin.Context, err error) {
	switch {
	case errors.Is(err, recordings.ErrValidation):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, recordings.ErrNotFound):
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, recordings.ErrBlobUnavailable):
		// The metadata + timeline are still available; only the byte-level
		// replay is gone (tiered out or no reader). 409 tells the player to show
		// the "blob expired" state rather than treating it as a hard error.
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": err.Error()})
	default:
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}

// parseOptionalTime parses an optional RFC3339 timestamp. An empty string is
// "not set" (nil, no error); a non-empty malformed value is an error.
func parseOptionalTime(raw string) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, err
	}
	u := t.UTC()
	return &u, nil
}
