package recordings

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// SearchQuery is the faceted + full-text query an auditor runs across a
// workspace's recordings. Every field is optional; an empty query lists the
// workspace's recordings newest-first. The text term is matched with Postgres
// FTS (to_tsvector/plainto_tsquery over the indexed command/keystroke text) and
// degrades to a case-insensitive LIKE on the SQLite test path.
type SearchQuery struct {
	Text     string
	Operator string
	Protocol string
	Target   string
	From     *time.Time
	To       *time.Time
	// IncludePruned includes recordings whose blob was tiered out by retention.
	// They remain searchable (the metadata row is preserved); the player surfaces
	// them as "blob expired". Default false keeps the common console view to
	// replayable recordings.
	IncludePruned bool
	Limit         int
	Offset        int
}

const (
	defaultSearchLimit = 50
	maxSearchLimit     = 200
)

func (q SearchQuery) normalized() SearchQuery {
	q.Text = strings.TrimSpace(q.Text)
	q.Operator = strings.TrimSpace(q.Operator)
	q.Protocol = strings.TrimSpace(q.Protocol)
	q.Target = strings.TrimSpace(q.Target)
	if q.Limit <= 0 {
		q.Limit = defaultSearchLimit
	}
	if q.Limit > maxSearchLimit {
		q.Limit = maxSearchLimit
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	return q
}

// SearchResult is one page of recordings plus the total match count (for
// pagination) and the page window the service actually applied.
type SearchResult struct {
	Recordings []models.SessionRecording
	Total      int64
	Limit      int
	Offset     int
}

// Search runs the faceted + full-text query within the workspace, newest-first,
// and returns one page plus the total match count. The workspace filter is
// always applied explicitly (defence in depth behind RLS) so a search can never
// cross a tenant boundary even if the GUC is unset on this connection.
func (s *Service) Search(ctx context.Context, workspaceID uuid.UUID, q SearchQuery) (SearchResult, error) {
	if workspaceID == uuid.Nil {
		return SearchResult{}, fmt.Errorf("%w: workspace id is required", ErrValidation)
	}
	q = q.normalized()

	base := s.db.WithContext(ctx).
		Model(&models.SessionRecording{}).
		Where("workspace_id = ?", workspaceID)
	base = applyFilters(base, q, isPostgres(s.db))

	var total int64
	if err := base.Count(&total).Error; err != nil {
		return SearchResult{}, fmt.Errorf("recordings: count search results: %w", err)
	}

	rows := []models.SessionRecording{}
	if total > 0 {
		if err := base.
			Order("started_at DESC NULLS LAST").
			Limit(q.Limit).
			Offset(q.Offset).
			Find(&rows).Error; err != nil {
			return SearchResult{}, fmt.Errorf("recordings: run search: %w", err)
		}
	}
	return SearchResult{Recordings: rows, Total: total, Limit: q.Limit, Offset: q.Offset}, nil
}

// escapeLike escapes the SQL LIKE wildcards so a user-supplied facet term is
// matched literally: a target of "prod_db" must not match "prodXdb". It escapes
// the backslash first (the escape char itself), then % and _. Both the Postgres
// and SQLite LIKE clauses that use it declare ESCAPE '\' so the backslash is the
// recognised escape on both dialects (SQLite has no default escape char).
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}

// applyFilters layers the query's facets and full-text term onto the base query.
// It is split out (and dialect-aware) so the Count and the Find share EXACTLY
// the same predicate — otherwise the pagination total would not match the rows.
func applyFilters(db *gorm.DB, q SearchQuery, postgres bool) *gorm.DB {
	if q.Operator != "" {
		db = db.Where("operator = ?", q.Operator)
	}
	if q.Protocol != "" {
		db = db.Where("protocol = ?", q.Protocol)
	}
	if q.Target != "" {
		db = db.Where(`target_name LIKE ? ESCAPE '\'`, "%"+escapeLike(q.Target)+"%")
	}
	if q.From != nil {
		db = db.Where("started_at >= ?", q.From.UTC())
	}
	if q.To != nil {
		db = db.Where("started_at <= ?", q.To.UTC())
	}
	if !q.IncludePruned {
		db = db.Where("blob_pruned = ?", false)
	}
	if q.Text != "" {
		if postgres {
			// Postgres FTS: the GIN index in migration 0061 is on
			// to_tsvector('english', search_text); using the identical
			// expression here lets the planner use that index.
			db = db.Where("to_tsvector('english', search_text) @@ plainto_tsquery('english', ?)", q.Text)
		} else {
			// SQLite test path: no tsvector, so fall back to a case-insensitive
			// substring match over the same indexed text.
			db = db.Where(`LOWER(search_text) LIKE LOWER(?) ESCAPE '\'`, "%"+escapeLike(q.Text)+"%")
		}
	}
	return db
}

// NULLS LAST is Postgres syntax; SQLite sorts NULLs first on ASC / last on DESC
// by default, and accepts the NULLS clause from modern builds, so the shared
// ordering string is portable for both. Kept as a named helper string so the
// intent is documented at the single call site above.
