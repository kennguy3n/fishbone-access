package recordings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kennguy3n/fishbone-access/internal/gateway"
	"github.com/kennguy3n/fishbone-access/internal/models"
)

// recordingAuditAction is the audit-chain action the gateway anchors a finished
// recording under (internal/services/pam/recording.go). The indexer reads the
// SHA-256 / byte length / truncation flag the gateway recorded there so the
// integrity digest in the searchable row is the SAME value committed to the
// tamper-evident chain at capture — not a digest this package computed and could
// not independently vouch for.
const recordingAuditAction = "pam.session.recording"

// anchoredRecording is the integrity descriptor the gateway committed to the
// audit chain at session teardown, recovered from the recording audit event.
type anchoredRecording struct {
	SHA256    string
	Bytes     int64
	Truncated bool
	Found     bool
}

// IndexSession projects a single finished PAM session into its searchable
// recording row, upserting on (workspace_id, session_id) so a re-index updates
// in place (idempotent). It is the unit the background sweep calls per session.
//
// The projection is DB-first: operator/target/protocol/timing come from the
// pam_sessions row, the command count / deny count / command text from
// pam_session_commands, and the integrity digest (SHA-256, bytes, truncated)
// from the recording's audit-chain event. When a ReplayReader is wired it ALSO
// reads the blob once to (a) mine operator keystroke text for richer full-text
// search and (b) verify the recomputed SHA-256 against the anchored digest,
// caching the live tamper status. A missing/unreadable blob is NOT fatal — the
// row is still indexed from DB facts (fail-open), because the searchable
// forensic metadata must exist even if the heavy blob is gone or unreachable.
func (s *Service) IndexSession(ctx context.Context, workspaceID, sessionID uuid.UUID) error {
	if workspaceID == uuid.Nil || sessionID == uuid.Nil {
		return fmt.Errorf("%w: workspace and session id are required", ErrValidation)
	}

	var session models.PAMSession
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, sessionID).
		First(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("%w: session %s", ErrNotFound, sessionID)
		}
		return fmt.Errorf("recordings: load session %s: %w", sessionID, err)
	}

	row, err := s.projectSession(ctx, session)
	if err != nil {
		return err
	}

	if err := s.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "workspace_id"}, {Name: "session_id"}},
			DoUpdates: clause.AssignmentColumns(indexUpsertColumns),
		}).
		Create(&row).Error; err != nil {
		return fmt.Errorf("recordings: upsert recording for session %s: %w", sessionID, err)
	}
	return nil
}

// indexUpsertColumns are the columns a re-index overwrites. The conflict keys
// (workspace_id, session_id), the row id, and created_at are intentionally NOT
// in the set so a re-index keeps the stable identity/creation time and only
// refreshes the projected facts.
var indexUpsertColumns = []string{
	"target_id", "operator", "target_name", "protocol", "state", "client_addr",
	"started_at", "ended_at", "duration_ms", "command_count", "deny_count",
	"frame_count", "bytes", "truncated", "replay_key", "sha256",
	"sha256_verified", "search_text", "indexed_at", "updated_at",
}

// projectSession builds the searchable row for one session from DB facts plus
// (best-effort) blob enrichment.
func (s *Service) projectSession(ctx context.Context, session models.PAMSession) (models.SessionRecording, error) {
	cmds, err := s.loadCommands(ctx, session.WorkspaceID, session.ID)
	if err != nil {
		return models.SessionRecording{}, err
	}
	denyCount := 0
	for _, c := range cmds {
		if c.Decision == models.PAMDecisionDeny {
			denyCount++
		}
	}

	anchor, err := s.anchoredRecording(ctx, session.WorkspaceID, session.ID)
	if err != nil {
		return models.SessionRecording{}, err
	}

	now := s.now().UTC()
	row := models.SessionRecording{
		WorkspaceID:  session.WorkspaceID,
		SessionID:    session.ID,
		Operator:     session.Subject,
		Protocol:     session.Protocol,
		State:        session.State,
		ClientAddr:   session.ClientAddr,
		StartedAt:    nonZeroTime(session.StartedAt),
		EndedAt:      session.EndedAt,
		CommandCount: len(cmds),
		DenyCount:    denyCount,
		ReplayKey:    session.ReplayKey,
		SHA256:       anchor.SHA256,
		Truncated:    anchor.Truncated,
		Bytes:        anchor.Bytes,
		IndexedAt:    &now,
	}
	if session.TargetID != uuid.Nil {
		tid := session.TargetID
		row.TargetID = &tid
		row.TargetName = s.targetName(ctx, session.WorkspaceID, session.TargetID)
	}
	if row.StartedAt != nil && session.EndedAt != nil {
		if d := session.EndedAt.Sub(*row.StartedAt); d > 0 {
			row.DurationMillis = d.Milliseconds()
		}
	}

	keystrokes := s.enrichFromBlob(ctx, &row, anchor)
	row.SearchText = buildSearchText(session, cmds, keystrokes)
	return row, nil
}

// enrichFromBlob reads the recording blob once (when a reader is configured and
// the blob is not already tiered out) to set the live frame count, refine the
// byte length, and verify the SHA-256 against the anchored digest, returning the
// extracted operator keystroke text for the search index. Every failure is
// swallowed (fail-open): enrichment is a bonus over the DB projection, never a
// reason to leave a session unindexed. A detected tamper (recomputed digest does
// not match the anchor) increments the aggregate security counter.
func (s *Service) enrichFromBlob(ctx context.Context, row *models.SessionRecording, anchor anchoredRecording) string {
	if s.reader == nil || row.BlobPruned {
		return ""
	}
	rc, err := s.getReplay(ctx, row.WorkspaceID, row.SessionID)
	if err != nil {
		return ""
	}
	defer rc.Close()

	decoded, err := gateway.DecodeAndVerify(rc, anchor.SHA256)
	if err != nil {
		return ""
	}
	row.FrameCount = len(decoded.Frames)
	row.Bytes = decoded.Bytes
	row.Truncated = decoded.Truncated
	if row.SHA256 == "" {
		row.SHA256 = decoded.SHA256
	}
	if anchor.Found {
		row.SHA256Verified = decoded.SHA256Verified
		if !decoded.SHA256Verified && s.metrics != nil {
			s.metrics.IncRecordingTamperDetected()
		}
	}
	return gateway.ExtractKeystrokeText(decoded.Frames, s.maxKeystrokeText)
}

// loadCommands returns a session's logged commands ordered by the per-session
// monotonic sequence so the transcript reconstructs deterministically.
func (s *Service) loadCommands(ctx context.Context, workspaceID, sessionID uuid.UUID) ([]models.PAMSessionCommand, error) {
	var cmds []models.PAMSessionCommand
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND session_id = ?", workspaceID, sessionID).
		Order("seq ASC").
		Find(&cmds).Error; err != nil {
		return nil, fmt.Errorf("recordings: load commands for session %s: %w", sessionID, err)
	}
	return cmds, nil
}

// targetName resolves the human-readable target name for display/search. A
// missing target (deleted since the session) is not fatal — the row simply
// carries an empty target name.
func (s *Service) targetName(ctx context.Context, workspaceID, targetID uuid.UUID) string {
	var t models.PAMTarget
	if err := s.db.WithContext(ctx).
		Select("name").
		Where("workspace_id = ? AND id = ?", workspaceID, targetID).
		First(&t).Error; err != nil {
		return ""
	}
	return t.Name
}

// anchoredRecording recovers the integrity descriptor the gateway committed to
// the audit chain for this session. It matches on the recording action plus the
// session id embedded in the event metadata, newest chain entry first (a
// re-recorded session — should not happen, but be safe — uses the latest). When
// no such event exists (recording disabled, or the session never produced a
// durable artifact) it returns Found=false and the row is indexed without an
// integrity digest.
func (s *Service) anchoredRecording(ctx context.Context, workspaceID, sessionID uuid.UUID) (anchoredRecording, error) {
	q := s.db.WithContext(ctx).
		Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND action = ?", workspaceID, recordingAuditAction)
	if isPostgres(s.db) {
		q = q.Where("metadata->>'session_id' = ?", sessionID.String())
	} else {
		q = q.Where("json_extract(metadata, '$.session_id') = ?", sessionID.String())
	}

	var ev models.AuditEvent
	if err := q.Order("chain_seq DESC").First(&ev).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return anchoredRecording{Found: false}, nil
		}
		return anchoredRecording{}, fmt.Errorf("recordings: load recording audit event for session %s: %w", sessionID, err)
	}

	var meta struct {
		SHA256    string `json:"sha256"`
		Bytes     int64  `json:"bytes"`
		Truncated bool   `json:"truncated"`
	}
	if len(ev.Metadata) > 0 {
		if err := json.Unmarshal(ev.Metadata, &meta); err != nil {
			// A malformed metadata blob must not strand indexing; treat it as
			// "no anchor recovered" so the row still indexes from DB facts.
			return anchoredRecording{Found: false}, nil
		}
	}
	return anchoredRecording{
		SHA256:    strings.TrimSpace(meta.SHA256),
		Bytes:     meta.Bytes,
		Truncated: meta.Truncated,
		Found:     true,
	}, nil
}

// IndexClosedSessions indexes up to limit finished sessions in the workspace
// that have no recording row yet (or whose row predates the session's last
// update), newest first. It is the unit of work the background sweep runs per
// workspace; it returns the number of sessions indexed so the sweep can report
// an aggregate. Only non-active sessions are indexed — an active session is
// still being recorded, so its projection would be incomplete.
func (s *Service) IndexClosedSessions(ctx context.Context, workspaceID uuid.UUID, limit int) (int, error) {
	if workspaceID == uuid.Nil {
		return 0, fmt.Errorf("%w: workspace id is required", ErrValidation)
	}
	if limit <= 0 {
		limit = 100
	}

	var sessions []models.PAMSession
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND state <> ?", workspaceID, models.PAMSessionActive).
		Where("id NOT IN (?)",
			s.db.Model(&models.SessionRecording{}).
				Select("session_id").
				Where("workspace_id = ?", workspaceID)).
		Order("started_at DESC").
		Limit(limit).
		Find(&sessions).Error; err != nil {
		return 0, fmt.Errorf("recordings: list unindexed sessions: %w", err)
	}

	indexed := 0
	for i := range sessions {
		if err := ctx.Err(); err != nil {
			return indexed, err
		}
		if err := s.IndexSession(ctx, workspaceID, sessions[i].ID); err != nil {
			// Fail-open per session: one bad session must not starve the rest of
			// the workspace's backlog. The sweep logs the aggregate; the row is
			// retried next round.
			continue
		}
		indexed++
	}
	if indexed > 0 && s.metrics != nil {
		s.metrics.AddRecordingsIndexed(indexed)
	}
	return indexed, nil
}

// buildSearchText assembles the full-text search payload for a recording: the
// who/what (operator, target, protocol), every logged command, and the
// extracted operator keystroke text. It deliberately includes ONLY operator
// input and the already policy-gated command rows — never target output, which
// holds secrets and query results that must not be indexed. Duplicate tokens
// are collapsed to keep the indexed text (and the FTS vector) compact.
func buildSearchText(session models.PAMSession, cmds []models.PAMSessionCommand, keystrokes string) string {
	parts := make([]string, 0, len(cmds)+4)
	parts = append(parts, session.Subject, session.Protocol)
	for _, c := range cmds {
		if t := strings.TrimSpace(c.Command); t != "" {
			parts = append(parts, t)
		}
	}
	if k := strings.TrimSpace(keystrokes); k != "" {
		parts = append(parts, k)
	}

	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	// Stable order keeps the indexed text deterministic across re-indexes (so an
	// unchanged session does not churn the row), independent of map iteration.
	sort.Strings(out)
	return strings.Join(out, "\n")
}

// nonZeroTime returns a pointer to t unless t is the zero time, in which case it
// returns nil so the column stays NULL rather than storing 0001-01-01.
func nonZeroTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}
