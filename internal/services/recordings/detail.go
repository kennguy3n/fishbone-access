package recordings

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/gateway"
	"github.com/kennguy3n/fishbone-access/internal/models"
)

// CommandTimelineEntry is one row of the synchronized command timeline the
// replay player renders alongside the transcript: the per-session sequence, the
// command/statement text, the policy decision the gateway applied (the player
// highlights deny), and the human-readable reason.
type CommandTimelineEntry struct {
	Seq      int64  `json:"seq"`
	Command  string `json:"command"`
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
	Denied   bool   `json:"denied"`
}

// RecordingDetail is a single recording's searchable metadata plus its command
// timeline — everything the player needs EXCEPT the heavy frame bytes (streamed
// separately so the metadata view loads instantly and the bytes only when the
// operator actually presses play).
type RecordingDetail struct {
	Recording models.SessionRecording `json:"recording"`
	Timeline  []CommandTimelineEntry  `json:"timeline"`
}

// ReplayStream is the decoded, time-ordered transcript the player animates,
// plus the live tamper verdict. Verified is the authoritative tamper-evidence
// signal: the bytes were re-hashed on read and compared to the SHA-256 the
// gateway anchored in the audit chain at capture. Anchored reports whether such
// a digest existed to compare against (an un-anchored recording cannot be
// "verified", only displayed).
type ReplayStream struct {
	SessionID uuid.UUID             `json:"session_id"`
	Frames    []gateway.ReplayFrame `json:"frames"`
	Bytes     int64                 `json:"bytes"`
	SHA256    string                `json:"sha256"`
	Anchored  bool                  `json:"anchored"`
	Verified  bool                  `json:"verified"`
	Truncated bool                  `json:"truncated"`
}

// GetRecording returns one recording's metadata and command timeline. The
// workspace filter is applied explicitly (defence in depth behind RLS).
func (s *Service) GetRecording(ctx context.Context, workspaceID, sessionID uuid.UUID) (RecordingDetail, error) {
	if workspaceID == uuid.Nil || sessionID == uuid.Nil {
		return RecordingDetail{}, fmt.Errorf("%w: workspace and session id are required", ErrValidation)
	}
	var rec models.SessionRecording
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND session_id = ?", workspaceID, sessionID).
		First(&rec).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return RecordingDetail{}, fmt.Errorf("%w: session %s", ErrNotFound, sessionID)
		}
		return RecordingDetail{}, fmt.Errorf("recordings: load recording: %w", err)
	}

	cmds, err := s.loadCommands(ctx, workspaceID, sessionID)
	if err != nil {
		return RecordingDetail{}, err
	}
	timeline := make([]CommandTimelineEntry, 0, len(cmds))
	for _, c := range cmds {
		timeline = append(timeline, CommandTimelineEntry{
			Seq:      c.Seq,
			Command:  c.Command,
			Decision: c.Decision,
			Reason:   c.Reason,
			Denied:   c.Decision == models.PAMDecisionDeny,
		})
	}
	return RecordingDetail{Recording: rec, Timeline: timeline}, nil
}

// LoadFrames fetches the recording blob, decodes the time-ordered frames, and
// verifies the recomputed SHA-256 against the digest anchored in the audit
// chain — the live tamper check the player's badge reflects. It returns
// ErrBlobUnavailable when no reader is configured or the blob was tiered out by
// retention (the metadata + timeline remain available via GetRecording).
func (s *Service) LoadFrames(ctx context.Context, workspaceID, sessionID uuid.UUID) (ReplayStream, error) {
	if workspaceID == uuid.Nil || sessionID == uuid.Nil {
		return ReplayStream{}, fmt.Errorf("%w: workspace and session id are required", ErrValidation)
	}
	var rec models.SessionRecording
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND session_id = ?", workspaceID, sessionID).
		First(&rec).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ReplayStream{}, fmt.Errorf("%w: session %s", ErrNotFound, sessionID)
		}
		return ReplayStream{}, fmt.Errorf("recordings: load recording: %w", err)
	}
	if rec.BlobPruned {
		return ReplayStream{}, fmt.Errorf("%w: blob tiered out by retention policy", ErrBlobUnavailable)
	}
	if s.reader == nil {
		return ReplayStream{}, fmt.Errorf("%w: no replay reader configured", ErrBlobUnavailable)
	}

	rc, err := s.getReplay(ctx, workspaceID, sessionID)
	if err != nil {
		return ReplayStream{}, fmt.Errorf("%w: %v", ErrBlobUnavailable, err)
	}
	defer rc.Close()

	decoded, err := gateway.DecodeAndVerify(rc, rec.SHA256)
	if err != nil {
		return ReplayStream{}, fmt.Errorf("recordings: decode replay for session %s: %w", sessionID, err)
	}
	anchored := rec.SHA256 != ""
	if anchored && !decoded.SHA256Verified && s.metrics != nil {
		s.metrics.IncRecordingTamperDetected()
	}
	return ReplayStream{
		SessionID: sessionID,
		Frames:    decoded.Frames,
		Bytes:     decoded.Bytes,
		SHA256:    decoded.SHA256,
		Anchored:  anchored,
		Verified:  anchored && decoded.SHA256Verified,
		Truncated: decoded.Truncated,
	}, nil
}
