package pam

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// RecordingRef is the tamper-evident reference to a finished session recording
// that the gateway hands the control plane at teardown. It mirrors the
// gateway's recording integrity descriptor but is expressed in primitives so
// the pam package never imports gateway (the dependency only points
// gateway → pam, avoiding an import cycle).
//
//   - Key is the canonical replay-store key (gateway.ReplayKey), the stable
//     handle an auditor or the replay UI uses to fetch replay.bin.
//   - SHA256 is the hex SHA-256 over the exact framed bytes that were persisted,
//     so re-hashing the artifact proves it has not been altered since capture.
//   - Bytes is the recording length; Truncated reports whether the gateway's
//     size cap dropped trailing payload (the recording is still valid evidence,
//     just incomplete — the flag keeps that explicit for the auditor).
type RecordingRef struct {
	Key       string
	SHA256    string
	Bytes     int64
	Truncated bool
}

// RecordRecording anchors a finished privileged session's recording in the
// workspace audit hash chain as a single pam.session.recording event, so the
// recording's identity and integrity hash become first-class, tamper-evident
// compliance evidence (CC6.7 / A.8.2) rather than living only in the replay
// store. It is deliberately separate from CloseSession/TerminateSession: a
// recording exists regardless of HOW the session ended, so the reference must
// be emitted on both the clean-close and admin-terminate teardown paths, not
// gated on the close state transition.
//
// The gateway calls this exactly once per session, from the same single
// teardown defer that flushes the recorder, and only when the recording was
// actually persisted (ref.Key set). A zero/empty ref (recording disabled, or
// the flush failed to store) is a no-op: there is no durable artifact to
// reference, so the chain is not polluted with a dangling pointer.
func (m *SessionManager) RecordRecording(ctx context.Context, session *models.PAMSession, ref RecordingRef) error {
	if session == nil {
		return fmt.Errorf("%w: session is required", ErrValidation)
	}
	if ref.Key == "" {
		// No durable recording to anchor (recording disabled or store failed).
		return nil
	}
	now := m.now()
	md, err := marshalMeta(map[string]any{
		"session_id": session.ID.String(),
		"replay_key": ref.Key,
		"sha256":     ref.SHA256,
		"bytes":      ref.Bytes,
		"truncated":  ref.Truncated,
	})
	if err != nil {
		return err
	}
	return m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: session.WorkspaceID,
			Actor:       session.Subject,
			Action:      "pam.session.recording",
			TargetRef:   session.TargetID.String(),
			Metadata:    md,
		})
	})
}
