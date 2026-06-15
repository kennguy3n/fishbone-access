package recordings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// recordingPrunedAuditAction is the audit-chain action appended when the
// retention sweep tiers a recording's blob out of storage. It is a NEW event in
// the SAME per-workspace hash chain as the original pam.session.recording
// anchor — the anchor is never deleted or altered, so the integrity record of
// "this session was recorded, here is its digest" is preserved; this event adds
// "and its heavy blob was tiered out on date X per the retention policy". An
// auditor reading the chain sees both, with no gap.
const recordingPrunedAuditAction = "pam.session.recording.pruned"

// retentionPruneActor is recorded as the actor on the prune audit event. It is
// the automated sweep, not a human — named distinctly so the audit trail
// attributes the tiering to the system retention job.
const retentionPruneActor = "retention-sweep"

// GetRetentionPolicy returns the workspace's recording retention override and
// whether one is set. When none is set the caller falls back to the
// plan/global default (config). RetentionDays == 0 means "retain indefinitely".
func (s *Service) GetRetentionPolicy(ctx context.Context, workspaceID uuid.UUID) (models.RecordingRetentionPolicy, bool, error) {
	if workspaceID == uuid.Nil {
		return models.RecordingRetentionPolicy{}, false, fmt.Errorf("%w: workspace id is required", ErrValidation)
	}
	var p models.RecordingRetentionPolicy
	err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return models.RecordingRetentionPolicy{WorkspaceID: workspaceID}, false, nil
	}
	if err != nil {
		return models.RecordingRetentionPolicy{}, false, fmt.Errorf("recordings: load retention policy: %w", err)
	}
	return p, true, nil
}

// SetRetentionPolicy upserts the workspace's recording retention override.
// retentionDays must be >= 0; 0 means "retain indefinitely" (the sweep never
// tiers the workspace's blobs). The write is upserted on the workspace primary
// key so a repeat call updates in place.
func (s *Service) SetRetentionPolicy(ctx context.Context, workspaceID uuid.UUID, retentionDays int, actor string) (models.RecordingRetentionPolicy, error) {
	if workspaceID == uuid.Nil {
		return models.RecordingRetentionPolicy{}, fmt.Errorf("%w: workspace id is required", ErrValidation)
	}
	if retentionDays < 0 {
		return models.RecordingRetentionPolicy{}, fmt.Errorf("%w: retention days must be >= 0", ErrValidation)
	}
	now := s.now().UTC()
	p := models.RecordingRetentionPolicy{
		WorkspaceID:   workspaceID,
		RetentionDays: retentionDays,
		UpdatedBy:     actor,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := s.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "workspace_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"retention_days", "updated_by", "updated_at"}),
		}).
		Create(&p).Error; err != nil {
		return models.RecordingRetentionPolicy{}, fmt.Errorf("recordings: upsert retention policy: %w", err)
	}
	return p, nil
}

// EffectiveRetentionDays resolves the retention window the sweep enforces for a
// workspace: the per-workspace override when set, else the supplied
// plan/global default. A result <= 0 means "retain indefinitely" (no pruning).
func (s *Service) EffectiveRetentionDays(ctx context.Context, workspaceID uuid.UUID, defaultDays int) (int, error) {
	p, ok, err := s.GetRetentionPolicy(ctx, workspaceID)
	if err != nil {
		return 0, err
	}
	if ok {
		return p.RetentionDays, nil
	}
	if defaultDays < 0 {
		return 0, nil
	}
	return defaultDays, nil
}

// PruneExpiredBlobs tiers out the replay blobs of recordings in the workspace
// whose end time is older than the effective retention window, up to a bounded
// batch. For each expired recording it deletes the heavy blob from object
// storage, then atomically marks the metadata row pruned AND appends a
// tier-out event to the audit chain — so the searchable row and the integrity
// anchor survive, but the secrets-bearing bytes are gone.
//
// It is FAIL-OPEN per recording: a blob delete or row update that errors logs
// (via the returned count being short) and the loop continues, so one stuck
// recording cannot block the rest of the workspace's expiry. A workspace with
// retention disabled (effective days <= 0), no deleter wired, or no expired
// recordings is a no-op returning 0.
func (s *Service) PruneExpiredBlobs(ctx context.Context, workspaceID uuid.UUID, defaultDays, limit int) (int, error) {
	if workspaceID == uuid.Nil {
		return 0, fmt.Errorf("%w: workspace id is required", ErrValidation)
	}
	if s.deleter == nil {
		// No backend to tier blobs out of — pruning the row without deleting the
		// blob would orphan storage, so refuse rather than lie. Reported as a
		// no-op so the sweep over many workspaces is unaffected.
		return 0, nil
	}
	days, err := s.EffectiveRetentionDays(ctx, workspaceID, defaultDays)
	if err != nil {
		return 0, err
	}
	if days <= 0 {
		return 0, nil // retain indefinitely
	}
	if limit <= 0 {
		limit = 100
	}
	cutoff := s.now().UTC().Add(-time.Duration(days) * 24 * time.Hour)

	var expired []models.SessionRecording
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND blob_pruned = ? AND ended_at IS NOT NULL AND ended_at < ?",
			workspaceID, false, cutoff).
		Order("ended_at ASC").
		Limit(limit).
		Find(&expired).Error; err != nil {
		return 0, fmt.Errorf("recordings: list expired recordings: %w", err)
	}

	pruned := 0
	for i := range expired {
		if err := ctx.Err(); err != nil {
			return pruned, err
		}
		if err := s.pruneOne(ctx, expired[i]); err != nil {
			// Fail-open: skip this recording, keep tiering the rest. It is retried
			// next sweep (still matches the cutoff until its blob is gone).
			continue
		}
		pruned++
	}
	if pruned > 0 && s.metrics != nil {
		s.metrics.AddRecordingsPruned(pruned)
	}
	return pruned, nil
}

// pruneOne tiers a single recording: delete the blob first, then atomically
// mark the row pruned and append the audit event. Ordering matters — deleting
// the blob before the row update means a crash between the two leaves the row
// un-pruned (so the next sweep retries the idempotent delete), never a row that
// claims pruned while the blob lingers.
func (s *Service) pruneOne(ctx context.Context, rec models.SessionRecording) error {
	if err := s.deleter.DeleteReplay(ctx, rec.SessionID.String()); err != nil {
		return fmt.Errorf("recordings: delete blob for session %s: %w", rec.SessionID, err)
	}
	now := s.now().UTC()
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.SessionRecording{}).
			Where("workspace_id = ? AND session_id = ? AND blob_pruned = ?", rec.WorkspaceID, rec.SessionID, false).
			Updates(map[string]any{
				"blob_pruned":    true,
				"blob_pruned_at": &now,
				"updated_at":     now,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			// Another sweep pruned it first; the blob delete above was idempotent,
			// so just skip the audit append (the winner wrote it).
			return nil
		}
		md, err := pruneAuditMetadata(rec, now)
		if err != nil {
			return err
		}
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: rec.WorkspaceID,
			Actor:       retentionPruneActor,
			Action:      recordingPrunedAuditAction,
			TargetRef:   rec.SessionID.String(),
			Metadata:    md,
		})
	})
}

// pruneAuditMetadata builds the tier-out event's metadata. It records the
// session, the replay key now emptied of bytes, and the integrity digest the
// original anchor carried — so an auditor reading ONLY this event still has the
// recording's identity and SHA-256, and can see the blob was tiered (not lost).
func pruneAuditMetadata(rec models.SessionRecording, prunedAt time.Time) (datatypes.JSON, error) {
	b, err := json.Marshal(map[string]any{
		"session_id": rec.SessionID.String(),
		"replay_key": rec.ReplayKey,
		"sha256":     rec.SHA256,
		"bytes":      rec.Bytes,
		"pruned_at":  prunedAt.Format(time.RFC3339Nano),
		"reason":     "retention_policy",
	})
	if err != nil {
		return nil, fmt.Errorf("recordings: marshal prune audit metadata: %w", err)
	}
	return datatypes.JSON(b), nil
}
