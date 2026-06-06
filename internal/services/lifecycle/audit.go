package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// auditEntry is the high-level description of an action to record. The chain
// bookkeeping (prev/chain hash, timestamps, id) is filled in by appendAudit.
type auditEntry struct {
	WorkspaceID uuid.UUID
	Actor       string
	Action      string
	TargetRef   string
	Metadata    datatypes.JSON
}

// appendAudit writes one tamper-evident AuditEvent inside the supplied
// transaction, linking it into the workspace's SHA-256 hash chain
// (prev_hash → chain_hash). It must run inside a transaction so the read of the
// previous chain head and the insert of the new row are atomic — otherwise two
// concurrent writers in the same workspace could both read the same head and
// fork the chain.
//
// chain_hash = SHA256(prev_hash || workspace || action || target || metadata || ts).
// The first event in a workspace has an empty prev_hash.
func appendAudit(ctx context.Context, tx *gorm.DB, now time.Time, e auditEntry) error {
	if e.WorkspaceID == uuid.Nil {
		return fmt.Errorf("%w: audit event requires a workspace id", ErrValidation)
	}
	if e.Action == "" {
		return fmt.Errorf("%w: audit event requires an action", ErrValidation)
	}

	var prev models.AuditEvent
	prevHash := ""
	err := tx.WithContext(ctx).
		Where("workspace_id = ?", e.WorkspaceID).
		Order("created_at desc, id desc").
		Limit(1).
		Take(&prev).Error
	switch {
	case err == nil:
		prevHash = prev.ChainHash
	case errors.Is(err, gorm.ErrRecordNotFound):
		prevHash = ""
	default:
		return fmt.Errorf("lifecycle: read audit chain head: %w", err)
	}

	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n%s\n%s\n%d",
		prevHash, e.WorkspaceID, e.Action, e.TargetRef, string(e.Metadata), now.UnixNano())
	chainHash := hex.EncodeToString(h.Sum(nil))

	row := &models.AuditEvent{
		WorkspaceID: e.WorkspaceID,
		Actor:       e.Actor,
		Action:      e.Action,
		TargetRef:   e.TargetRef,
		Metadata:    e.Metadata,
		PrevHash:    prevHash,
		ChainHash:   chainHash,
	}
	row.CreatedAt = now
	row.UpdatedAt = now
	if err := tx.WithContext(ctx).Create(row).Error; err != nil {
		return fmt.Errorf("lifecycle: insert audit event: %w", err)
	}
	return nil
}
