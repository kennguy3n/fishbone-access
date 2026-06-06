package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// auditChainLockNamespace salts the per-workspace advisory-lock key so it can
// never collide with the migration runner's advisory lock (which uses a
// different fixed key).
const auditChainLockNamespace uint64 = 0x4155_4449_5443_4841 // "AUDITCHA"

// lockAuditChain serializes audit appends per workspace on Postgres by taking a
// transaction-scoped advisory lock keyed on the workspace id. Without it, two
// concurrent transactions at READ COMMITTED could both read the same chain head
// and fork the hash chain. The lock is released automatically when tx commits
// or rolls back. On non-Postgres dialects (e.g. the SQLite test path, which
// serializes writers with a single global write lock) this is a no-op.
func lockAuditChain(ctx context.Context, tx *gorm.DB, workspaceID uuid.UUID) error {
	if tx.Dialector == nil || tx.Name() != "postgres" {
		return nil
	}
	key := int64(binary.BigEndian.Uint64(workspaceID[:8]) ^ auditChainLockNamespace)
	if err := tx.WithContext(ctx).Exec("SELECT pg_advisory_xact_lock(?)", key).Error; err != nil {
		return fmt.Errorf("lifecycle: lock audit chain: %w", err)
	}
	return nil
}

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

	// Serialize concurrent appends in this workspace so the read-head/insert
	// pair below is atomic and the chain cannot fork (see lockAuditChain).
	if err := lockAuditChain(ctx, tx, e.WorkspaceID); err != nil {
		return err
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
