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
	"gorm.io/gorm/clause"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// forUpdate returns tx with a row-level write lock (SELECT ... FOR UPDATE) on
// Postgres so two concurrent transactions that load-then-transition the same
// row serialize instead of both reading the same state, both passing the FSM
// gate, and each writing a duplicate history/audit row. It is a no-op on
// dialects without FOR UPDATE (the SQLite test path serializes writers with a
// single global write lock, so no such race exists there).
func forUpdate(tx *gorm.DB) *gorm.DB {
	if tx.Dialector != nil && tx.Name() == "postgres" {
		return tx.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	return tx
}

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

	// Find the chain head by the monotonic per-workspace sequence rather than by
	// (created_at, id). Several audit rows are appended inside a single
	// transaction (e.g. Provision writes two state-transition events plus the
	// grant-created event), and their created_at values are not guaranteed to
	// increase in append order — the caller may pass a timestamp computed before
	// the transaction while TransitionInTx computes its own later one, and tests
	// use a fixed clock so every row shares one timestamp. Ordering by created_at
	// could therefore select a row that is not the true tail, and the next append
	// would chain off it, forking the chain and orphaning the real head. chain_seq
	// is strictly increasing in append order, so it identifies the head exactly.
	var prev models.AuditEvent
	prevHash := ""
	var prevSeq int64
	// Unscoped() so the head lookup considers ALL rows, including any that were
	// soft-deleted. AuditEvent embeds gorm.DeletedAt (via Base), so a default
	// query implicitly filters deleted_at IS NULL. Audit events are immutable and
	// must never be deleted, but were one ever soft-deleted the scoped query would
	// silently skip it, pick an earlier row as the head, and the next append would
	// chain off that — forking the SHA-256 chain and orphaning the deleted row's
	// successors. Anchoring on the true max chain_seq regardless of soft-delete
	// keeps the chain unforkable even under that (should-never-happen) condition.
	err := tx.WithContext(ctx).
		Unscoped().
		Where("workspace_id = ?", e.WorkspaceID).
		Order("chain_seq desc").
		Limit(1).
		Take(&prev).Error
	switch {
	case err == nil:
		prevHash = prev.ChainHash
		prevSeq = prev.ChainSeq
	case errors.Is(err, gorm.ErrRecordNotFound):
		prevHash = ""
		prevSeq = 0
	default:
		return fmt.Errorf("lifecycle: read audit chain head: %w", err)
	}

	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n%s\n%s\n%d",
		prevHash, e.WorkspaceID, e.Action, e.TargetRef, string(e.Metadata), now.UnixNano())
	chainHash := hex.EncodeToString(h.Sum(nil))

	row := &models.AuditEvent{
		WorkspaceID: e.WorkspaceID,
		ChainSeq:    prevSeq + 1,
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
