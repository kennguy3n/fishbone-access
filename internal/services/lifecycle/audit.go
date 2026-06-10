package lifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/auditchain"
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

// lockWorkspace takes a transaction-scoped Postgres advisory lock keyed on the
// workspace id, serializing the holders of this single per-workspace key. It
// underpins two invariants:
//
//   - Audit-chain integrity: without it, two concurrent transactions at READ
//     COMMITTED could both read the same chain head and fork the hash chain
//     (see appendAudit).
//   - Promotion serialization: two different drafts promoted concurrently each
//     only FOR UPDATE-lock their own row, so neither sees the other as it
//     re-scans conflicts — a grant/deny pair could both go active. Taking this
//     lock at the top of Promote forces promotions in a workspace to run one at
//     a time, so the second promotion's re-scan sees the first as ACTIVE.
//
// pg_advisory_xact_lock is reentrant within a transaction, so a Promote that
// has already taken the lock and then calls appendAudit (which takes it again)
// is harmless. The lock is released automatically when the tx commits or rolls
// back. On non-Postgres dialects (e.g. the SQLite test path, which serializes
// writers with a single global write lock) this is a no-op.
func lockWorkspace(ctx context.Context, tx *gorm.DB, workspaceID uuid.UUID) error {
	if tx.Dialector == nil || tx.Name() != "postgres" {
		return nil
	}
	key := auditchain.LockKey(workspaceID)
	if err := tx.WithContext(ctx).Exec("SELECT pg_advisory_xact_lock(?)", key).Error; err != nil {
		return fmt.Errorf("lifecycle: lock workspace: %w", err)
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

// AuditInput is the stable, cross-package description of an action to append to
// a workspace's tamper-evident audit hash chain. It is the public face of the
// internal auditEntry so other services (e.g. the Session 1D PAM gateway) write
// into the SAME per-workspace chain — same audit_events table, same SHA-256
// linking, same per-workspace advisory lock — rather than inventing a parallel
// one. The chain bookkeeping (prev/chain hash, sequence, timestamps, id) is
// filled in by the appender.
type AuditInput struct {
	WorkspaceID uuid.UUID
	Actor       string
	Action      string
	TargetRef   string
	Metadata    datatypes.JSON
}

// AppendAuditTx appends one audit event to the workspace's hash chain inside an
// existing transaction. Callers that mutate other rows in the same tx use this
// so the state change and its audit record commit atomically (the 1C services
// do this via the internal appendAudit; PAM uses this exported entrypoint).
func AppendAuditTx(ctx context.Context, tx *gorm.DB, now time.Time, in AuditInput) error {
	return appendAudit(ctx, tx, now, auditEntry(in))
}

// AppendAudit opens its own transaction and appends one audit event to the
// workspace's hash chain. It is the convenience entrypoint for callers (e.g.
// the PAM gateway recording a session lifecycle event) that have no other
// writes to bundle into the same transaction. The transaction boundary keeps
// the chain-head read and the row insert atomic so concurrent appends cannot
// fork the chain.
func AppendAudit(ctx context.Context, db *gorm.DB, now time.Time, in AuditInput) error {
	if db == nil {
		return fmt.Errorf("%w: audit append requires a database handle", ErrValidation)
	}
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return appendAudit(ctx, tx, now, auditEntry(in))
	})
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

	// Normalise the timestamp to UTC microseconds BEFORE it is folded into the
	// hash AND stored, so the chain stays recomputable by a read-only verifier.
	// Postgres timestamptz preserves only microseconds, so hashing the raw
	// nanosecond clock while storing a truncated created_at would make every
	// legitimately-stored row fail a recompute check. Truncating here keeps the
	// hashed timestamp identical to the persisted one on every dialect.
	now = now.UTC().Truncate(time.Microsecond)

	// Serialize concurrent appends in this workspace so the read-head/insert
	// pair below is atomic and the chain cannot fork (see lockWorkspace).
	if err := lockWorkspace(ctx, tx, e.WorkspaceID); err != nil {
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

	// Canonicalize the metadata to a stable byte form BEFORE it is both hashed
	// and persisted. The audit_events.metadata column is jsonb, and Postgres
	// jsonb does NOT preserve the input byte representation — it reorders object
	// keys and rewrites whitespace/number formatting on the way in. Hashing the
	// caller's raw bytes while storing jsonb would therefore make every row that
	// carries non-trivial metadata fail to recompute on read-back (the verifier
	// would re-serialize a differently-ordered object). Folding the canonical
	// form into both the hash AND the stored row makes the pre-image identical at
	// append and verify time, independent of jsonb's internal normalization.
	//
	// This GORM path stamps ChainHashVersion = AuditHashVersion (canonical,
	// microsecond-truncated, fully recomputable). The pgx audit backend
	// (internal/pkg/database) links into the SAME per-workspace chain via the
	// shared auditchain.LockKey + prev_hash, but writes version-0 rows with
	// auditchain.Hash; the verifier accepts those on linkage alone, so the two
	// backends coexist on one chain without false tamper reports.
	canonMeta := canonicalJSON(e.Metadata)
	chainHash := ComputeChainHash(prevHash, e.WorkspaceID, e.Action, e.TargetRef, canonMeta, now)

	stored := e.Metadata
	if len(canonMeta) > 0 {
		stored = datatypes.JSON(canonMeta)
	}
	row := &models.AuditEvent{
		WorkspaceID: e.WorkspaceID,
		ChainSeq:    prevSeq + 1,
		Actor:       e.Actor,
		Action:      e.Action,
		TargetRef:   e.TargetRef,
		Metadata:    stored,
		PrevHash:    prevHash,
		ChainHash:   chainHash,
		// Stamp the format the pre-image above used so the verifier never has to
		// guess; every freshly appended row is canonical and fully recomputable.
		ChainHashVersion: AuditHashVersion,
	}
	row.CreatedAt = now
	row.UpdatedAt = now
	if err := tx.WithContext(ctx).Create(row).Error; err != nil {
		return fmt.Errorf("lifecycle: insert audit event: %w", err)
	}
	return nil
}

// AuditHashVersion is the pre-image format the current appender stamps on every
// audit row it writes. It lets a read-only verifier select the rule that
// recomputes a given row instead of assuming one global formula forever:
//
//	0 — legacy / pre-canonical: the pre-image folded the raw nanosecond wall
//	    clock (now.UnixNano()) and the caller's raw metadata bytes. Neither is
//	    recoverable from stored columns — Postgres timestamptz keeps only
//	    microseconds and jsonb reorders metadata on read-back — so version-0 rows
//	    are NOT recomputable and are validated by chain linkage only.
//	1 — canonical: the pre-image truncates the timestamp to UTC microseconds (the
//	    precision Postgres persists) and folds canonical-JSON metadata, so the row
//	    recomputes byte-for-byte from its stored columns on every dialect.
//
// When this constant advances, ComputeChainHash and the compliance verifier must
// branch per version so older canonical rows keep verifying under their own rule.
const AuditHashVersion = 1

// ComputeChainHash derives the SHA-256 chain hash for one audit event from its
// linking pre-image:
//
//	SHA256(prevHash \n workspace \n action \n targetRef \n metadata \n ts_unixnano)
//
// It is the single source of truth for the pre-image so the appender and any
// read-only verifier (the compliance evidence stream) can never drift. Callers
// MUST pass the canonical metadata bytes (see CanonicalAuditMetadata) and a
// timestamp; the timestamp is truncated to UTC microseconds here so the hashed
// value matches what Postgres timestamptz persists (it keeps only microseconds).
func ComputeChainHash(prevHash string, workspaceID uuid.UUID, action, targetRef string, metadata []byte, ts time.Time) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n%s\n%s\n%d",
		prevHash, workspaceID, action, targetRef, string(metadata),
		ts.UTC().Truncate(time.Microsecond).UnixNano())
	return hex.EncodeToString(h.Sum(nil))
}

// CanonicalAuditMetadata returns a stable, canonical JSON encoding of raw so the
// audit chain hash is invariant under the jsonb round-trip (Postgres reorders
// object keys and rewrites whitespace/number formatting when it stores jsonb).
// Re-canonicalizing the bytes read back from jsonb reproduces this exact form,
// because Go's json.Marshal emits object keys in sorted order with no
// insignificant whitespace. Empty/whitespace-only input maps to nil so a missing
// metadata column hashes identically to an explicit empty value.
func CanonicalAuditMetadata(raw []byte) []byte { return canonicalJSON(raw) }

func canonicalJSON(raw []byte) []byte {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		// Not valid JSON: fall back to the raw bytes so a (malformed) value still
		// hashes deterministically rather than silently dropping it.
		return raw
	}
	canon, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return canon
}
