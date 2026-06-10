// Package auditchain holds the two pure, backend-independent primitives that
// define a workspace's tamper-evident audit hash chain: the per-event chain
// hash and the per-workspace advisory-lock key.
//
// They live in their own leaf package (no database dependency) so that every
// backend computes them identically. The GORM appender in
// internal/services/lifecycle and the pgxpool appender in
// internal/pkg/database both call these functions, which is what lets the two
// implementations interleave appends to the same chain — a pgxpool standalone
// append and an in-flight GORM-transaction append in the same workspace
// serialize on the same advisory key and produce byte-identical hashes. If
// either primitive diverged between backends the chain would fork, so keeping
// them here, shared and untyped to any ORM, is load-bearing for the GORM→pgx
// migration.
package auditchain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// HashVersion is the pre-image format every backend stamps on the audit rows it
// writes today. It lets a read-only verifier select the rule that recomputes a
// given row instead of assuming one global formula forever:
//
//	0 — legacy / pre-canonical (see Hash): the pre-image folded the raw
//	    nanosecond wall clock and the caller's raw metadata bytes. Neither is
//	    recoverable from stored columns — Postgres timestamptz keeps only
//	    microseconds and jsonb reorders metadata on read-back — so version-0 rows
//	    are NOT recomputable and are validated by chain linkage only.
//	1 — canonical (see CanonicalHash): the pre-image truncates the timestamp to
//	    UTC microseconds (the precision Postgres persists) and folds canonical-
//	    JSON metadata, so the row recomputes byte-for-byte from its stored
//	    columns on every dialect and through both the GORM and pgx backends.
//
// When this constant advances, CanonicalHash and the compliance verifier must
// branch per version so older canonical rows keep verifying under their own rule.
const HashVersion = 1

// lockNamespace salts the per-workspace advisory-lock key so it can never
// collide with the migration runner's advisory lock (which uses a different
// fixed key). The literal value must never change, or a process holding the
// old key would stop serializing against one holding the new key. The
// "AUDITCHA" bytes are just the mnemonic origin of the constant.
const lockNamespace uint64 = 0x4155_4449_5443_4841 // bytes "AUDITCHA"

// Hash returns the SHA-256 chain hash of one audit event, linking it to the
// previous head:
//
//	chain_hash = SHA256(prev_hash \n workspace \n action \n target \n metadata \n ts_unixnano)
//
// The first event in a workspace has an empty prevHash. metadata is the raw
// JSON bytes exactly as they will be stored; ts is hashed at nanosecond
// resolution. The field order and separators are part of the on-disk contract
// — changing them rewrites every chain — so this is the single definition both
// backends share.
func Hash(prevHash string, workspaceID uuid.UUID, action, targetRef string, metadata []byte, ts time.Time) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n%s\n%s\n%d",
		prevHash, workspaceID, action, targetRef, string(metadata), ts.UnixNano())
	return hex.EncodeToString(h.Sum(nil))
}

// CanonicalHash returns the version-1 (canonical) SHA-256 chain hash of one
// audit event:
//
//	chain_hash = SHA256(prev_hash \n workspace \n action \n target \n metadata \n ts_unixnano)
//
// It shares the field order and separators of the legacy Hash above — the
// on-disk contract — but differs in two deliberate ways that make a version-1
// row recompute byte-for-byte from its stored columns:
//
//   - ts is truncated to UTC microseconds, the precision Postgres timestamptz
//     persists, so the hashed instant equals the stored created_at on every
//     dialect (hashing the raw nanosecond clock would never recompute).
//   - metadata MUST be the canonical-JSON bytes (CanonicalMetadata), which is
//     also what is stored, so the pre-image is invariant under jsonb's key
//     reordering and whitespace rewriting on read-back.
//
// Callers pass the canonical metadata; the timestamp may be passed either raw
// or already truncated. Appenders pre-truncate now to UTC microseconds because
// they also store that value in created_at/updated_at, and this function
// truncates again defensively (the operation is idempotent) so a caller that
// forgets cannot hash a finer instant than it stores. This is the single source
// of truth for the version-1 pre-image shared by the GORM appender
// (internal/services/lifecycle), the pgx appender (internal/pkg/database), and
// the read-only compliance verifier, so the three can never drift.
func CanonicalHash(prevHash string, workspaceID uuid.UUID, action, targetRef string, canonicalMetadata []byte, ts time.Time) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n%s\n%s\n%d",
		prevHash, workspaceID, action, targetRef, string(canonicalMetadata),
		ts.UTC().Truncate(time.Microsecond).UnixNano())
	return hex.EncodeToString(h.Sum(nil))
}

// CanonicalMetadata returns a stable, canonical JSON encoding of raw so the
// audit chain hash is invariant under the jsonb round-trip (Postgres reorders
// object keys and rewrites whitespace/number formatting when it stores jsonb).
// Re-canonicalizing the bytes read back from jsonb reproduces this exact form,
// because Go's json.Marshal emits object keys in sorted order with no
// insignificant whitespace. Empty/whitespace-only input maps to nil so a missing
// metadata column hashes identically to an explicit empty value. Input that is
// not valid JSON is returned unchanged so a (malformed) value still hashes
// deterministically rather than being silently dropped.
func CanonicalMetadata(raw []byte) []byte {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	canon, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return canon
}

// LockKey derives the int64 key for pg_advisory_xact_lock that serializes all
// audit appends (and policy promotions) within a single workspace. Folding the
// first 8 bytes of the workspace UUID with the namespace gives a stable,
// well-distributed key; two callers in the same workspace always compute the
// same value regardless of which database backend they use.
func LockKey(workspaceID uuid.UUID) int64 {
	return int64(binary.BigEndian.Uint64(workspaceID[:8]) ^ lockNamespace)
}
