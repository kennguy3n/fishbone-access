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
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
)

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

// LockKey derives the int64 key for pg_advisory_xact_lock that serializes all
// audit appends (and policy promotions) within a single workspace. Folding the
// first 8 bytes of the workspace UUID with the namespace gives a stable,
// well-distributed key; two callers in the same workspace always compute the
// same value regardless of which database backend they use.
func LockKey(workspaceID uuid.UUID) int64 {
	return int64(binary.BigEndian.Uint64(workspaceID[:8]) ^ lockNamespace)
}
