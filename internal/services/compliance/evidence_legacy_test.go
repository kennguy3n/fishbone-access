package compliance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// legacyChainHash reproduces the PRE-canonical (version 0) audit pre-image
// exactly as it existed before canonicalization: it folds the raw nanosecond wall clock and
// the caller's raw metadata bytes (no microsecond truncation, no canonical
// JSON). A row hashed this way is intentionally NOT recomputable by the current
// canonical verifier, which is the whole point of the backward-compat path.
func legacyChainHash(prevHash string, ws uuid.UUID, action, target string, rawMeta []byte, createdAt time.Time) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n%s\n%s\n%d",
		prevHash, ws, action, target, string(rawMeta), createdAt.UnixNano())
	return hex.EncodeToString(h.Sum(nil))
}

// insertLegacyRow writes a version-0 audit row directly (bypassing the appender)
// to simulate a chain that predates the canonical, recomputable hash format.
func insertLegacyRow(t *testing.T, db *gorm.DB, ws uuid.UUID, seq int64, prevHash, action, target string, rawMeta []byte, createdAt time.Time) *models.AuditEvent {
	t.Helper()
	row := &models.AuditEvent{
		WorkspaceID:      ws,
		ChainSeq:         seq,
		Actor:            "legacy",
		Action:           action,
		TargetRef:        target,
		PrevHash:         prevHash,
		ChainHash:        legacyChainHash(prevHash, ws, action, target, rawMeta, createdAt),
		ChainHashVersion: 0,
	}
	if len(rawMeta) > 0 {
		row.Metadata = datatypes.JSON(rawMeta)
	}
	row.CreatedAt = createdAt
	row.UpdatedAt = createdAt
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("insert legacy row seq %d: %v", seq, err)
	}
	return row
}

// TestVerifyChainAcceptsLegacyPrefixThenCanonical proves the backward-compat
// fix: a workspace whose chain begins with pre-canonical (version 0) audit rows
// — whose stored hashes do NOT recompute under the canonical formula — verifies
// as VALID (not a false "tampered"), the legacy rows are counted, and canonical
// rows appended afterwards still chain off them and fully recompute.
func TestVerifyChainAcceptsLegacyPrefixThenCanonical(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	ctx := context.Background()

	// A pre-canonical row with sub-microsecond nanoseconds in its timestamp and
	// non-canonical (reverse-key-order) metadata. Both of these would change the
	// recomputed hash under the canonical formula (which truncates to micros and
	// canonicalises metadata), so recomputing this row would FALSELY report it as
	// tampered. The version-0 marker is what tells the verifier to skip recompute.
	createdAt := time.Unix(1_700_000_000, 123_456_789).UTC() // 789ns past the microsecond
	legacy := insertLegacyRow(t, db, ws, 1, "", "policy.promoted", "p", []byte(`{"b":2,"a":1}`), createdAt)

	// Sanity: the canonical recompute of this row does NOT match its stored hash,
	// so without the version gate the verifier would flag it as tampered.
	if got := recomputeChainHash("", legacy); got == legacy.ChainHash {
		t.Fatalf("test setup invalid: legacy row unexpectedly recomputes under canonical formula")
	}

	// Append a canonical (version 1) row through the real appender; it chains off
	// the legacy row's stored hash and is fully recomputable.
	appendEvent(t, db, ws, "access_grant.granted", "g")

	svc := NewEvidenceService(db)
	v, err := svc.VerifyChain(ctx, ws)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !v.OK || v.Status != chainStatusValid {
		t.Fatalf("expected valid chain spanning legacy+canonical, got %+v", v)
	}
	if v.Length != 2 {
		t.Fatalf("expected length 2, got %d", v.Length)
	}
	if v.LegacyUnverified != 1 {
		t.Fatalf("expected 1 legacy-unverified row, got %d", v.LegacyUnverified)
	}

	// Tampering a CANONICAL row is still detected — the version gate only relaxes
	// recompute for legacy rows, it never blinds verification of current rows.
	if err := db.Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND chain_seq = ?", ws, int64(2)).
		Update("action", "access_grant.revoked").Error; err != nil {
		t.Fatalf("tamper canonical row: %v", err)
	}
	v2, err := svc.VerifyChain(ctx, ws)
	if err != nil {
		t.Fatalf("VerifyChain after tamper: %v", err)
	}
	if v2.OK || v2.Status != chainStatusTampered || v2.BrokenAtSeq != 2 {
		t.Fatalf("expected tampered at seq 2 after editing canonical row, got %+v", v2)
	}
}

// TestVerifyChainLegacyLinkageStillEnforced proves that legacy rows are not a
// blanket "trust me": their CONTENT is not recomputed (so an in-place content
// edit of a legacy row is intentionally not flagged), but chain LINKAGE and
// chain_seq contiguity are still enforced, so reorders/insertions/deletions in
// the legacy prefix are detected exactly like in the canonical era.
func TestVerifyChainLegacyLinkageStillEnforced(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	ctx := context.Background()
	svc := NewEvidenceService(db)

	base := time.Unix(1_700_000_000, 500).UTC()
	r1 := insertLegacyRow(t, db, ws, 1, "", "policy.promoted", "p", nil, base)
	insertLegacyRow(t, db, ws, 2, r1.ChainHash, "policy.promoted", "p", nil, base.Add(time.Second))

	v, err := svc.VerifyChain(ctx, ws)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !v.OK || v.LegacyUnverified != 2 {
		t.Fatalf("expected valid all-legacy chain with 2 legacy rows, got %+v", v)
	}

	// Editing a legacy row's content is NOT flagged (legacy rows are linkage-only,
	// by documented design — their pre-image is unrecoverable from stored columns).
	if err := db.Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND chain_seq = ?", ws, int64(1)).
		Update("target_ref", "edited").Error; err != nil {
		t.Fatalf("edit legacy content: %v", err)
	}
	if v, err = svc.VerifyChain(ctx, ws); err != nil || !v.OK {
		t.Fatalf("expected legacy content edit to remain valid (linkage-only), got %+v err=%v", v, err)
	}

	// But breaking LINKAGE on a legacy row IS detected.
	if err := db.Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND chain_seq = ?", ws, int64(2)).
		Update("prev_hash", "deadbeef").Error; err != nil {
		t.Fatalf("break legacy linkage: %v", err)
	}
	v3, err := svc.VerifyChain(ctx, ws)
	if err != nil {
		t.Fatalf("VerifyChain after linkage break: %v", err)
	}
	if v3.OK || v3.Status != chainStatusTampered || v3.BrokenAtSeq != 2 {
		t.Fatalf("expected tampered linkage at seq 2 on legacy row, got %+v", v3)
	}
}
