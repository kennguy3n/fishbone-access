package lifecycle

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestCanonicalAuditMetadataStableUnderReorder verifies that the canonical
// metadata form is invariant to object-key order and insignificant whitespace.
// This is the in-process guard for the audit-chain invariant exercised end-to-
// end against Postgres jsonb in TestEvidenceStreamChainPostgres: two encodings
// of the same JSON value MUST hash identically, or a chain written with one and
// verified after a jsonb round-trip (which reorders keys) would falsely report
// tampering.
func TestCanonicalAuditMetadataStableUnderReorder(t *testing.T) {
	a := []byte(`{"zeta":"z","alpha":1,"nested":{"y":2,"x":1},"list":[3,2,1]}`)
	b := []byte(`{  "alpha": 1,"nested":{"x":1,"y":2}, "list":[3,2,1],  "zeta":"z"  }`)

	ca, cb := CanonicalAuditMetadata(a), CanonicalAuditMetadata(b)
	if !bytes.Equal(ca, cb) {
		t.Fatalf("canonical forms differ:\n a=%s\n b=%s", ca, cb)
	}
	if string(ca) != `{"alpha":1,"list":[3,2,1],"nested":{"x":1,"y":2},"zeta":"z"}` {
		t.Fatalf("unexpected canonical form: %s", ca)
	}
}

// TestCanonicalAuditMetadataIdempotent verifies canonicalization is a fixed
// point: re-canonicalizing already-canonical bytes (what the verifier does to
// the value read back from jsonb) yields the same bytes folded into the hash at
// append time.
func TestCanonicalAuditMetadataIdempotent(t *testing.T) {
	once := CanonicalAuditMetadata([]byte(`{"b":2,"a":1}`))
	twice := CanonicalAuditMetadata(once)
	if !bytes.Equal(once, twice) {
		t.Fatalf("canonicalization not idempotent: %s != %s", once, twice)
	}
}

// TestCanonicalAuditMetadataEmpty maps empty/whitespace-only input to nil so a
// missing metadata column hashes identically to an explicit empty value.
func TestCanonicalAuditMetadataEmpty(t *testing.T) {
	for _, in := range [][]byte{nil, {}, []byte("   "), []byte("\n\t")} {
		if got := CanonicalAuditMetadata(in); got != nil {
			t.Fatalf("expected nil for empty input %q, got %q", in, got)
		}
	}
}

// TestComputeChainHashTruncatesTimestamp confirms the hash is invariant to
// sub-microsecond clock precision, matching what Postgres timestamptz persists.
func TestComputeChainHashTruncatesTimestamp(t *testing.T) {
	ws := uuid.New()
	base := time.Unix(1700000000, 123456000).UTC() // exact microseconds
	withNanos := base.Add(789 * time.Nanosecond)    // sub-microsecond jitter

	h1 := ComputeChainHash("", ws, "access_grant.created", "t", []byte(`{"a":1}`), base)
	h2 := ComputeChainHash("", ws, "access_grant.created", "t", []byte(`{"a":1}`), withNanos)
	if h1 != h2 {
		t.Fatalf("hash changed under sub-microsecond jitter: %s != %s", h1, h2)
	}
}
