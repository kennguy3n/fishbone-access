package auditchain

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCanonicalMetadata(t *testing.T) {
	// Key order and whitespace must not affect the canonical form, so a value
	// and its jsonb-reordered read-back hash identically.
	a := CanonicalMetadata([]byte(`{"b":2,"a":1}`))
	b := CanonicalMetadata([]byte(`{ "a": 1, "b": 2 }`))
	if !bytes.Equal(a, b) {
		t.Errorf("canonical metadata not order/whitespace invariant: %q vs %q", a, b)
	}
	if string(a) != `{"a":1,"b":2}` {
		t.Errorf("canonical form = %q, want sorted compact JSON", a)
	}
	// Empty / whitespace-only maps to nil so a missing column hashes like an
	// explicit empty value.
	if CanonicalMetadata(nil) != nil || CanonicalMetadata([]byte("  \n")) != nil {
		t.Error("empty metadata should canonicalize to nil")
	}
	// Invalid JSON is returned unchanged rather than dropped.
	if got := CanonicalMetadata([]byte("not json")); string(got) != "not json" {
		t.Errorf("invalid JSON should pass through unchanged, got %q", got)
	}
}

func TestCanonicalHashTimestampNormalization(t *testing.T) {
	ws := uuid.New()
	meta := CanonicalMetadata([]byte(`{"a":1}`))

	// Sub-microsecond precision and a non-UTC zone must not change the hash:
	// the canonical pre-image truncates to UTC microseconds (what Postgres
	// stores), so the row recomputes from its stored created_at.
	base := time.Date(2026, 6, 10, 15, 0, 0, 123456789, time.UTC)
	truncated := base.Truncate(time.Microsecond)
	loc := time.FixedZone("X+02", 2*60*60)

	h1 := CanonicalHash("", ws, "policy.promote", "policy/1", meta, base)
	h2 := CanonicalHash("", ws, "policy.promote", "policy/1", meta, truncated.In(loc))
	if h1 != h2 {
		t.Errorf("hash not invariant to sub-microsecond / zone: %s vs %s", h1, h2)
	}

	// Distinct prev hashes chain to distinct values (tamper-evidence).
	if CanonicalHash("prevA", ws, "a", "t", nil, truncated) ==
		CanonicalHash("prevB", ws, "a", "t", nil, truncated) {
		t.Error("hash must depend on prevHash")
	}
}

func TestLockKeyDeterministicAndDistinct(t *testing.T) {
	ws := uuid.New()
	first, second := LockKey(ws), LockKey(ws)
	if first != second {
		t.Error("LockKey must be deterministic for a workspace")
	}
	if LockKey(ws) == LockKey(uuid.New()) {
		t.Error("LockKey should differ across workspaces (collision unlikely)")
	}
}
