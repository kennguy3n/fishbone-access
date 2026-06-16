package broker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// newTestDirectory builds a GORM-backed session directory over the shared
// in-memory test DB with a controllable clock.
func newTestDirectory(t *testing.T, now *time.Time, staleAfter time.Duration) *GormSessionDirectory {
	t.Helper()
	db := newTestDB(t)
	d := NewGormSessionDirectory(db, staleAfter)
	d.SetClock(func() time.Time { return *now })
	return d
}

func TestSessionDirectoryClaimRefreshRelease(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d := newTestDirectory(t, &now, time.Minute)
	ws, agent := uuid.New(), uuid.New()

	epoch, err := d.Claim(ctx, ws, agent, "node-a", "10.0.0.1:7444")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if epoch != 1 {
		t.Fatalf("first claim epoch = %d, want 1", epoch)
	}

	entry, fresh, err := d.Lookup(ctx, ws, agent)
	if err != nil || entry == nil {
		t.Fatalf("lookup: entry=%v fresh=%v err=%v", entry, fresh, err)
	}
	if !fresh || entry.NodeID != "node-a" || entry.ForwardAddr != "10.0.0.1:7444" || entry.Epoch != 1 {
		t.Fatalf("unexpected entry %+v fresh=%v", entry, fresh)
	}

	// Refresh by the holder bumps last-seen and keeps it fresh after the window.
	now = now.Add(50 * time.Second)
	if err := d.Refresh(ctx, ws, agent, "node-a", 1); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	now = now.Add(50 * time.Second) // 100s since claim, 50s since refresh
	if _, fresh, _ := d.Lookup(ctx, ws, agent); !fresh {
		t.Fatalf("entry should be fresh 50s after refresh with 60s window")
	}

	if err := d.Release(ctx, ws, agent, "node-a", 1); err != nil {
		t.Fatalf("release: %v", err)
	}
	if entry, _, _ := d.Lookup(ctx, ws, agent); entry != nil {
		t.Fatalf("entry should be gone after release, got %+v", entry)
	}
}

// TestSessionDirectoryTakeoverByEpoch proves a reconnect to another replica
// takes over ownership (epoch bump), and the superseded owner's refresh/release
// become no-ops so it cannot clobber or delete the new owner's claim.
func TestSessionDirectoryTakeoverByEpoch(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d := newTestDirectory(t, &now, time.Minute)
	ws, agent := uuid.New(), uuid.New()

	e1, err := d.Claim(ctx, ws, agent, "node-a", "a:7444")
	if err != nil {
		t.Fatalf("claim A: %v", err)
	}
	e2, err := d.Claim(ctx, ws, agent, "node-b", "b:7444")
	if err != nil {
		t.Fatalf("claim B: %v", err)
	}
	if e2 <= e1 {
		t.Fatalf("takeover epoch %d must exceed prior %d", e2, e1)
	}

	// Owner is now B.
	entry, _, _ := d.Lookup(ctx, ws, agent)
	if entry == nil || entry.NodeID != "node-b" || entry.Epoch != e2 {
		t.Fatalf("owner should be node-b@%d, got %+v", e2, entry)
	}

	// A's stale refresh is rejected and must not change the row.
	if err := d.Refresh(ctx, ws, agent, "node-a", e1); !errors.Is(err, ErrOwnershipLost) {
		t.Fatalf("stale refresh: want ErrOwnershipLost, got %v", err)
	}
	// A's stale release must not delete B's claim.
	if err := d.Release(ctx, ws, agent, "node-a", e1); err != nil {
		t.Fatalf("stale release: %v", err)
	}
	if entry, _, _ := d.Lookup(ctx, ws, agent); entry == nil || entry.NodeID != "node-b" {
		t.Fatalf("B's claim must survive A's stale release, got %+v", entry)
	}
}

func TestSessionDirectoryStaleness(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d := newTestDirectory(t, &now, time.Minute)
	ws, agent := uuid.New(), uuid.New()

	if _, err := d.Claim(ctx, ws, agent, "node-a", "a:7444"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	now = now.Add(2 * time.Minute) // crash: no heartbeat past the window

	entry, fresh, err := d.Lookup(ctx, ws, agent)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if entry == nil {
		t.Fatalf("row still present, just stale")
	}
	if fresh {
		t.Fatalf("entry should be stale 2m after claim with 60s window")
	}
	if ok, _ := d.IsOnline(ctx, ws, agent); ok {
		t.Fatalf("IsOnline should be false for a stale owner")
	}
	if n, _ := d.OnlineCount(ctx, ws); n != 0 {
		t.Fatalf("OnlineCount = %d, want 0 for stale owner", n)
	}
}

func TestSessionDirectoryOnlineCount(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d := newTestDirectory(t, &now, time.Minute)
	ws := uuid.New()
	other := uuid.New()

	for i := 0; i < 3; i++ {
		if _, err := d.Claim(ctx, ws, uuid.New(), "node-a", "a:7444"); err != nil {
			t.Fatalf("claim %d: %v", i, err)
		}
	}
	if _, err := d.Claim(ctx, other, uuid.New(), "node-a", "a:7444"); err != nil {
		t.Fatalf("claim other ws: %v", err)
	}

	if n, _ := d.OnlineCount(ctx, ws); n != 3 {
		t.Fatalf("OnlineCount(ws) = %d, want 3", n)
	}
	if n, _ := d.OnlineCount(ctx, other); n != 1 {
		t.Fatalf("OnlineCount(other) = %d, want 1", n)
	}
}
