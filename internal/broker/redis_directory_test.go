package broker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// newDirectoryRedis spins up a hermetic in-process miniredis + client.
func newDirectoryRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	c := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	return mr, c
}

// newRedisDir builds a Redis-cached directory over a real Gorm directory with a
// shared clock so freshness is deterministic.
func newRedisDir(t *testing.T) (*RedisSessionDirectory, *GormSessionDirectory, *miniredis.Miniredis, *time.Time, uuid.UUID) {
	t.Helper()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	inner := NewGormSessionDirectory(db, 0)
	mr, c := newDirectoryRedis(t)
	now := time.Now().UTC()
	clock := func() time.Time { return now }
	inner.SetClock(clock)
	cached := NewRedisSessionDirectory(inner, c, RedisDirectoryConfig{})
	cached.SetClock(clock)
	return cached, inner, mr, &now, ws
}

// TestRedisDirectoryWriteThroughLookup proves a Claim populates the cache so a
// Lookup is served from Redis (no inner read needed) and stays correct.
func TestRedisDirectoryWriteThroughLookup(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	inner := NewGormSessionDirectory(db, 0)
	mr, c := newDirectoryRedis(t)

	cached := NewRedisSessionDirectory(inner, c, RedisDirectoryConfig{})

	agentID := uuid.New()
	if _, err := cached.Claim(ctx, ws, agentID, "node-a", "10.0.0.1:7444"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	// The key exists in Redis (write-through).
	if !mr.Exists(cached.key(ws, agentID)) {
		t.Fatalf("claim did not populate the cache")
	}
	entry, fresh, err := cached.Lookup(ctx, ws, agentID)
	if err != nil || entry == nil || !fresh {
		t.Fatalf("lookup: entry=%v fresh=%v err=%v", entry, fresh, err)
	}
	if entry.NodeID != "node-a" || entry.ForwardAddr != "10.0.0.1:7444" {
		t.Fatalf("lookup returned wrong owner: %+v", entry)
	}
}

// TestRedisDirectoryFailOpenOnOutage proves that with Redis down every call
// falls through to the authoritative directory and still returns correctly.
func TestRedisDirectoryFailOpenOnOutage(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	inner := NewGormSessionDirectory(db, 0)
	mr, c := newDirectoryRedis(t)

	var failOpens int
	cached := NewRedisSessionDirectory(inner, c, RedisDirectoryConfig{
		OnError: func(error) { failOpens++ },
	})

	agentID := uuid.New()
	if _, err := cached.Claim(ctx, ws, agentID, "node-a", "10.0.0.1:7444"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	// Kill Redis: the authoritative Postgres directory must still answer.
	mr.Close()

	entry, fresh, err := cached.Lookup(ctx, ws, agentID)
	if err != nil {
		t.Fatalf("lookup must fail open to Postgres, got err: %v", err)
	}
	if entry == nil || !fresh || entry.NodeID != "node-a" {
		t.Fatalf("fail-open lookup returned wrong result: %+v fresh=%v", entry, fresh)
	}
	if failOpens == 0 {
		t.Fatalf("expected fail-open events to be observed")
	}
}

// TestRedisDirectoryReleaseInvalidates proves Release clears the cache so a
// disconnected agent is not served from a stale entry.
func TestRedisDirectoryReleaseInvalidates(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	inner := NewGormSessionDirectory(db, 0)
	mr, c := newDirectoryRedis(t)
	cached := NewRedisSessionDirectory(inner, c, RedisDirectoryConfig{})

	agentID := uuid.New()
	epoch, err := cached.Claim(ctx, ws, agentID, "node-a", "10.0.0.1:7444")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := cached.Release(ctx, ws, agentID, "node-a", epoch); err != nil {
		t.Fatalf("release: %v", err)
	}
	if mr.Exists(cached.key(ws, agentID)) {
		t.Fatalf("release did not invalidate the cache")
	}
	entry, fresh, err := cached.Lookup(ctx, ws, agentID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if entry != nil || fresh {
		t.Fatalf("released agent must have no owner, got %+v fresh=%v", entry, fresh)
	}
}

// TestRedisDirectoryStaleEntryNotFreshFromCache proves freshness is recomputed
// from the cached last_seen: a crashed owner whose entry still sits in the cache
// is reported NOT fresh, so the cache cannot make a dead owner look alive.
func TestRedisDirectoryStaleEntryNotFreshFromCache(t *testing.T) {
	ctx := context.Background()
	cached, _, _, nowp, ws := newRedisDir(t)

	agentID := uuid.New()
	if _, err := cached.Claim(ctx, ws, agentID, "node-a", "10.0.0.1:7444"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	// Advance the clock beyond the staleness window WITHOUT a heartbeat: the
	// owner "crashed". The cache entry still exists (TTL is real time, not the
	// fake clock) but freshness must be recomputed as stale.
	*nowp = nowp.Add(2 * HealthOfflineAfter)

	entry, fresh, err := cached.Lookup(ctx, ws, agentID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if entry == nil {
		t.Fatalf("expected the (stale) entry to still resolve")
	}
	if fresh {
		t.Fatalf("crashed owner must be reported stale even from cache")
	}
}

// TestRedisDirectoryRefreshLostInvalidates proves a Refresh that lost ownership
// (another replica took over) invalidates the local cache entry.
func TestRedisDirectoryRefreshLostInvalidates(t *testing.T) {
	ctx := context.Background()
	cached, inner, mr, _, ws := newRedisDir(t)

	agentID := uuid.New()
	epoch, err := cached.Claim(ctx, ws, agentID, "node-a", "10.0.0.1:7444")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	// Another replica takes over (bumps epoch) directly on the inner directory.
	if _, err := inner.Claim(ctx, ws, agentID, "node-b", "10.0.0.2:7444"); err != nil {
		t.Fatalf("takeover claim: %v", err)
	}
	// node-a's heartbeat now loses the CAS and must invalidate its cache entry.
	if err := cached.Refresh(ctx, ws, agentID, "node-a", epoch); !errors.Is(err, ErrOwnershipLost) {
		t.Fatalf("refresh after takeover: want ErrOwnershipLost, got %v", err)
	}
	if mr.Exists(cached.key(ws, agentID)) {
		t.Fatalf("lost-ownership refresh must invalidate the cache")
	}
}
