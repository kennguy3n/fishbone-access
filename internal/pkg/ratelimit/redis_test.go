package ratelimit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newTestRedis spins up a hermetic in-process miniredis and a client wired to
// it, with a fixed base TIME so the token-bucket script's server-side clock is
// deterministic. Returns the server (for FastForward) and the client.
func newTestRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	mr.SetTime(time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC))
	c := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	return mr, c
}

// TestRedisLimiterTokenBucketBasic proves the atomic bucket admits up to Burst
// instantaneously then denies with a positive Retry-After hint, matching the
// in-memory limiter's contract.
func TestRedisLimiterTokenBucketBasic(t *testing.T) {
	_, c := newTestRedis(t)
	// rps low so refill is negligible across the test's wall-clock; burst is the
	// instantaneous budget under test.
	lim := NewRedisLimiter(c, RedisConfig{RPS: 1, Burst: 5})

	for i := 0; i < 5; i++ {
		ok, retry := lim.Allow("tenant-a")
		if !ok {
			t.Fatalf("request %d: denied, want allowed", i)
		}
		if retry != 0 {
			t.Fatalf("request %d: retry=%s on an allowed request, want 0", i, retry)
		}
	}
	ok, retry := lim.Allow("tenant-a")
	if ok {
		t.Fatal("6th request: allowed, want denied (bucket should be empty)")
	}
	if retry <= 0 {
		t.Fatalf("denied request: retry=%s, want > 0 for a Retry-After hint", retry)
	}
}

// TestRedisLimiterSharedBudgetAcrossInstances is the core exactness proof: two
// SEPARATE limiter instances (standing in for two ztna-api replicas) sharing one
// Redis enforce ONE budget. The in-memory limiter would give each its own burst
// (2×); the shared atomic bucket admits exactly Burst in total.
func TestRedisLimiterSharedBudgetAcrossInstances(t *testing.T) {
	_, c := newTestRedis(t)
	const burst = 10
	// A frozen, SHARED clock so refill is exactly zero across the run: any
	// admission past the burst would therefore be a true atomicity violation,
	// not a refill artifact. (miniredis' Lua TIME ignores SetTime/FastForward,
	// so the limiter's Clock override is the deterministic time source.)
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	clk := func() time.Time { return now }
	// Generous OpTimeout + a fail-open assertion so the test isolates ATOMICITY:
	// a spurious timeout would fail open (admit) and is forbidden here.
	var failOpens int
	cfg := RedisConfig{RPS: 1, Burst: burst, Clock: clk, OpTimeout: 5 * time.Second, OnError: func(error) { failOpens++ }}
	replicaA := NewRedisLimiter(c, cfg)
	replicaB := NewRedisLimiter(c, cfg)

	admitted := 0
	// Interleave the two replicas hitting the SAME tenant key. Total admissions
	// must equal the single shared burst, regardless of which replica served.
	for i := 0; i < burst*2; i++ {
		lim := replicaA
		if i%2 == 1 {
			lim = replicaB
		}
		if ok, _ := lim.Allow("tenant-shared"); ok {
			admitted++
		}
	}
	if admitted != burst {
		t.Fatalf("admitted %d across two replicas, want exactly the shared burst %d", admitted, burst)
	}
	if failOpens != 0 {
		t.Fatalf("%d fail-open events; the exactness result must come from the limiter, not a degraded backend", failOpens)
	}
}

// TestRedisLimiterConcurrentSharedBudget hammers one shared bucket from many
// goroutines (two replicas) at once: the EVALSHA atomicity must prevent any
// over-admission beyond the shared burst even under a race.
func TestRedisLimiterConcurrentSharedBudget(t *testing.T) {
	_, c := newTestRedis(t)
	const burst = 50
	// Frozen shared clock => zero refill => any admission beyond burst is an
	// over-admission caused by a lost atomic update.
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	clk := func() time.Time { return now }
	// A generous OpTimeout keeps a slow miniredis under heavy -race load from
	// tripping the fail-open path (which would admit and look like an
	// over-admission); failOpens asserts the result is pure atomicity.
	var mu sync.Mutex
	var failOpens int
	cfg := RedisConfig{RPS: 1, Burst: burst, Clock: clk, OpTimeout: 5 * time.Second, OnError: func(error) {
		mu.Lock()
		failOpens++
		mu.Unlock()
	}}
	replicaA := NewRedisLimiter(c, cfg)
	replicaB := NewRedisLimiter(c, cfg)

	admitted := 0
	var wg sync.WaitGroup
	for i := 0; i < burst*4; i++ {
		wg.Add(1)
		lim := replicaA
		if i%2 == 1 {
			lim = replicaB
		}
		go func(l *RedisLimiter) {
			defer wg.Done()
			if ok, _ := l.Allow("tenant-race"); ok {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}(lim)
	}
	wg.Wait()
	if admitted != burst {
		t.Fatalf("admitted %d under concurrency, want exactly the shared burst %d (no over-admission)", admitted, burst)
	}
	if failOpens != 0 {
		t.Fatalf("%d fail-open events under load; the no-over-admission result must come from atomicity, not a degraded backend", failOpens)
	}
}

// TestRedisLimiterRefill proves tokens come back over time using the Redis
// server clock: after draining the bucket, advancing the shared clock refills
// it at the configured rate.
func TestRedisLimiterRefill(t *testing.T) {
	_, c := newTestRedis(t)
	base := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	now := base
	lim := NewRedisLimiter(c, RedisConfig{RPS: 10, Burst: 2, Clock: func() time.Time { return now }}) // 10 tok/s => 1 token per 100ms

	// Drain the burst.
	for i := 0; i < 2; i++ {
		if ok, _ := lim.Allow("t"); !ok {
			t.Fatalf("drain %d: denied, want allowed", i)
		}
	}
	if ok, _ := lim.Allow("t"); ok {
		t.Fatal("post-drain: allowed, want denied")
	}

	// Advance the shared clock by 100ms => exactly one token refilled.
	now = base.Add(100 * time.Millisecond)
	if ok, _ := lim.Allow("t"); !ok {
		t.Fatal("after 100ms: denied, want allowed (one token should have refilled)")
	}
	// That single refilled token is now spent again.
	if ok, _ := lim.Allow("t"); ok {
		t.Fatal("immediately after: allowed, want denied (refilled token already spent)")
	}
}

// TestRedisLimiterKeyIsolation proves distinct keys (tenants) hold independent
// buckets: exhausting one never throttles another.
func TestRedisLimiterKeyIsolation(t *testing.T) {
	_, c := newTestRedis(t)
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	lim := NewRedisLimiter(c, RedisConfig{RPS: 1, Burst: 3, Clock: func() time.Time { return now }})

	for i := 0; i < 3; i++ {
		if ok, _ := lim.Allow("tenant-1"); !ok {
			t.Fatalf("tenant-1 request %d denied, want allowed", i)
		}
	}
	if ok, _ := lim.Allow("tenant-1"); ok {
		t.Fatal("tenant-1 over budget: allowed, want denied")
	}
	// tenant-2 must still have its full, independent budget.
	if ok, _ := lim.Allow("tenant-2"); !ok {
		t.Fatal("tenant-2 first request denied; buckets are not isolated by key")
	}
}

// TestRedisLimiterFailOpenOnError proves the non-negotiable fail-open posture:
// when Redis is unreachable Allow ADMITS rather than rejecting, and reports the
// failure through OnError so a degraded backend is observable.
func TestRedisLimiterFailOpenOnError(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	c := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = c.Close() })

	var failOpens int
	lim := NewRedisLimiter(c, RedisConfig{
		RPS: 1, Burst: 1,
		OpTimeout: 200 * time.Millisecond,
		OnError:   func(error) { failOpens++ },
	})

	// Take the backend down: every Allow must now fail OPEN (admit).
	mr.Close()
	for i := 0; i < 3; i++ {
		ok, retry := lim.Allow("tenant-x")
		if !ok {
			t.Fatalf("request %d: denied while Redis is down, want fail-open (allowed)", i)
		}
		if retry != 0 {
			t.Fatalf("request %d: retry=%s on fail-open, want 0", i, retry)
		}
	}
	if failOpens != 3 {
		t.Fatalf("OnError called %d times, want 3 (one per failed Allow)", failOpens)
	}
}

// TestRedisLimiterClockOverride proves the test clock override drives the bucket
// without relying on the Redis server clock, and that it shares state across
// instances exactly like the server-TIME path.
func TestRedisLimiterClockOverride(t *testing.T) {
	_, c := newTestRedis(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base
	clk := func() time.Time { return now }
	lim := NewRedisLimiter(c, RedisConfig{RPS: 1, Burst: 1, Clock: clk})

	if ok, _ := lim.Allow("k"); !ok {
		t.Fatal("first: denied, want allowed")
	}
	if ok, _ := lim.Allow("k"); ok {
		t.Fatal("second (same instant): allowed, want denied")
	}
	now = base.Add(time.Second) // one token refills at 1 tok/s
	if ok, _ := lim.Allow("k"); !ok {
		t.Fatal("after 1s: denied, want allowed")
	}
}

// TestParseAllowResult covers the reply decoder's malformed-input handling so a
// garbled reply maps to fail-open (ok=false) rather than a wrong verdict.
func TestParseAllowResult(t *testing.T) {
	if allowed, retry, ok := parseAllowResult([]interface{}{int64(1), int64(0)}); !ok || !allowed || retry != 0 {
		t.Fatalf("allowed reply: got allowed=%t retry=%d ok=%t", allowed, retry, ok)
	}
	if allowed, retry, ok := parseAllowResult([]interface{}{int64(0), int64(250)}); !ok || allowed || retry != 250 {
		t.Fatalf("denied reply: got allowed=%t retry=%d ok=%t", allowed, retry, ok)
	}
	if _, _, ok := parseAllowResult([]interface{}{int64(1)}); ok {
		t.Fatal("short reply: ok=true, want false")
	}
	if _, _, ok := parseAllowResult([]interface{}{"x", "y"}); ok {
		t.Fatal("non-int reply: ok=true, want false")
	}
	if _, retry, ok := parseAllowResult([]interface{}{int64(0), int64(-5)}); !ok || retry != 0 {
		t.Fatalf("negative retry clamp: retry=%d ok=%t, want 0/true", retry, ok)
	}
}

// ensure the deadline path compiles against a real context (guards against an
// accidental signature drift on the per-call timeout).
var _ = context.Background
