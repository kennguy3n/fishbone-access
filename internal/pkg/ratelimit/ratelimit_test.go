package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestAllowConsumesBurstThenDenies(t *testing.T) {
	t.Parallel()
	lim := New(Config{RPS: 1, Burst: 3})
	defer lim.Stop()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Burst of 3 → first three at the same instant succeed, the fourth is denied.
	for i := 0; i < 3; i++ {
		if ok, _ := lim.allowAt("tenant-a", base); !ok {
			t.Fatalf("request %d within burst should be allowed", i+1)
		}
	}
	ok, retry := lim.allowAt("tenant-a", base)
	if ok {
		t.Fatal("fourth request beyond burst should be denied")
	}
	// At 1 RPS the next token is ~1s out; Retry-After must be positive.
	if retry <= 0 {
		t.Fatalf("denied request should report a positive retry delay, got %s", retry)
	}
	if retry > time.Second {
		t.Fatalf("retry delay %s should be ~1s at 1 RPS", retry)
	}
}

func TestDeniedRetryDelayDoesNotConsumeToken(t *testing.T) {
	t.Parallel()
	lim := New(Config{RPS: 1, Burst: 1})
	defer lim.Stop()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if ok, _ := lim.allowAt("t", base); !ok {
		t.Fatal("first request should be allowed")
	}
	// Several denied probes must not push the recovery time further out:
	// each should report ~the same (decreasing only by elapsed time) delay.
	_, d1 := lim.allowAt("t", base)
	_, d2 := lim.allowAt("t", base)
	if d1 <= 0 || d2 <= 0 {
		t.Fatalf("denied probes should report positive delays, got %s, %s", d1, d2)
	}
	if d2 > d1 {
		t.Fatalf("repeated denied probes must not increase the delay (no token consumed): d1=%s d2=%s", d1, d2)
	}
	// After the refill window the next request is allowed again.
	if ok, _ := lim.allowAt("t", base.Add(time.Second)); !ok {
		t.Fatal("request after one refill period should be allowed")
	}
}

func TestPerKeyIsolation(t *testing.T) {
	t.Parallel()
	lim := New(Config{RPS: 1, Burst: 1})
	defer lim.Stop()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Tenant A exhausts its bucket; tenant B must be unaffected.
	if ok, _ := lim.allowAt("A", base); !ok {
		t.Fatal("A first request should be allowed")
	}
	if ok, _ := lim.allowAt("A", base); ok {
		t.Fatal("A second request should be denied")
	}
	if ok, _ := lim.allowAt("B", base); !ok {
		t.Fatal("B must have its own independent bucket")
	}
}

func TestEvictIdleBuckets(t *testing.T) {
	t.Parallel()
	lim := New(Config{RPS: 1, Burst: 1, IdleTTL: time.Minute})
	defer lim.Stop()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	lim.allowAt("stale", base)
	lim.allowAt("fresh", base.Add(90*time.Second))
	if got := lim.Len(); got != 2 {
		t.Fatalf("expected 2 live buckets, got %d", got)
	}
	// Evict relative to a now that is >TTL past "stale" but within TTL of "fresh".
	lim.evict(base.Add(2 * time.Minute))
	if got := lim.Len(); got != 1 {
		t.Fatalf("expected 1 bucket after eviction, got %d", got)
	}
	// The fresh bucket survived: probing at its last-seen instant (no refill
	// since) finds it still drained → denied. A re-created bucket would instead
	// be full and allow. The stale one being gone is harmless (a returning key
	// just gets a new full bucket).
	if ok, _ := lim.allowAt("fresh", base.Add(90*time.Second)); ok {
		t.Fatal("fresh bucket should have been retained and still drained, not recreated full")
	}
}

func TestBurstClampedToAtLeastOne(t *testing.T) {
	t.Parallel()
	lim := New(Config{RPS: 1, Burst: 0})
	defer lim.Stop()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Burst clamped to 1 → exactly one request allowed, not zero (which would
	// deadlock every tenant).
	if ok, _ := lim.allowAt("k", base); !ok {
		t.Fatal("clamped burst of 1 must allow a first request")
	}
}

func TestStopIsIdempotent(t *testing.T) {
	t.Parallel()
	lim := New(Config{RPS: 1, Burst: 1})
	lim.Stop()
	lim.Stop() // must not panic or block
}

func TestConcurrentAllowIsRaceFree(t *testing.T) {
	t.Parallel()
	lim := New(Config{RPS: 1000, Burst: 1000})
	defer lim.Stop()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := "tenant-" + time.Duration(n%5).String()
			for j := 0; j < 100; j++ {
				lim.Allow(key)
			}
		}(i)
	}
	wg.Wait()
}
