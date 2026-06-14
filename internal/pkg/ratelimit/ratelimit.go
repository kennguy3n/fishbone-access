// Package ratelimit provides a per-key token-bucket limiter used to cap the
// inbound request rate of a single tenant. At 5,000 tenants on a shared control
// plane the dominant operational risk is not a global flood but ONE noisy or
// runaway tenant monopolising the shared Postgres pool (and our bill) at the
// expense of the other 4,999; a per-tenant bucket isolates that blast radius
// without throttling well-behaved tenants.
//
// The limiter is in-memory and therefore per-process: with N ztna-api replicas
// a tenant's effective ceiling is N×RPS. This is the deliberate local/dev
// posture — it needs no extra infrastructure and already bounds a single
// abusive tenant to a small multiple of the configured rate. A globally exact
// limit across replicas would need a shared store (the ACCESS_REDIS_URL seam);
// this package's KeyLimiter interface is the seam a Redis-backed limiter plugs
// into later with no caller changes.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// defaultIdleTTL is how long an unused per-key bucket is retained before the
// janitor evicts it. Eviction is safe: a returning key simply gets a fresh,
// full bucket, so the only effect is bounding memory to the ACTIVE-key count
// rather than the all-time key count (which, for tenants, churns as trials come
// and go).
const defaultIdleTTL = 10 * time.Minute

// Config tunes a TenantLimiter.
type Config struct {
	// RPS is the sustained token refill rate per key (requests per second).
	RPS float64
	// Burst is the bucket depth per key: the most requests a key may make
	// instantaneously before being shaped to RPS. A single browser page load
	// fans out into several XHRs, so Burst should comfortably exceed that.
	Burst int
	// IdleTTL is how long a bucket may sit unused before eviction. Non-positive
	// uses defaultIdleTTL.
	IdleTTL time.Duration
}

type entry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// TenantLimiter is a concurrency-safe map of per-key token buckets with a
// background janitor that evicts idle buckets. It is keyed by an opaque string
// (the authoritative tenant id at the call sites here, but the type is generic).
type TenantLimiter struct {
	rps   rate.Limit
	burst int
	ttl   time.Duration
	// now is injectable so tests can drive the clock deterministically; it
	// defaults to time.Now.
	now func() time.Time

	mu      sync.Mutex
	buckets map[string]*entry

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// New builds a TenantLimiter and starts its eviction janitor. Call Stop to
// release the janitor goroutine. Burst is clamped to at least 1 so a
// misconfigured zero can never wedge every tenant at "always denied"; callers
// that want to reject a bad value loudly should validate before constructing.
func New(cfg Config) *TenantLimiter {
	burst := cfg.Burst
	if burst < 1 {
		burst = 1
	}
	ttl := cfg.IdleTTL
	if ttl <= 0 {
		ttl = defaultIdleTTL
	}
	t := &TenantLimiter{
		rps:     rate.Limit(cfg.RPS),
		burst:   burst,
		ttl:     ttl,
		now:     time.Now,
		buckets: make(map[string]*entry),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go t.janitor()
	return t
}

// Allow reports whether a request for key may proceed now, consuming one token
// when it does. When denied it returns the estimated wait until a token frees
// up, suitable for a Retry-After hint; no token is consumed on denial.
func (t *TenantLimiter) Allow(key string) (bool, time.Duration) {
	return t.allowAt(key, t.now())
}

func (t *TenantLimiter) allowAt(key string, now time.Time) (bool, time.Duration) {
	lim := t.limiterFor(key, now)
	if lim.AllowN(now, 1) {
		return true, 0
	}
	// Denied: read the delay until the next token without consuming it, so a
	// throttled caller's retries don't push the recovery time ever further out.
	r := lim.ReserveN(now, 1)
	d := r.DelayFrom(now)
	r.CancelAt(now)
	return false, d
}

func (t *TenantLimiter) limiterFor(key string, now time.Time) *rate.Limiter {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.buckets[key]; ok {
		e.lastSeen = now
		return e.lim
	}
	lim := rate.NewLimiter(t.rps, t.burst)
	t.buckets[key] = &entry{lim: lim, lastSeen: now}
	return lim
}

// Len returns the number of live buckets. Exposed for tests and for an operator
// gauge of how many distinct tenants are currently being tracked.
func (t *TenantLimiter) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.buckets)
}

func (t *TenantLimiter) janitor() {
	defer close(t.done)
	ticker := time.NewTicker(t.ttl)
	defer ticker.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-ticker.C:
			t.evict(t.now())
		}
	}
}

func (t *TenantLimiter) evict(now time.Time) {
	cutoff := now.Add(-t.ttl)
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, e := range t.buckets {
		if e.lastSeen.Before(cutoff) {
			delete(t.buckets, k)
		}
	}
}

// Stop terminates the janitor goroutine. It is idempotent and safe to call from
// a shutdown path.
func (t *TenantLimiter) Stop() {
	t.stopOnce.Do(func() {
		close(t.stop)
		<-t.done
	})
}
