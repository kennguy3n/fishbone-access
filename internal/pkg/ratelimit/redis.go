package ratelimit

// This file makes real the shared-store seam named in the package doc: a
// Redis-backed token bucket that satisfies the SAME Allow(key) contract the
// middleware consumes via the RateLimiter interface, so plugging it in is a
// construction-site change with no caller or middleware edits.
//
// Why a server-side Lua script (EVALSHA). The whole point of the shared store
// is GLOBAL exactness across the N ztna-api replicas: the in-memory limiter
// gives each replica its own bucket, so a tenant's true ceiling is N×RPS. To
// make the limit exact the read-modify-write of the bucket (refill, check,
// consume) must be ATOMIC across replicas — two replicas hitting the same
// tenant in the same instant must not both observe "a token is free" and both
// admit. A client-side GET/SET would race exactly there. Evaluating the bucket
// in a single Lua script runs the whole decision atomically inside Redis in one
// round trip, so the shared budget is enforced no matter how many replicas race
// it. redis.Script.Run uses EVALSHA and transparently falls back to EVAL+cache
// on NOSCRIPT, so steady state is a single EVALSHA round trip per request.
//
// The trade-off this buys, stated honestly: one Redis round trip is now on the
// admission path of every authenticated request (the in-memory bucket was a
// lock-and-map with no I/O). That is the cost of cross-replica exactness. It is
// bounded (one RTT to a co-located Redis) and, critically, FAIL-OPEN: if Redis
// is slow, unreachable, or errors, Allow returns "allowed" rather than failing
// the tenant's request — a limiter-backend outage must never take down request
// serving. A flapping Redis therefore degrades to the permissive (pre-limit)
// posture, never to a closed door.

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultRedisKeyPrefix namespaces this limiter's keys inside a Redis instance
// that is shared with other subsystems (the usage accumulator, a future worker
// queue). It includes a scheme and a version segment so the key layout can be
// evolved without colliding with an older deployment's keys during a rollout.
// The caller-supplied key (the authoritative tenant id) is appended verbatim,
// so one tenant can never address another tenant's bucket.
const DefaultRedisKeyPrefix = "shieldnet:ratelimit:v1:"

// defaultRedisOpTimeout bounds a single Allow's Redis round trip. It is short
// on purpose: the limiter sits on the request admission path, so a stalled
// Redis must trip the fail-open path quickly rather than adding its stall to
// every request's latency. On timeout Allow fails OPEN (admits).
const defaultRedisOpTimeout = 100 * time.Millisecond

// allowTokenBucketScript is the atomic token-bucket evaluated server-side. It
// is the exactness mechanism: refill, admission check, and consume happen in
// one indivisible step inside Redis, so concurrent replicas cannot both
// over-admit against one shared budget.
//
//	KEYS[1] = bucket key (prefix + tenant id)
//	ARGV[1] = refill rate, tokens per second (float)
//	ARGV[2] = burst, bucket capacity (integer)
//	ARGV[3] = tokens requested by this call (integer, normally 1)
//	ARGV[4] = caller clock override in epoch-ms, or < 0 to use Redis server TIME
//	ARGV[5] = idle TTL in ms applied to the bucket key
//
// Returns {allowed (1|0), retry_after_ms}. Server TIME is the default clock so
// every replica shares ONE monotonic-enough reference rather than trusting each
// replica's (possibly skewed) wall clock; the override exists only so tests can
// drive the clock deterministically.
//
// A denied request consumes NO token (mirroring the in-memory limiter, whose
// ReserveN/CancelAt leaves the bucket untouched on denial) so a throttled
// caller's retries cannot push its own recovery time ever further out. The
// refilled level and timestamp are still persisted on every call so the bucket
// keeps advancing. PEXPIRE bounds memory to the ACTIVE-tenant set: an idle key
// that has fully refilled is evicted, and a returning tenant simply gets a
// fresh full bucket — the same safe eviction the in-memory janitor performs.
var allowTokenBucketScript = redis.NewScript(`
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local requested = tonumber(ARGV[3])
local now_ms
if tonumber(ARGV[4]) >= 0 then
  now_ms = tonumber(ARGV[4])
else
  local t = redis.call('TIME')
  now_ms = (tonumber(t[1]) * 1000) + math.floor(tonumber(t[2]) / 1000)
end
local ttl_ms = tonumber(ARGV[5])

local data = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil or ts == nil then
  tokens = burst
  ts = now_ms
end

local elapsed = now_ms - ts
if elapsed < 0 then elapsed = 0 end
tokens = tokens + (elapsed * rate / 1000.0)
if tokens > burst then tokens = burst end

local allowed = 0
local retry_ms = 0
if tokens >= requested then
  allowed = 1
  tokens = tokens - requested
else
  local deficit = requested - tokens
  retry_ms = math.ceil((deficit / rate) * 1000.0)
end

redis.call('HSET', KEYS[1], 'tokens', tostring(tokens), 'ts', tostring(now_ms))
redis.call('PEXPIRE', KEYS[1], ttl_ms)
return {allowed, retry_ms}
`)

// RedisConfig tunes a RedisLimiter. RPS and Burst carry the identical meaning
// as the in-memory Config so the same operator knobs drive either backend.
type RedisConfig struct {
	// RPS is the sustained per-key token refill rate (requests per second).
	RPS float64
	// Burst is the per-key bucket depth.
	Burst int
	// IdleTTL is how long an unused bucket key is retained before Redis evicts
	// it. Non-positive derives a safe default from RPS/Burst (twice the time to
	// refill a full bucket, floored at one minute) so an idle, fully-refilled
	// key is reclaimed without ever evicting a bucket that is still draining.
	IdleTTL time.Duration
	// OpTimeout bounds a single Allow's Redis round trip. Non-positive uses
	// defaultRedisOpTimeout. On timeout Allow fails OPEN.
	OpTimeout time.Duration
	// KeyPrefix overrides DefaultRedisKeyPrefix. Empty uses the default.
	KeyPrefix string
	// Clock, when non-nil, overrides the server-side TIME with a caller clock
	// (epoch). Used by tests to drive the bucket deterministically; production
	// leaves it nil so all replicas share Redis' own clock.
	Clock func() time.Time
	// OnError, when non-nil, is invoked with the error whenever a Redis op fails
	// and Allow consequently fails open. It feeds a fail-open counter/log
	// without coupling this package to a metrics implementation. It is never
	// passed a key (tenant id), keeping cardinality bounded.
	OnError func(error)
}

// RedisLimiter is a globally-exact, Redis-backed token-bucket limiter. It
// satisfies the same Allow(key) (bool, time.Duration) contract as
// *TenantLimiter and therefore the middleware's RateLimiter interface, so it
// drops into the existing seam with no caller changes. It holds no goroutines
// (eviction is Redis-side via PEXPIRE), so unlike *TenantLimiter it needs no
// Stop; the caller owns the redis.Client lifecycle.
type RedisLimiter struct {
	client    redis.Scripter
	rps       float64
	burst     int
	ttlMS     int64
	opTimeout time.Duration
	keyPrefix string
	clock     func() time.Time
	onError   func(error)
}

// NewRedisLimiter builds a RedisLimiter over an already-connected client (any
// redis.Scripter; *redis.Client satisfies it). Burst is clamped to at least 1,
// mirroring New, so a misconfigured zero can never wedge a tenant at
// always-denied; callers wanting to reject a bad value loudly should validate
// before constructing (cmd/ztna-api does, via config.Validate).
func NewRedisLimiter(client redis.Scripter, cfg RedisConfig) *RedisLimiter {
	burst := cfg.Burst
	if burst < 1 {
		burst = 1
	}
	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = DefaultRedisKeyPrefix
	}
	opTimeout := cfg.OpTimeout
	if opTimeout <= 0 {
		opTimeout = defaultRedisOpTimeout
	}
	return &RedisLimiter{
		client:    client,
		rps:       cfg.RPS,
		burst:     burst,
		ttlMS:     redisIdleTTLMillis(cfg.IdleTTL, cfg.RPS, burst),
		opTimeout: opTimeout,
		keyPrefix: prefix,
		clock:     cfg.Clock,
		onError:   cfg.OnError,
	}
}

// redisIdleTTLMillis resolves the bucket idle TTL in milliseconds. An explicit
// positive IdleTTL wins; otherwise it derives twice the full-refill time
// (burst/rps seconds), floored at one minute, so eviction can only ever happen
// to a key that has had ample time to refill to full — making eviction
// equivalent to handing a returning tenant a fresh full bucket.
func redisIdleTTLMillis(idle time.Duration, rps float64, burst int) int64 {
	if idle > 0 {
		return idle.Milliseconds()
	}
	ttl := defaultIdleTTL
	if rps > 0 {
		fullRefill := time.Duration(float64(burst) / rps * float64(time.Second))
		if d := 2 * fullRefill; d > ttl {
			ttl = d
		}
	}
	return ttl.Milliseconds()
}

// Allow reports whether a request for key may proceed now, consuming one token
// when it does, and returns the estimated wait until a token frees up when
// denied (for a Retry-After hint) — the same contract as *TenantLimiter.Allow.
//
// It is FAIL-OPEN: any Redis error or timeout results in (true, 0). A limiter
// whose backend is down must not reject a tenant's traffic; the worst case of a
// Redis outage is therefore reverting to the permissive (un-limited) posture,
// never a hard fail. The per-call context is bounded by OpTimeout so a stalled
// Redis trips this path promptly instead of stalling the request.
func (r *RedisLimiter) Allow(key string) (bool, time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), r.opTimeout)
	defer cancel()

	nowArg := int64(-1)
	if r.clock != nil {
		nowArg = r.clock().UnixMilli()
	}

	res, err := allowTokenBucketScript.Run(
		ctx, r.client, []string{r.keyPrefix + key},
		r.rps, r.burst, 1, nowArg, r.ttlMS,
	).Slice()
	if err != nil {
		if r.onError != nil {
			r.onError(err)
		}
		return true, 0 // FAIL OPEN — never reject because the backend is unavailable.
	}

	allowed, retryMS, ok := parseAllowResult(res)
	if !ok {
		// A malformed reply is as opaque to us as an outage; fail open rather
		// than guessing a verdict from a value we don't understand.
		if r.onError != nil {
			r.onError(errors.New("ratelimit: malformed token-bucket reply"))
		}
		return true, 0
	}
	if allowed {
		return true, 0
	}
	return false, time.Duration(retryMS) * time.Millisecond
}

// parseAllowResult decodes the {allowed, retry_after_ms} reply. Redis integer
// replies decode to int64 through go-redis' Slice(); anything else is treated
// as malformed (ok=false) so Allow can fail open rather than misread it.
func parseAllowResult(res []interface{}) (allowed bool, retryMS int64, ok bool) {
	if len(res) != 2 {
		return false, 0, false
	}
	a, ok1 := res[0].(int64)
	d, ok2 := res[1].(int64)
	if !ok1 || !ok2 {
		return false, 0, false
	}
	if d < 0 {
		d = 0
	}
	return a == 1, d, true
}
