package usage

// This file makes real the shared-store seam for usage metering. The in-memory
// Aggregator already sums correctly across replicas (each replica flushes its
// own deltas with an additive Postgres UPSERT), so the win here is not
// correctness but CONSOLIDATION: instead of N replicas each writing the same
// (workspace, period, metric) row every flush window, the per-replica deltas
// are first accumulated into ONE shared Redis counter, and a single claim-based
// flush rolls that global counter up into Postgres. Postgres stays the durable
// record; Redis is the cross-replica accumulator in front of it.
//
// The pipeline, end to end:
//
//	request → Aggregator.Record (in-memory, fail-open, no I/O on the hot path)
//	        → Aggregator flush → RedisSink.AddUsage  (HINCRBY into a shared hash)
//	        → RedisFlusher      → Store.AddUsage      (atomic additive UPSERT)
//
// Two properties carry the design:
//
//   - No double counting when multiple replicas flush. The Redis→Postgres step
//     CLAIMS each period's accumulated counters with an atomic HGETALL+DEL in a
//     single Lua script, so if two replicas' flushers race, exactly one reads
//     the counters and the other sees an empty hash. The claimed batch is then
//     written through the same additive, single-transaction Store.AddUsage the
//     per-replica path used, so a merge-back retry (on a Postgres error) cannot
//     double count — identical to the in-memory aggregator's guarantee.
//
//   - Fail-open, never blocking a request. Recording stays the in-memory
//     Aggregator increment, so a Redis outage is invisible to the request path.
//     When the Aggregator flushes to RedisSink and Redis is down, RedisSink
//     DEGRADES the affected deltas to the Postgres sink (the exact pre-Redis
//     behaviour); if Postgres is also unavailable it DROPS them (usage metering
//     is best-effort billing telemetry, explicitly allowed to drop rather than
//     stall). RedisSink therefore never returns an error that would make the
//     Aggregator retry — which, because HINCRBY is not idempotent, is also what
//     keeps a retry from double counting. The honest trade-off: a simultaneous
//     Redis+Postgres outage loses at most the in-flight flush windows.

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// DefaultRedisKeyPrefix namespaces the usage accumulator's keys inside a Redis
// instance shared with other subsystems (the rate limiter, a future worker
// queue). Scheme + version segments let the layout evolve without colliding
// with an older deployment's keys mid-rollout.
const DefaultRedisKeyPrefix = "shieldnet:usage:v1:"

// defaultRedisOpTimeout bounds a single Redis round trip on the flush path. The
// flush runs off the request path, so this only stops a stalled Redis from
// hanging the flush goroutine (and thus the shutdown join).
const defaultRedisOpTimeout = 5 * time.Second

// defaultAccumulatorTTL is the safety-net expiry on a period's accumulator hash.
// In steady state the flusher drains and deletes the hash within a flush window,
// so it lives only seconds; this TTL only matters if a period stops receiving
// writes while every flusher is down, bounding an orphaned hash's lifetime. It
// is far longer than any tolerable flush outage so it never races a healthy
// flush, but finite so a permanently-abandoned period cannot leak forever.
const defaultAccumulatorTTL = 7 * 24 * time.Hour

// accumulateScript adds a batch of (field, count) increments to one period's
// accumulator hash and (re)arms its TTL, all atomically. Used both by RedisSink
// to record per-replica deltas and by RedisFlusher to merge a failed batch back
// after a Postgres write error.
//
//	KEYS[1] = period hash key
//	ARGV[1] = ttl in ms
//	ARGV[2i], ARGV[2i+1] = field, increment pairs (i >= 1)
var accumulateScript = redis.NewScript(`
local ttl_ms = tonumber(ARGV[1])
for i = 2, #ARGV, 2 do
  redis.call('HINCRBY', KEYS[1], ARGV[i], tonumber(ARGV[i+1]))
end
redis.call('PEXPIRE', KEYS[1], ttl_ms)
return 1
`)

// claimScript atomically reads and removes one period's accumulator hash. The
// HGETALL and DEL run in one indivisible step so concurrent flushers across
// replicas cannot both claim the same counters: the first gets the values and
// deletes them, any racing flusher sees an empty hash. Returns the flat
// HGETALL array (field, value, field, value, ...).
//
//	KEYS[1] = period hash key
var claimScript = redis.NewScript(`
local vals = redis.call('HGETALL', KEYS[1])
if #vals > 0 then
  redis.call('DEL', KEYS[1])
end
return vals
`)

// encodeField packs a (workspace, metric) pair into one hash field. The
// workspace UUID renders to a fixed 36-char form and metrics never contain a
// pipe, so '|' is an unambiguous separator decodeField can split on.
func encodeField(workspaceID uuid.UUID, metric string) string {
	return workspaceID.String() + "|" + metric
}

// decodeField reverses encodeField, rejecting a malformed field (bad UUID or
// missing separator) so a corrupt key can be skipped rather than poisoning the
// whole flush batch.
func decodeField(field string) (uuid.UUID, string, bool) {
	ws, metric, found := strings.Cut(field, "|")
	if !found || metric == "" {
		return uuid.Nil, "", false
	}
	id, err := uuid.Parse(ws)
	if err != nil || id == uuid.Nil {
		return uuid.Nil, "", false
	}
	return id, metric, true
}

// RedisSink is the Sink the in-memory Aggregator flushes its per-replica deltas
// into: it HINCRBYs them onto a shared Redis hash (the cross-replica
// accumulator) rather than straight into Postgres. It satisfies the same Sink
// interface as *Store, so it slots into Aggregator construction with no change
// to Record or the middleware.
//
// It is fail-open by construction: on any Redis error it routes the affected
// deltas to fallback (the Postgres Store) and, failing that, drops them — and
// it always reports success to the Aggregator so the non-idempotent HINCRBY is
// never retried (which would double count). See the file header.
type RedisSink struct {
	client    redis.Scripter
	fallback  Sink
	keyPrefix string
	ttlMS     int64
	opTimeout time.Duration
	onError   func(error)
}

// RedisSinkConfig tunes a RedisSink.
type RedisSinkConfig struct {
	// Fallback receives deltas that could not be accumulated into Redis (a
	// Redis outage), so a degraded boot reverts to the exact per-replica →
	// Postgres path. Typically the *Store. When nil, un-accumulable deltas are
	// dropped (best-effort telemetry).
	Fallback Sink
	// KeyPrefix overrides DefaultRedisKeyPrefix. Empty uses the default. MUST
	// match the RedisFlusher's prefix so the flusher claims what the sink wrote.
	KeyPrefix string
	// AccumulatorTTL overrides defaultAccumulatorTTL (the orphaned-period safety
	// net). Non-positive uses the default.
	AccumulatorTTL time.Duration
	// OpTimeout bounds a single Redis round trip. Non-positive uses
	// defaultRedisOpTimeout.
	OpTimeout time.Duration
	// OnError, when non-nil, is invoked when a Redis op fails and the sink
	// degrades or drops. It is never passed a workspace id (cardinality).
	OnError func(error)
}

var _ Sink = (*RedisSink)(nil)

// NewRedisSink builds a RedisSink over an already-connected client.
func NewRedisSink(client redis.Scripter, cfg RedisSinkConfig) *RedisSink {
	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = DefaultRedisKeyPrefix
	}
	ttl := cfg.AccumulatorTTL
	if ttl <= 0 {
		ttl = defaultAccumulatorTTL
	}
	opTimeout := cfg.OpTimeout
	if opTimeout <= 0 {
		opTimeout = defaultRedisOpTimeout
	}
	return &RedisSink{
		client:    client,
		fallback:  cfg.Fallback,
		keyPrefix: prefix,
		ttlMS:     ttl.Milliseconds(),
		opTimeout: opTimeout,
		onError:   cfg.OnError,
	}
}

func (s *RedisSink) periodKey(period string) string {
	return s.keyPrefix + "agg:" + period
}

// AddUsage accumulates a batch of deltas into the shared Redis hashes, grouped
// by period. Each delta lands in exactly one place: Redis on success, else the
// Postgres fallback, else dropped — so it can never be counted twice. It always
// returns nil so the Aggregator treats the batch as flushed and never retries
// the non-idempotent HINCRBYs.
func (s *RedisSink) AddUsage(ctx context.Context, deltas []Delta) error {
	if len(deltas) == 0 {
		return nil
	}
	byPeriod := make(map[string][]Delta, 1)
	for _, d := range deltas {
		if d.WorkspaceID == uuid.Nil || d.Period == "" || d.Metric == "" || d.Count <= 0 {
			continue
		}
		byPeriod[d.Period] = append(byPeriod[d.Period], d)
	}

	var failed []Delta
	var firstErr error
	for period, ds := range byPeriod {
		if err := s.accumulate(ctx, period, ds); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			failed = append(failed, ds...)
		}
	}
	if len(failed) == 0 {
		return nil
	}

	if s.onError != nil {
		s.onError(firstErr)
	}
	// Degrade only the deltas that did not reach Redis, so the periods that DID
	// are not also written to Postgres (which would double count once the
	// flusher rolls them up).
	if s.fallback != nil {
		if err := s.fallback.AddUsage(ctx, failed); err != nil {
			logger.Warnf(ctx, "usage: redis accumulate AND postgres fallback failed; dropping %d deltas: redis=%v postgres=%v", len(failed), firstErr, err)
		}
		return nil
	}
	logger.Warnf(ctx, "usage: redis accumulate failed and no fallback configured; dropping %d deltas: %v", len(failed), firstErr)
	return nil
}

func (s *RedisSink) accumulate(ctx context.Context, period string, ds []Delta) error {
	opCtx, cancel := context.WithTimeout(ctx, s.opTimeout)
	defer cancel()
	args := make([]interface{}, 0, 1+2*len(ds))
	args = append(args, s.ttlMS)
	for _, d := range ds {
		args = append(args, encodeField(d.WorkspaceID, d.Metric), d.Count)
	}
	return accumulateScript.Run(opCtx, s.client, []string{s.periodKey(period)}, args...).Err()
}

// RedisFlusher rolls the shared Redis accumulator up into Postgres. It claims
// each tracked period's counters atomically (so racing replica flushers never
// double count), writes them through the additive Store.AddUsage, and on a
// Postgres error merges the claimed counters back into Redis for a later flush.
type RedisFlusher struct {
	client    redis.Scripter
	store     Sink
	keyPrefix string
	ttlMS     int64
	interval  time.Duration
	timeout   time.Duration
	clock     func() time.Time
	onError   func(error)

	startOnce sync.Once
	stopOnce  sync.Once
	stop      chan struct{}
	done      chan struct{}
}

// RedisFlusherConfig tunes a RedisFlusher.
type RedisFlusherConfig struct {
	// Interval is the cadence at which Redis aggregates are rolled up into
	// Postgres. Non-positive uses defaultFlushInterval.
	Interval time.Duration
	// Timeout bounds a single roll-up (claim + Postgres write). Non-positive
	// uses defaultFlushTimeout.
	Timeout time.Duration
	// KeyPrefix MUST match the RedisSink's prefix. Empty uses DefaultRedisKeyPrefix.
	KeyPrefix string
	// AccumulatorTTL is re-armed on a merge-back. Non-positive uses defaultAccumulatorTTL.
	AccumulatorTTL time.Duration
	// Clock overrides time.Now (drives which billing periods are claimed). Tests
	// inject a fake; production leaves it nil.
	Clock func() time.Time
	// OnError, when non-nil, is invoked on a claim or roll-up failure. Never
	// passed a workspace id.
	OnError func(error)
}

// NewRedisFlusher builds a RedisFlusher writing through store (the Postgres
// Sink). Call Run to start its loop.
func NewRedisFlusher(client redis.Scripter, store Sink, cfg RedisFlusherConfig) *RedisFlusher {
	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = DefaultRedisKeyPrefix
	}
	ttl := cfg.AccumulatorTTL
	if ttl <= 0 {
		ttl = defaultAccumulatorTTL
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = defaultFlushInterval
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultFlushTimeout
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	return &RedisFlusher{
		client:    client,
		store:     store,
		keyPrefix: prefix,
		ttlMS:     ttl.Milliseconds(),
		interval:  interval,
		timeout:   timeout,
		clock:     clock,
		onError:   cfg.OnError,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
}

func (f *RedisFlusher) periodKey(period string) string {
	return f.keyPrefix + "agg:" + period
}

// claimPeriods returns the period keys a flush should claim: the current
// billing period and the previous one. Deltas are always written under the
// period of the request that produced them (PeriodOf at Record time), so a
// flush only needs the current month plus the one just rolled over — the
// previous month catches counters written moments before a month boundary that
// have not yet been flushed.
func (f *RedisFlusher) claimPeriods() []string {
	now := f.clock().UTC()
	cur := PeriodOf(now)
	prev := PeriodOf(now.AddDate(0, -1, 0))
	if prev == cur {
		return []string{cur}
	}
	return []string{cur, prev}
}

// Flush claims every tracked period's accumulated counters from Redis and
// writes them to Postgres in one additive batch. On a Postgres error it merges
// the claimed counters back into Redis so a later flush retries them; because
// the claim already removed them, the merge-back cannot duplicate what is
// already in Postgres beyond the at-least-once window the additive UPSERT
// tolerates. A claim error for one period is logged and skipped (its counters
// stay in Redis for the next flush) rather than failing the others.
func (f *RedisFlusher) Flush(ctx context.Context) error {
	var deltas []Delta
	for _, period := range f.claimPeriods() {
		claimed, err := f.claim(ctx, period)
		if err != nil {
			if f.onError != nil {
				f.onError(err)
			}
			logger.Warnf(ctx, "usage: redis claim for period %s failed (counters retained in redis): %v", period, err)
			continue
		}
		deltas = append(deltas, claimed...)
	}
	if len(deltas) == 0 {
		return nil
	}

	if err := f.store.AddUsage(ctx, deltas); err != nil {
		f.mergeBack(ctx, deltas)
		if f.onError != nil {
			f.onError(err)
		}
		return err
	}
	return nil
}

func (f *RedisFlusher) claim(ctx context.Context, period string) ([]Delta, error) {
	res, err := claimScript.Run(ctx, f.client, []string{f.periodKey(period)}).Slice()
	if err != nil {
		return nil, fmt.Errorf("usage: claim period %s: %w", period, err)
	}
	// res is a flat HGETALL: field, value, field, value, ...
	deltas := make([]Delta, 0, len(res)/2)
	for i := 0; i+1 < len(res); i += 2 {
		field, ok := res[i].(string)
		if !ok {
			continue
		}
		raw, ok := res[i+1].(string)
		if !ok {
			continue
		}
		count, perr := strconv.ParseInt(raw, 10, 64)
		if perr != nil || count <= 0 {
			continue
		}
		ws, metric, ok := decodeField(field)
		if !ok {
			continue
		}
		deltas = append(deltas, Delta{WorkspaceID: ws, Period: period, Metric: metric, Count: count})
	}
	return deltas, nil
}

// mergeBack re-accumulates a batch whose Postgres write failed, grouped by
// period, so the next flush re-claims and retries it. Best-effort: if Redis is
// now also unavailable the deltas are dropped (logged), the same best-effort
// posture as RedisSink.
func (f *RedisFlusher) mergeBack(ctx context.Context, deltas []Delta) {
	byPeriod := make(map[string][]Delta, 1)
	for _, d := range deltas {
		byPeriod[d.Period] = append(byPeriod[d.Period], d)
	}
	for period, ds := range byPeriod {
		args := make([]interface{}, 0, 1+2*len(ds))
		args = append(args, f.ttlMS)
		for _, d := range ds {
			args = append(args, encodeField(d.WorkspaceID, d.Metric), d.Count)
		}
		if err := accumulateScript.Run(ctx, f.client, []string{f.periodKey(period)}, args...).Err(); err != nil {
			logger.Warnf(ctx, "usage: redis merge-back for period %s failed; dropping %d deltas: %v", period, len(ds), err)
		}
	}
}

// Run starts the roll-up loop and returns a join function that blocks until the
// loop has stopped after a final flush, mirroring Aggregator.Run's lifecycle so
// main can order shutdown deterministically. The write context drops ctx's
// cancellation (WithoutCancel) but keeps its values so the shutdown flush runs
// to its own bounded deadline. Run is safe to call more than once (startOnce
// guards the launch).
func (f *RedisFlusher) Run(ctx context.Context) (join func()) {
	f.startOnce.Do(func() {
		writeCtx := context.WithoutCancel(ctx)
		go func() {
			defer close(f.done)
			ticker := time.NewTicker(f.interval)
			defer ticker.Stop()
			for {
				select {
				case <-f.stop:
					f.flushBounded(writeCtx)
					return
				case <-ctx.Done():
					f.flushBounded(writeCtx)
					return
				case <-ticker.C:
					f.flushBounded(writeCtx)
				}
			}
		}()
	})
	return func() {
		f.stopOnce.Do(func() { close(f.stop) })
		<-f.done
	}
}

// flushBounded runs one Flush under the per-flush timeout. A failure is logged,
// not surfaced: claimed counters were merged back into Redis by Flush, so the
// next tick retries them. Flushes are at most one per interval, so even a
// sustained outage logs at a bounded rate.
func (f *RedisFlusher) flushBounded(base context.Context) {
	ctx, cancel := context.WithTimeout(base, f.timeout)
	defer cancel()
	if err := f.Flush(ctx); err != nil {
		logger.Warnf(base, "usage: redis roll-up flush failed (counters retained for retry): %v", err)
	}
}
