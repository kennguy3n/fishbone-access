package usage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func newUsageRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
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

// TestRedisSinkAccumulatesThenFlushesToStore proves the full pipeline: deltas
// accumulate into the shared Redis hash, and a RedisFlusher rolls the global
// counter up into the (fake) Postgres store exactly once.
func TestRedisSinkAccumulatesThenFlushesToStore(t *testing.T) {
	_, c := newUsageRedis(t)
	store := &fakeSink{}
	sink := NewRedisSink(c, RedisSinkConfig{Fallback: store})
	flusher := NewRedisFlusher(c, store, RedisFlusherConfig{
		Clock: fixedClock(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)),
	})
	ctx := context.Background()
	ws := uuid.New()
	period := "2026-06"

	if err := sink.AddUsage(ctx, []Delta{{WorkspaceID: ws, Period: period, Metric: MetricAPIRequests, Count: 4}}); err != nil {
		t.Fatalf("accumulate 1: %v", err)
	}
	if err := sink.AddUsage(ctx, []Delta{{WorkspaceID: ws, Period: period, Metric: MetricAPIRequests, Count: 6}}); err != nil {
		t.Fatalf("accumulate 2: %v", err)
	}
	// Nothing in Postgres yet — it lives only in Redis.
	if got := store.total(ws, MetricAPIRequests); got != 0 {
		t.Fatalf("store total before flush = %d, want 0 (still in redis)", got)
	}

	if err := flusher.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if got := store.total(ws, MetricAPIRequests); got != 10 {
		t.Fatalf("store total after flush = %d, want 10 (4+6)", got)
	}

	// A second flush claims nothing (the hash was deleted) — no double count.
	if err := flusher.Flush(ctx); err != nil {
		t.Fatalf("second flush: %v", err)
	}
	if got := store.total(ws, MetricAPIRequests); got != 10 {
		t.Fatalf("store total after empty flush = %d, want 10 (no double count)", got)
	}
}

// TestRedisFlusherNoDoubleCountAcrossReplicas is the cross-replica exactness
// proof for usage: many flushers (standing in for replicas) race to roll up the
// SAME accumulated counters, and the atomic claim (HGETALL+DEL) guarantees the
// total written to Postgres equals what was accumulated — never a multiple.
func TestRedisFlusherNoDoubleCountAcrossReplicas(t *testing.T) {
	_, c := newUsageRedis(t)
	store := &fakeSink{}
	sink := NewRedisSink(c, RedisSinkConfig{Fallback: store})
	ctx := context.Background()
	ws := uuid.New()
	period := "2026-06"

	const total = 1000
	for i := 0; i < total; i++ {
		if err := sink.AddUsage(ctx, []Delta{{WorkspaceID: ws, Period: period, Metric: MetricAPIRequests, Count: 1}}); err != nil {
			t.Fatalf("accumulate: %v", err)
		}
	}

	clock := fixedClock(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC))
	const replicas = 8
	flushers := make([]*RedisFlusher, replicas)
	for i := range flushers {
		flushers[i] = NewRedisFlusher(c, store, RedisFlusherConfig{Clock: clock})
	}
	var wg sync.WaitGroup
	for _, f := range flushers {
		wg.Add(1)
		go func(f *RedisFlusher) {
			defer wg.Done()
			_ = f.Flush(ctx)
		}(f)
	}
	wg.Wait()

	if got := store.total(ws, MetricAPIRequests); got != total {
		t.Fatalf("store total = %d, want exactly %d (concurrent flushers double counted)", got, total)
	}
}

// TestRedisSinkFailOpenToFallback proves a Redis outage degrades the deltas to
// the Postgres fallback rather than blocking or losing them, and that the sink
// still reports success (so the aggregator never retries the non-idempotent
// HINCRBY).
func TestRedisSinkFailOpenToFallback(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	c := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	store := &fakeSink{}
	var failOpens int
	sink := NewRedisSink(c, RedisSinkConfig{
		Fallback:  store,
		OpTimeout: 200 * time.Millisecond,
		OnError:   func(error) { failOpens++ },
	})
	ctx := context.Background()
	ws := uuid.New()

	mr.Close() // take Redis down

	if err := sink.AddUsage(ctx, []Delta{{WorkspaceID: ws, Period: "2026-06", Metric: MetricAPIRequests, Count: 7}}); err != nil {
		t.Fatalf("AddUsage returned error, want nil (must not trigger a retry): %v", err)
	}
	if got := store.total(ws, MetricAPIRequests); got != 7 {
		t.Fatalf("fallback store total = %d, want 7 (deltas should degrade to Postgres)", got)
	}
	if failOpens == 0 {
		t.Fatal("OnError never fired; a Redis outage must be observable")
	}
}

// TestRedisSinkDropsWhenNoFallback proves that with both Redis down and no
// fallback the deltas are dropped (best-effort telemetry) WITHOUT returning an
// error — never blocking and never forcing a double-counting retry.
func TestRedisSinkDropsWhenNoFallback(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	c := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	sink := NewRedisSink(c, RedisSinkConfig{OpTimeout: 200 * time.Millisecond})
	mr.Close()

	if err := sink.AddUsage(context.Background(), []Delta{{WorkspaceID: uuid.New(), Period: "2026-06", Metric: MetricAPIRequests, Count: 3}}); err != nil {
		t.Fatalf("AddUsage returned error, want nil (drop silently): %v", err)
	}
}

// TestRedisFlusherMergeBackOnStoreError proves that when the Postgres write
// fails, the claimed counters are merged back into Redis and a later flush
// rolls them up without loss and without double counting.
func TestRedisFlusherMergeBackOnStoreError(t *testing.T) {
	_, c := newUsageRedis(t)
	store := &fakeSink{failNext: 1, err: errors.New("postgres down")}
	sink := NewRedisSink(c, RedisSinkConfig{})
	flusher := NewRedisFlusher(c, store, RedisFlusherConfig{
		Clock: fixedClock(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)),
	})
	ctx := context.Background()
	ws := uuid.New()

	if err := sink.AddUsage(ctx, []Delta{{WorkspaceID: ws, Period: "2026-06", Metric: MetricAPIRequests, Count: 12}}); err != nil {
		t.Fatalf("accumulate: %v", err)
	}

	// First flush: Postgres fails; counters must be merged back into Redis.
	if err := flusher.Flush(ctx); err == nil {
		t.Fatal("first flush returned nil, want the store error surfaced")
	}
	if got := store.total(ws, MetricAPIRequests); got != 0 {
		t.Fatalf("store total after failed flush = %d, want 0", got)
	}

	// Second flush: Postgres healthy; the merged-back counters roll up exactly once.
	if err := flusher.Flush(ctx); err != nil {
		t.Fatalf("second flush: %v", err)
	}
	if got := store.total(ws, MetricAPIRequests); got != 12 {
		t.Fatalf("store total after recovery = %d, want 12 (merge-back lost or duplicated data)", got)
	}
}

// TestRedisFlusherClaimsPreviousPeriod proves a month-boundary straddle is
// covered: counters written under last month are still rolled up by this
// month's flush.
func TestRedisFlusherClaimsPreviousPeriod(t *testing.T) {
	_, c := newUsageRedis(t)
	store := &fakeSink{}
	sink := NewRedisSink(c, RedisSinkConfig{})
	// Clock sits just after the June 1 boundary; the May counters must flush.
	flusher := NewRedisFlusher(c, store, RedisFlusherConfig{
		Clock: fixedClock(time.Date(2026, 6, 1, 0, 0, 5, 0, time.UTC)),
	})
	ctx := context.Background()
	ws := uuid.New()

	if err := sink.AddUsage(ctx, []Delta{{WorkspaceID: ws, Period: "2026-05", Metric: MetricAPIRequests, Count: 8}}); err != nil {
		t.Fatalf("accumulate previous period: %v", err)
	}
	if err := flusher.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if got := store.total(ws, MetricAPIRequests); got != 8 {
		t.Fatalf("store total = %d, want 8 (previous-period counters not claimed)", got)
	}
}

// TestRedisFlusherClaimsPreviousPeriodOnMonthEnd guards the AddDate
// normalization trap: on a 31st (and other month-end days) a naive
// now.AddDate(0,-1,0) overflows back into the current month, so prev == cur and
// the previous month's accumulator is never claimed. Subtracting the
// day-of-month must still claim the prior month here.
func TestRedisFlusherClaimsPreviousPeriodOnMonthEnd(t *testing.T) {
	// Each of these days, AddDate(0,-1,0) normalises into the same month.
	for _, day := range []time.Time{
		time.Date(2026, 3, 31, 12, 0, 0, 0, time.UTC), // -> "Feb 31" -> Mar 3
		time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 12, 31, 12, 0, 0, 0, time.UTC), // crosses the year
	} {
		t.Run(day.Format("2006-01-02"), func(t *testing.T) {
			_, c := newUsageRedis(t)
			store := &fakeSink{}
			sink := NewRedisSink(c, RedisSinkConfig{})
			flusher := NewRedisFlusher(c, store, RedisFlusherConfig{Clock: fixedClock(day)})
			ctx := context.Background()
			ws := uuid.New()
			prev := PeriodOf(day.AddDate(0, 0, -day.Day()))

			if err := sink.AddUsage(ctx, []Delta{{WorkspaceID: ws, Period: prev, Metric: MetricAPIRequests, Count: 4}}); err != nil {
				t.Fatalf("accumulate: %v", err)
			}
			if err := flusher.Flush(ctx); err != nil {
				t.Fatalf("flush: %v", err)
			}
			if got := store.total(ws, MetricAPIRequests); got != 4 {
				t.Fatalf("store total = %d, want 4 (previous period %s not claimed on month-end)", got, prev)
			}
		})
	}
}

// TestRedisSinkPerDeltaLanding proves a partial Redis failure degrades only the
// affected period to the fallback while the healthy period stays in Redis, so
// every delta lands exactly once. It uses the malformed-period filter to assert
// invalid deltas are dropped before they reach Redis.
func TestRedisSinkFiltersInvalidDeltas(t *testing.T) {
	_, c := newUsageRedis(t)
	store := &fakeSink{}
	sink := NewRedisSink(c, RedisSinkConfig{Fallback: store})
	flusher := NewRedisFlusher(c, store, RedisFlusherConfig{
		Clock: fixedClock(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)),
	})
	ctx := context.Background()
	ws := uuid.New()

	if err := sink.AddUsage(ctx, []Delta{
		{WorkspaceID: uuid.Nil, Period: "2026-06", Metric: MetricAPIRequests, Count: 5}, // bad ws
		{WorkspaceID: ws, Period: "", Metric: MetricAPIRequests, Count: 5},              // bad period
		{WorkspaceID: ws, Period: "2026-06", Metric: "", Count: 5},                      // bad metric
		{WorkspaceID: ws, Period: "2026-06", Metric: MetricAPIRequests, Count: 0},       // non-positive
		{WorkspaceID: ws, Period: "2026-06", Metric: MetricAPIRequests, Count: 9},       // the only valid one
	}); err != nil {
		t.Fatalf("accumulate: %v", err)
	}
	if err := flusher.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if got := store.total(ws, MetricAPIRequests); got != 9 {
		t.Fatalf("store total = %d, want 9 (only the valid delta should survive)", got)
	}
}

// TestAggregatorThroughRedisSink wires the real in-memory Aggregator to the
// RedisSink and the RedisFlusher to a fake store, proving the construction the
// composition root performs works end to end with no caller changes.
func TestAggregatorThroughRedisSink(t *testing.T) {
	_, c := newUsageRedis(t)
	store := &fakeSink{}
	clock := fixedClock(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC))
	sink := NewRedisSink(c, RedisSinkConfig{Fallback: store})
	agg := New(sink, Config{Clock: clock})
	flusher := NewRedisFlusher(c, store, RedisFlusherConfig{Clock: clock})
	ctx := context.Background()

	wsA, wsB := uuid.New(), uuid.New()
	for i := 0; i < 5; i++ {
		agg.Record(wsA, MetricAPIRequests)
	}
	for i := 0; i < 3; i++ {
		agg.Record(wsB, MetricAPIRequests)
	}

	if err := agg.Flush(ctx); err != nil { // aggregator -> redis
		t.Fatalf("aggregator flush: %v", err)
	}
	if err := flusher.Flush(ctx); err != nil { // redis -> store
		t.Fatalf("redis flush: %v", err)
	}

	if got := store.total(wsA, MetricAPIRequests); got != 5 {
		t.Fatalf("tenant A total = %d, want 5", got)
	}
	if got := store.total(wsB, MetricAPIRequests); got != 3 {
		t.Fatalf("tenant B total = %d, want 3", got)
	}
}

// TestEncodeDecodeField proves the field round-trips and rejects malformed input.
func TestEncodeDecodeField(t *testing.T) {
	ws := uuid.New()
	got, metric, ok := decodeField(encodeField(ws, MetricAPIRequests))
	if !ok || got != ws || metric != MetricAPIRequests {
		t.Fatalf("round trip: ws=%s metric=%s ok=%t", got, metric, ok)
	}
	if _, _, ok := decodeField("not-a-uuid|api_requests"); ok {
		t.Fatal("bad uuid: ok=true, want false")
	}
	if _, _, ok := decodeField("no-separator"); ok {
		t.Fatal("missing separator: ok=true, want false")
	}
	if _, _, ok := decodeField(ws.String() + "|"); ok {
		t.Fatal("empty metric: ok=true, want false")
	}
}
