package usage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeSink captures the batches passed to AddUsage and can be made to fail, so
// the aggregator's success/failure paths are exercised without a database.
type fakeSink struct {
	mu       sync.Mutex
	batches  [][]Delta
	failNext int // number of subsequent calls to fail before succeeding
	err      error
}

func (f *fakeSink) AddUsage(_ context.Context, deltas []Delta) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext > 0 {
		f.failNext--
		if f.err != nil {
			return f.err
		}
		return errors.New("sink unavailable")
	}
	// Copy so a later mutation of the caller's slice cannot corrupt the record.
	cp := make([]Delta, len(deltas))
	copy(cp, deltas)
	f.batches = append(f.batches, cp)
	return nil
}

// total sums every delta the sink has accepted for a (workspace, metric) pair.
func (f *fakeSink) total(ws uuid.UUID, metric string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	var sum int64
	for _, batch := range f.batches {
		for _, d := range batch {
			if d.WorkspaceID == ws && d.Metric == metric {
				sum += d.Count
			}
		}
	}
	return sum
}

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

// TestAggregatorPerTenantIsolation proves counts are accumulated independently
// per (workspace, metric): one tenant's traffic never bleeds into another's.
func TestAggregatorPerTenantIsolation(t *testing.T) {
	sink := &fakeSink{}
	a := New(sink, Config{Clock: fixedClock(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC))})

	wsA, wsB := uuid.New(), uuid.New()
	for i := 0; i < 5; i++ {
		a.Record(wsA, MetricAPIRequests)
	}
	for i := 0; i < 3; i++ {
		a.Record(wsB, MetricAPIRequests)
	}

	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if got := sink.total(wsA, MetricAPIRequests); got != 5 {
		t.Fatalf("tenant A count = %d, want 5", got)
	}
	if got := sink.total(wsB, MetricAPIRequests); got != 3 {
		t.Fatalf("tenant B count = %d, want 3", got)
	}
}

// TestAggregatorAdditiveFlush proves successive flushes ACCUMULATE in the sink
// rather than overwrite — the additive-UPSERT contract the per-replica posture
// relies on — and that the in-memory buffer is drained (reset) after each
// successful flush so counts are never double-flushed.
func TestAggregatorAdditiveFlush(t *testing.T) {
	sink := &fakeSink{}
	a := New(sink, Config{Clock: fixedClock(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC))})
	ws := uuid.New()

	a.Add(ws, MetricAPIRequests, 10)
	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("first flush: %v", err)
	}
	// Buffer must be empty now: a second flush with no new traffic is a no-op
	// (no double counting).
	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("empty flush: %v", err)
	}
	a.Add(ws, MetricAPIRequests, 7)
	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("second flush: %v", err)
	}
	if got := sink.total(ws, MetricAPIRequests); got != 17 {
		t.Fatalf("accumulated count = %d, want 17 (10 + 7)", got)
	}
	// Exactly two non-empty batches reached the sink (the empty flush wrote
	// nothing), so nothing was re-flushed.
	if len(sink.batches) != 2 {
		t.Fatalf("sink received %d batches, want 2 (no re-flush of drained deltas)", len(sink.batches))
	}
}

// TestAggregatorFailOpen proves the hot path is fail-open: a Nil workspace, an
// empty metric, and a non-positive delta are all ignored rather than recorded,
// so a meter wiring problem degrades to "no metering" rather than poisoning the
// rollup with a bogus tenant.
func TestAggregatorFailOpen(t *testing.T) {
	sink := &fakeSink{}
	a := New(sink, Config{Clock: fixedClock(time.Now().UTC())})

	a.Record(uuid.Nil, MetricAPIRequests) // no workspace
	a.Add(uuid.New(), "", 1)              // no metric
	a.Add(uuid.New(), MetricAPIRequests, 0)
	a.Add(uuid.New(), MetricAPIRequests, -4)

	if got := a.PendingLen(); got != 0 {
		t.Fatalf("pending entries = %d, want 0 (all malformed records dropped)", got)
	}
	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if len(sink.batches) != 0 {
		t.Fatalf("sink received %d batches, want 0 (nothing valid to flush)", len(sink.batches))
	}
}

// TestAggregatorMergeBackOnFailure proves at-least-once durability: when the
// sink write fails the drained deltas are merged back into the buffer and
// retried on the next flush (without double counting once it succeeds).
func TestAggregatorMergeBackOnFailure(t *testing.T) {
	sink := &fakeSink{failNext: 1}
	a := New(sink, Config{Clock: fixedClock(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC))})
	ws := uuid.New()

	a.Add(ws, MetricAPIRequests, 4)
	if err := a.Flush(context.Background()); err == nil {
		t.Fatal("expected first flush to fail")
	}
	// Deltas must still be buffered for retry.
	if got := a.PendingLen(); got != 1 {
		t.Fatalf("pending entries after failed flush = %d, want 1 (merged back)", got)
	}
	// More traffic arrives before the retry; the retry must flush the SUM.
	a.Add(ws, MetricAPIRequests, 6)
	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("retry flush: %v", err)
	}
	if got := sink.total(ws, MetricAPIRequests); got != 10 {
		t.Fatalf("count after retry = %d, want 10 (4 retried + 6 new, no loss, no double count)", got)
	}
}

// TestAggregatorIdleBounding proves memory is bounded by the ACTIVE working set,
// not the all-time tenant count: after a flush the buffer is empty regardless of
// how many distinct tenants were seen, so an idle tenant occupies no memory.
func TestAggregatorIdleBounding(t *testing.T) {
	sink := &fakeSink{}
	a := New(sink, Config{Clock: fixedClock(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC))})

	for i := 0; i < 1000; i++ {
		a.Record(uuid.New(), MetricAPIRequests)
	}
	if got := a.PendingLen(); got != 1000 {
		t.Fatalf("pending before flush = %d, want 1000", got)
	}
	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if got := a.PendingLen(); got != 0 {
		t.Fatalf("pending after flush = %d, want 0 (drained; idle tenants hold no memory)", got)
	}
}

// TestAggregatorObserveAggregateOnly proves the flush observer (the Prometheus
// feed) is invoked with the per-METRIC aggregate summed across tenants — never a
// tenant id — so /metrics cardinality stays bounded.
func TestAggregatorObserveAggregateOnly(t *testing.T) {
	sink := &fakeSink{}
	observed := map[string]int64{}
	var mu sync.Mutex
	a := New(sink, Config{
		Clock: fixedClock(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)),
		Observe: func(metric string, n int64) {
			mu.Lock()
			observed[metric] += n
			mu.Unlock()
		},
	})

	a.Add(uuid.New(), MetricAPIRequests, 5)
	a.Add(uuid.New(), MetricAPIRequests, 8)
	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if observed[MetricAPIRequests] != 13 {
		t.Fatalf("observed api_requests = %d, want 13 (5 + 8 across two tenants)", observed[MetricAPIRequests])
	}
}

// TestAggregatorObserveSkippedOnFailure proves a failed flush does NOT advance
// the aggregate Prometheus counter (the deltas were merged back and will be
// counted on the successful retry), so the counter cannot over-count.
func TestAggregatorObserveSkippedOnFailure(t *testing.T) {
	sink := &fakeSink{failNext: 1}
	var observed int64
	a := New(sink, Config{
		Clock:   fixedClock(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)),
		Observe: func(_ string, n int64) { observed += n },
	})
	ws := uuid.New()

	a.Add(ws, MetricAPIRequests, 3)
	_ = a.Flush(context.Background()) // fails; observe must NOT fire
	if observed != 0 {
		t.Fatalf("observed after failed flush = %d, want 0", observed)
	}
	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("retry flush: %v", err)
	}
	if observed != 3 {
		t.Fatalf("observed after retry = %d, want 3 (counted once, on success)", observed)
	}
}

// TestAggregatorPeriodFromClock proves the billing period is derived from the
// clock at record time, so a record made in a different month lands in its own
// rollup row rather than the current one.
func TestAggregatorPeriodFromClock(t *testing.T) {
	sink := &fakeSink{}
	clock := time.Date(2026, 5, 31, 23, 59, 0, 0, time.UTC)
	a := New(sink, Config{Clock: func() time.Time { return clock }})
	ws := uuid.New()

	a.Record(ws, MetricAPIRequests) // May
	clock = time.Date(2026, 6, 1, 0, 1, 0, 0, time.UTC)
	a.Record(ws, MetricAPIRequests) // June
	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	periods := map[string]int64{}
	for _, b := range sink.batches {
		for _, d := range b {
			periods[d.Period] += d.Count
		}
	}
	if periods["2026-05"] != 1 || periods["2026-06"] != 1 {
		t.Fatalf("per-period counts = %v, want one each in 2026-05 and 2026-06", periods)
	}
}

// TestAggregatorRunFlushesOnShutdown proves the flush loop persists buffered
// deltas when its join function is called (graceful shutdown), so the final
// window's counts are not lost.
func TestAggregatorRunFlushesOnShutdown(t *testing.T) {
	sink := &fakeSink{}
	// A long interval guarantees the shutdown flush — not a tick — is what
	// persists the data, so the test is deterministic.
	a := New(sink, Config{FlushInterval: time.Hour, Clock: fixedClock(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC))})
	ws := uuid.New()
	a.Record(ws, MetricAPIRequests)

	join := a.Run(context.Background())
	join() // triggers the final flush and blocks until the loop exits

	if got := sink.total(ws, MetricAPIRequests); got != 1 {
		t.Fatalf("count after shutdown flush = %d, want 1", got)
	}
}

// TestAggregatorRunIsIdempotent proves a second Run is a safe no-op: the
// startOnce guards the goroutine launch, so the single-loop contract is
// self-enforcing and a stray second call cannot panic on a double close(done).
// Each returned join still stops the one loop and persists the final window.
func TestAggregatorRunIsIdempotent(t *testing.T) {
	sink := &fakeSink{}
	a := New(sink, Config{FlushInterval: time.Hour, Clock: fixedClock(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC))})
	ws := uuid.New()
	a.Record(ws, MetricAPIRequests)

	join1 := a.Run(context.Background())
	join2 := a.Run(context.Background()) // second call must not start a second loop

	join1() // stops the single loop, triggers the final flush
	join2() // must not panic on a double close(done); returns once stopped

	if got := sink.total(ws, MetricAPIRequests); got != 1 {
		t.Fatalf("count after shutdown flush = %d, want 1", got)
	}
}

// TestAggregatorConcurrentRecord is the race-detector exercise: many goroutines
// record concurrently while flushes interleave; the total persisted must equal
// the total recorded (no lost or duplicated increments).
func TestAggregatorConcurrentRecord(t *testing.T) {
	sink := &fakeSink{}
	a := New(sink, Config{Clock: fixedClock(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC))})
	ws := uuid.New()

	const goroutines, perG = 20, 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				a.Record(ws, MetricAPIRequests)
				if i%25 == 0 {
					_ = a.Flush(context.Background())
				}
			}
		}()
	}
	wg.Wait()
	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("final flush: %v", err)
	}
	if got := sink.total(ws, MetricAPIRequests); got != goroutines*perG {
		t.Fatalf("concurrent total = %d, want %d", got, goroutines*perG)
	}
}
