package usage

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// defaultFlushInterval is the flush cadence used when the configured interval
// is non-positive. It mirrors the config default; clamping here (rather than
// failing the boot) keeps a fat-fingered ACCESS_USAGE_METERING_FLUSH_INTERVAL
// from crashing a 5,000-tenant fleet, with the operator warned at boot.
const defaultFlushInterval = 30 * time.Second

// defaultFlushTimeout bounds a single flush's database write so a slow or stuck
// Postgres cannot make the flush goroutine (and thus the shutdown join) hang.
// On timeout the drained deltas are merged back and retried on the next flush,
// so a transient stall costs latency, never data.
const defaultFlushTimeout = 5 * time.Second

// Delta is one accumulated counter to add to the rollup: the running increment
// for a single (workspace, period, metric) since the last successful flush.
type Delta struct {
	WorkspaceID uuid.UUID
	Period      string
	Metric      string
	Count       int64
}

// Sink persists a batch of usage deltas. The contract is ADDITIVE and ATOMIC:
// each delta is added to the existing rollup count (count = count + delta) so
// concurrent per-replica flushes sum into one row rather than overwriting, and
// the whole batch must apply in a single transaction so a partial failure
// leaves nothing applied — which is what lets the aggregator safely merge a
// failed batch back and retry it without risking double counting.
//
// It is an interface (satisfied by *Store today) so the in-memory aggregator is
// decoupled from persistence and unit-testable with a fake, and so a future
// shared-store backend can be slotted in without touching the call sites.
type Sink interface {
	AddUsage(ctx context.Context, deltas []Delta) error
}

// counterKey is the in-memory accumulation key, mirroring the rollup's
// composite primary key (workspace, period, metric).
type counterKey struct {
	workspace uuid.UUID
	period    string
	metric    string
}

// Aggregator accumulates per-tenant usage counts in memory and flushes them to
// a Sink on an interval (and once more on shutdown). It is concurrency-safe and
// designed for the request hot path: Record is a single map increment under a
// short-held mutex, and the database write happens off the request path in the
// flush goroutine.
//
// Memory is bounded by the ACTIVE-tenant working set, not the all-time tenant
// count: each flush swaps the pending map out and replaces it with an empty
// one, so between flushes the map holds at most one entry per
// (active tenant × metric × period) seen in that window — the same
// active-set bounding the rate limiter achieves with idle eviction, achieved
// here for free by draining.
type Aggregator struct {
	sink          Sink
	flushInterval time.Duration
	flushTimeout  time.Duration
	clock         func() time.Time
	// observe, when non-nil, is invoked once per metric after a SUCCESSFUL
	// flush with the aggregate (summed-across-tenants) count flushed for that
	// metric. It feeds the non-tenant-labelled Prometheus counters, keeping
	// per-tenant cardinality out of /metrics while still surfacing fleet-wide
	// volume. It is never passed a tenant id.
	observe func(metric string, n int64)

	mu      sync.Mutex
	pending map[counterKey]int64

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// Config tunes an Aggregator.
type Config struct {
	// FlushInterval is the cadence at which accumulated deltas are flushed.
	// Non-positive uses defaultFlushInterval.
	FlushInterval time.Duration
	// FlushTimeout bounds a single flush's DB write. Non-positive uses
	// defaultFlushTimeout.
	FlushTimeout time.Duration
	// Clock overrides time.Now in tests (drives the billing period).
	Clock func() time.Time
	// Observe, when non-nil, receives the per-metric aggregate count after each
	// successful flush (for the non-tenant Prometheus counters).
	Observe func(metric string, n int64)
}

// New builds an Aggregator. Call Run to start its flush loop.
func New(sink Sink, cfg Config) *Aggregator {
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	interval := cfg.FlushInterval
	if interval <= 0 {
		interval = defaultFlushInterval
	}
	timeout := cfg.FlushTimeout
	if timeout <= 0 {
		timeout = defaultFlushTimeout
	}
	return &Aggregator{
		sink:          sink,
		flushInterval: interval,
		flushTimeout:  timeout,
		clock:         clock,
		observe:       cfg.Observe,
		pending:       make(map[counterKey]int64),
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
}

// Record adds one to the workspace's count for metric in the current billing
// period. It never blocks beyond a brief map-increment critical section and is
// safe for concurrent use. A Nil workspace is ignored (fail-open: an unkeyed
// request is never attributed to a bogus tenant).
func (a *Aggregator) Record(workspaceID uuid.UUID, metric string) {
	a.Add(workspaceID, metric, 1)
}

// Add increments the workspace's count for metric by n in the current billing
// period. n <= 0 and a Nil workspace are no-ops. Exposed so a future meter
// (e.g. connector syncs reporting a batch) can add more than one at a time.
func (a *Aggregator) Add(workspaceID uuid.UUID, metric string, n int64) {
	if workspaceID == uuid.Nil || metric == "" || n <= 0 {
		return
	}
	key := counterKey{workspace: workspaceID, period: PeriodOf(a.clock()), metric: metric}
	a.mu.Lock()
	a.pending[key] += n
	a.mu.Unlock()
}

// PendingLen returns the number of distinct (workspace, period, metric) entries
// currently buffered. Exposed for tests and an operator gauge of the active
// working set.
func (a *Aggregator) PendingLen() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.pending)
}

// Flush drains the buffered deltas and writes them through the sink in one
// additive batch. On success it emits the per-metric aggregate to observe; on
// failure it merges the drained deltas back so the next flush retries them
// (at-least-once durability — the batch is atomic, so a retry cannot double
// count). A no-op when nothing is buffered.
func (a *Aggregator) Flush(ctx context.Context) error {
	a.mu.Lock()
	if len(a.pending) == 0 {
		a.mu.Unlock()
		return nil
	}
	drained := a.pending
	a.pending = make(map[counterKey]int64)
	a.mu.Unlock()

	deltas := make([]Delta, 0, len(drained))
	for k, n := range drained {
		deltas = append(deltas, Delta{WorkspaceID: k.workspace, Period: k.period, Metric: k.metric, Count: n})
	}

	if err := a.sink.AddUsage(ctx, deltas); err != nil {
		a.mergeBack(drained)
		return err
	}

	if a.observe != nil {
		perMetric := make(map[string]int64, 2)
		for k, n := range drained {
			perMetric[k.metric] += n
		}
		for metric, n := range perMetric {
			a.observe(metric, n)
		}
	}
	return nil
}

// mergeBack re-adds a failed batch's deltas to the pending map so they are
// retried on the next flush. Bounded by the distinct-key count (not request
// volume), so even a prolonged sink outage cannot grow memory unboundedly — the
// counts grow as int64, the map does not.
func (a *Aggregator) mergeBack(drained map[counterKey]int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, n := range drained {
		a.pending[k] += n
	}
}

// Run starts the flush loop and returns a join function that blocks until the
// loop has stopped after a final flush. It mirrors the tenancy recorder's
// start/join lifecycle so main can order shutdown deterministically against the
// DB-pool close.
//
// The write context is decoupled from ctx's cancellation (context.WithoutCancel)
// so the shutdown flush still runs to its own bounded deadline after ctx is
// cancelled, rather than starting already-cancelled and losing the final
// window's counts. ctx's values (logging/tracing) are preserved.
func (a *Aggregator) Run(ctx context.Context) (join func()) {
	writeCtx := context.WithoutCancel(ctx)
	go func() {
		defer close(a.done)
		ticker := time.NewTicker(a.flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-a.stop:
				a.flushBounded(writeCtx)
				return
			case <-ctx.Done():
				a.flushBounded(writeCtx)
				return
			case <-ticker.C:
				a.flushBounded(writeCtx)
			}
		}
	}()
	return func() {
		a.stopOnce.Do(func() { close(a.stop) })
		<-a.done
	}
}

// flushBounded runs one Flush under the per-flush timeout. A failure is logged
// (not surfaced): the deltas were merged back into the pending map by Flush, so
// the next tick retries them. Flushes are at most one per interval, so even a
// sustained DB outage logs at a bounded rate. Kept private so the loop and the
// shutdown path share identical behaviour.
func (a *Aggregator) flushBounded(base context.Context) {
	ctx, cancel := context.WithTimeout(base, a.flushTimeout)
	defer cancel()
	if err := a.Flush(ctx); err != nil {
		logger.Warnf(base, "usage: flush failed (deltas retained for retry): %v", err)
	}
}
