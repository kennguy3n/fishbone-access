package tenancy

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// ActivityRecorder is the write side of activity tracking, as the request hot
// path sees it: a fire-and-forget Record that must not block the caller. The
// HTTP middleware depends only on this interface, so the recorder's buffering
// strategy is an implementation detail.
type ActivityRecorder interface {
	Record(workspaceID uuid.UUID, kind string)
}

// NoopRecorder discards activity. It is wired when tracking is disabled or in a
// degraded (no-DB) boot, so the middleware can depend on a non-nil recorder.
type NoopRecorder struct{}

// Record does nothing.
func (NoopRecorder) Record(uuid.UUID, string) {}

var _ ActivityRecorder = NoopRecorder{}
var _ ActivityRecorder = (*AsyncRecorder)(nil)

// activitySink is the persistence dependency of AsyncRecorder (satisfied by
// *Service / *Store). Narrowed to an interface for testability.
type activitySink interface {
	RecordActivity(ctx context.Context, workspaceID uuid.UUID, kind string) (bool, error)
}

// AsyncRecorder decouples activity recording from the request path with two
// mechanisms that together keep write volume near zero at 5,000-tenant scale:
//
//   - Coalescing: at most one enqueue per tenant per throttle window. A tenant
//     hammering the API still produces ~one write per window, not per request.
//   - Async drain: Record only enqueues (non-blocking); a single background
//     goroutine performs the DB writes, so request latency never includes a
//     write. If the queue is momentarily full the event is dropped — safe,
//     because activity is best-effort and the next request re-enqueues.
//
// Correctness invariant: the throttle window MUST be far smaller than the
// dormancy idle threshold (the constructor enforces this). Then a coalesced
// burst can never hide a wake — a tenant can only be dormant after idle ≥
// threshold, by which point any in-window suppression has long expired, so the
// first post-dormancy request always enqueues and wakes the tenant.
type AsyncRecorder struct {
	sink         activitySink
	throttle     time.Duration
	drainTimeout time.Duration
	clock        func() time.Time

	queue chan recordReq

	mu       sync.Mutex
	lastSeen map[uuid.UUID]time.Time
}

type recordReq struct {
	workspaceID uuid.UUID
	kind        string
}

// AsyncRecorderConfig configures an AsyncRecorder.
type AsyncRecorderConfig struct {
	// Throttle is the per-tenant coalescing window. <=0 disables coalescing
	// (every Record enqueues). It is clamped to 0 if it is not safely below
	// IdleThreshold (see SafeThrottle).
	Throttle time.Duration
	// IdleThreshold is the dormancy threshold, used only to validate Throttle.
	IdleThreshold time.Duration
	// QueueSize bounds the buffered enqueue channel. Defaults to 4096.
	QueueSize int
	// DrainTimeout bounds the total wall time the shutdown drain may spend
	// flushing the buffered queue, so a slow/stuck DB cannot make the join wedge
	// the process for queue_size×per-write-timeout (hours in the worst case) and
	// stall a rolling deploy. <=0 uses the 30s default. Per-write timeouts still
	// apply within this budget; once it elapses the remaining best-effort events
	// are abandoned (the next boot re-derives state from the reconcile sweep).
	DrainTimeout time.Duration
	// Clock overrides time.Now in tests.
	Clock func() time.Time
}

// defaultDrainTimeout bounds the shutdown flush when DrainTimeout is unset.
const defaultDrainTimeout = 30 * time.Second

// SafeThrottle returns throttle if it is positive and at most a small fraction
// of idle (so coalescing can never mask a wake), else 0 (coalescing off). The
// 1/10 bound is deliberately conservative: with the defaults (60s throttle, 14d
// idle) it is satisfied by six orders of magnitude.
func SafeThrottle(throttle, idle time.Duration) time.Duration {
	if throttle <= 0 {
		return 0
	}
	if idle > 0 && throttle > idle/10 {
		return 0
	}
	return throttle
}

// NewAsyncRecorder builds an AsyncRecorder. Call Run to start its drain loop.
func NewAsyncRecorder(sink activitySink, cfg AsyncRecorderConfig) *AsyncRecorder {
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	qs := cfg.QueueSize
	if qs <= 0 {
		qs = 4096
	}
	drainTimeout := cfg.DrainTimeout
	if drainTimeout <= 0 {
		drainTimeout = defaultDrainTimeout
	}
	return &AsyncRecorder{
		sink:         sink,
		throttle:     SafeThrottle(cfg.Throttle, cfg.IdleThreshold),
		drainTimeout: drainTimeout,
		clock:        clock,
		queue:        make(chan recordReq, qs),
		lastSeen:     make(map[uuid.UUID]time.Time),
	}
}

// Record enqueues an activity event for the workspace. It never blocks: if the
// event is within the coalescing window it is suppressed, and if the queue is
// full it is dropped (the next request re-enqueues). Safe for concurrent use.
func (r *AsyncRecorder) Record(workspaceID uuid.UUID, kind string) {
	if workspaceID == uuid.Nil {
		return
	}
	if r.throttle > 0 {
		now := r.clock()
		r.mu.Lock()
		last, ok := r.lastSeen[workspaceID]
		if ok && now.Sub(last) < r.throttle {
			r.mu.Unlock()
			return
		}
		r.mu.Unlock()
	}
	select {
	case r.queue <- recordReq{workspaceID: workspaceID, kind: kind}:
		// Mark seen only after a successful enqueue so a dropped event is
		// retried by the next request rather than suppressed for a full window.
		if r.throttle > 0 {
			now := r.clock()
			r.mu.Lock()
			r.lastSeen[workspaceID] = now
			r.pruneLocked(now)
			r.mu.Unlock()
		}
	default:
		// Queue full: drop. Best-effort by design (see type doc).
	}
}

// maxTracked bounds the lastSeen map so a long-lived process that has seen a
// huge number of distinct tenants cannot grow it without limit. Far above the
// 5,000-tenant target, so it never triggers in practice — a backstop, not a
// steady-state limiter.
const maxTracked = 100_000

// pruneLocked drops coalescing entries older than the throttle window when the
// map grows large. Callers must hold r.mu.
func (r *AsyncRecorder) pruneLocked(now time.Time) {
	if len(r.lastSeen) < maxTracked {
		return
	}
	for id, t := range r.lastSeen {
		if now.Sub(t) >= r.throttle {
			delete(r.lastSeen, id)
		}
	}
}

// Run drains the queue until ctx is cancelled, persisting each event through
// the sink. It returns a join function that blocks until the drain goroutine
// has fully stopped (after flushing what is already queued), mirroring the
// lifecycle scheduler's start/join pattern so shutdown is race-free against the
// DB pool close.
func (r *AsyncRecorder) Run(ctx context.Context) (join func()) {
	// The persist write context is decoupled from ctx's cancellation up front:
	// when ctx is cancelled at shutdown, select may still pick a ready queue
	// item over ctx.Done(), and persisting that item with the cancelled ctx
	// would make persist's bounded-timeout context start already-cancelled, fail
	// the write, and silently lose an event that was already dequeued. Using a
	// non-cancellable derivative keeps ctx's values (for logging/tracing) while
	// letting every write run to its own 5s deadline — the same base the final
	// drain uses, so the hot-loop and shutdown paths behave identically.
	writeCtx := context.WithoutCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			// Check shutdown first so a cancelled ctx deterministically enters the
			// bounded drain rather than racing the queue branch (select picks
			// uniformly when both are ready), which would persist with the
			// unbounded base context.
			if ctx.Err() != nil {
				// Best-effort drain of what is already buffered so activity that
				// arrived just before shutdown is not lost. Bounded by
				// drainTimeout so a slow DB can never wedge the join (and thus
				// the process) for queue_size×per-write-timeout.
				drainCtx, cancel := context.WithTimeout(writeCtx, r.drainTimeout)
				r.drainRemaining(drainCtx)
				cancel()
				return
			}
			select {
			case <-ctx.Done():
				// Loop back; the top-of-loop check runs the bounded drain.
			case req := <-r.queue:
				r.persist(writeCtx, req)
			}
		}
	}()
	return func() { <-done }
}

// drainRemaining flushes already-queued events using drainCtx, which carries
// both the non-cancellable base (so a cancelled parent does not abort the final
// writes) and the overall drain deadline. It returns as soon as the queue is
// empty or the deadline elapses, whichever comes first — so the total flush is
// bounded regardless of queue depth or DB latency.
func (r *AsyncRecorder) drainRemaining(drainCtx context.Context) {
	for {
		select {
		case <-drainCtx.Done():
			return
		default:
		}
		select {
		case <-drainCtx.Done():
			return
		case req := <-r.queue:
			r.persist(drainCtx, req)
		default:
			return
		}
	}
}

// persist writes one event with a bounded timeout so a slow DB cannot wedge the
// drain loop. Errors are logged, not surfaced — activity is best-effort.
func (r *AsyncRecorder) persist(ctx context.Context, req recordReq) {
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	woke, err := r.sink.RecordActivity(wctx, req.workspaceID, req.kind)
	if err != nil {
		logger.Warnf(ctx, "tenancy: record activity workspace_id=%s kind=%s: %v", req.workspaceID, req.kind, err)
		return
	}
	if woke {
		logger.Infof(ctx, "tenancy: tenant woken from dormancy workspace_id=%s kind=%s", req.workspaceID, req.kind)
	}
}
