package tenancy

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeSink records activity calls for assertions.
type fakeSink struct {
	mu             sync.Mutex
	calls          int64
	cancelledCalls int64
	seen           map[uuid.UUID]int
	woke           bool
	notes          chan struct{}
}

func newFakeSink() *fakeSink {
	return &fakeSink{seen: make(map[uuid.UUID]int), notes: make(chan struct{}, 1024)}
}

func (s *fakeSink) RecordActivity(ctx context.Context, ws uuid.UUID, _ string) (bool, error) {
	s.mu.Lock()
	s.calls++
	s.seen[ws]++
	if ctx.Err() != nil {
		s.cancelledCalls++
	}
	woke := s.woke
	s.mu.Unlock()
	select {
	case s.notes <- struct{}{}:
	default:
	}
	return woke, nil
}

func (s *fakeSink) cancelled() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cancelledCalls
}

func (s *fakeSink) count() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestSafeThrottle(t *testing.T) {
	cases := []struct {
		throttle, idle, want time.Duration
	}{
		{60 * time.Second, 14 * 24 * time.Hour, 60 * time.Second},
		{0, time.Hour, 0},
		{-1, time.Hour, 0},
		{10 * time.Second, 60 * time.Second, 0}, // 10s > 6s (idle/10) → unsafe → off
		{5 * time.Second, 60 * time.Second, 5 * time.Second},
		{time.Hour, 0, time.Hour}, // idle unknown → accept positive throttle
	}
	for _, c := range cases {
		if got := SafeThrottle(c.throttle, c.idle); got != c.want {
			t.Errorf("SafeThrottle(%s,%s) = %s, want %s", c.throttle, c.idle, got, c.want)
		}
	}
}

func TestAsyncRecorderCoalesces(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	r := NewAsyncRecorder(newFakeSink(), AsyncRecorderConfig{
		Throttle:      time.Minute,
		IdleThreshold: 14 * 24 * time.Hour,
		Clock:         clk.now,
	})
	ws := uuid.New()

	r.Record(ws, KindAPI)
	r.Record(ws, KindAPI) // within window → coalesced
	if got := len(r.queue); got != 1 {
		t.Fatalf("queued = %d, want 1 (coalesced)", got)
	}

	clk.advance(2 * time.Minute) // past the window
	r.Record(ws, KindAPI)
	if got := len(r.queue); got != 2 {
		t.Fatalf("queued = %d, want 2 after window expiry", got)
	}

	// A different tenant is tracked independently.
	r.Record(uuid.New(), KindAPI)
	if got := len(r.queue); got != 3 {
		t.Fatalf("queued = %d, want 3 for distinct tenant", got)
	}
}

func TestAsyncRecorderNilWorkspaceIgnored(t *testing.T) {
	r := NewAsyncRecorder(newFakeSink(), AsyncRecorderConfig{})
	r.Record(uuid.Nil, KindAPI)
	if got := len(r.queue); got != 0 {
		t.Fatalf("queued = %d, want 0 for nil workspace", got)
	}
}

func TestAsyncRecorderDrainsToSink(t *testing.T) {
	sink := newFakeSink()
	r := NewAsyncRecorder(sink, AsyncRecorderConfig{}) // no throttle → every Record enqueues
	ctx, cancel := context.WithCancel(context.Background())
	join := r.Run(ctx)

	ws := uuid.New()
	for i := 0; i < 5; i++ {
		r.Record(ws, KindAPI)
		<-sink.notes // wait for the drain goroutine to persist this one
	}
	if got := sink.count(); got != 5 {
		t.Fatalf("persisted = %d, want 5", got)
	}
	cancel()
	join()
}

func TestAsyncRecorderFlushesBufferedOnShutdown(t *testing.T) {
	sink := newFakeSink()
	r := NewAsyncRecorder(sink, AsyncRecorderConfig{})
	// Enqueue before draining starts.
	for i := 0; i < 10; i++ {
		r.Record(uuid.New(), KindAPI)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: Run must still flush the buffered events
	join := r.Run(ctx)
	join()
	if got := sink.count(); got != 10 {
		t.Fatalf("flushed = %d, want 10 on shutdown", got)
	}
	// Regression: every flushed write must run with a live context. If the
	// persist context were tied to the loop's cancellation, these dequeued
	// events would hit an already-cancelled timeout context and be lost.
	if got := sink.cancelled(); got != 0 {
		t.Fatalf("%d writes saw a cancelled context, want 0", got)
	}
}

// TestAsyncRecorderPersistsWithLiveContextAfterCancel exercises the drain loop
// with a context that is cancelled while items remain queued, asserting that
// persist always receives a non-cancelled context regardless of whether the
// hot-loop branch or the ctx.Done() drain branch wins the select. This guards
// the shutdown event-loss bug where persist(ctx) on a cancelled ctx aborts the
// write.
func TestAsyncRecorderPersistsWithLiveContextAfterCancel(t *testing.T) {
	for i := 0; i < 50; i++ {
		sink := newFakeSink()
		r := NewAsyncRecorder(sink, AsyncRecorderConfig{QueueSize: 64})
		const n = 16
		for j := 0; j < n; j++ {
			r.Record(uuid.New(), KindAPI)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // cancelled with a full queue: both select branches are ready
		join := r.Run(ctx)
		join()
		if got := sink.count(); got != n {
			t.Fatalf("iter %d: persisted = %d, want %d", i, got, n)
		}
		if got := sink.cancelled(); got != 0 {
			t.Fatalf("iter %d: %d writes saw a cancelled context, want 0", i, got)
		}
	}
}

// blockingSink blocks every RecordActivity until its context is cancelled,
// simulating a stuck/slow DB so the drain's overall deadline can be observed.
type blockingSink struct{}

func (blockingSink) RecordActivity(ctx context.Context, _ uuid.UUID, _ string) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
}

// TestAsyncRecorderShutdownDrainIsBounded asserts the shutdown flush is bounded
// by DrainTimeout even when the sink never completes a write — so joinRecorder
// (and thus process shutdown / a rolling deploy) cannot wedge for
// queue_size×per-write-timeout.
func TestAsyncRecorderShutdownDrainIsBounded(t *testing.T) {
	r := NewAsyncRecorder(blockingSink{}, AsyncRecorderConfig{
		QueueSize:    256,
		DrainTimeout: 150 * time.Millisecond,
	})
	for i := 0; i < 200; i++ {
		r.Record(uuid.New(), KindAPI)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // shutdown with a backed-up queue and a sink that never returns
	join := r.Run(ctx)

	doneCh := make(chan struct{})
	go func() { join(); close(doneCh) }()
	start := time.Now()
	select {
	case <-doneCh:
	case <-time.After(5 * time.Second):
		t.Fatal("drain did not respect DrainTimeout; join blocked > 5s")
	}
	// Unbounded behaviour would be 200×5s; bounded behaviour returns shortly
	// after the 150ms deadline.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("drain took %s, want ~DrainTimeout (150ms)", elapsed)
	}
}

func TestAsyncRecorderQueueFullDrops(t *testing.T) {
	r := NewAsyncRecorder(newFakeSink(), AsyncRecorderConfig{QueueSize: 2})
	// No drain running; third enqueue must drop without blocking.
	r.Record(uuid.New(), KindAPI)
	r.Record(uuid.New(), KindAPI)
	done := make(chan struct{})
	go func() {
		r.Record(uuid.New(), KindAPI) // would block if not for the default drop
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Record blocked on a full queue")
	}
	if got := len(r.queue); got != 2 {
		t.Fatalf("queued = %d, want 2 (third dropped)", got)
	}
}

func TestNoopRecorder(t *testing.T) {
	var r ActivityRecorder = NoopRecorder{}
	r.Record(uuid.New(), KindAPI) // must not panic
}
