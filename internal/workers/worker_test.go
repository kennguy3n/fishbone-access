package workers

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// memQueue is an in-memory Queue for testing the drain/retry loop.
type memQueue struct {
	mu         sync.Mutex
	pending    []Job
	completed  []string
	failed     []string
	deadLetter []string
}

func (q *memQueue) Claim(_ context.Context, max int) ([]Job, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.pending) == 0 {
		return nil, nil
	}
	n := max
	if n > len(q.pending) {
		n = len(q.pending)
	}
	batch := q.pending[:n]
	q.pending = q.pending[n:]
	return batch, nil
}

func (q *memQueue) Complete(_ context.Context, jobID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.completed = append(q.completed, jobID)
	return nil
}

func (q *memQueue) Fail(_ context.Context, jobID string, _ int, _ error, _ time.Time) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.failed = append(q.failed, jobID)
	return nil
}

func (q *memQueue) DeadLetter(_ context.Context, jobID string, _ int, _ error) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.deadLetter = append(q.deadLetter, jobID)
	return nil
}

func (q *memQueue) counts() (int, int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.completed), len(q.failed)
}

func (q *memQueue) deadLetterCount() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.deadLetter)
}

func TestWorkerProcessesAndCompletes(t *testing.T) {
	q := &memQueue{pending: []Job{{ID: "a", Type: "sync"}, {ID: "b", Type: "sync"}}}
	var processed int
	proc := ProcessorFunc(func(_ context.Context, _ Job) error {
		processed++
		return nil
	})
	w := New(q, proc, Config{PollInterval: 5 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = w.Run(ctx) }()

	waitFor(t, func() bool { c, _ := q.counts(); return c == 2 })
	cancel()

	if processed != 2 {
		t.Errorf("processed = %d, want 2", processed)
	}
}

func TestWorkerFailsOnProcessorError(t *testing.T) {
	q := &memQueue{pending: []Job{{ID: "x", Type: "sync"}}}
	proc := ProcessorFunc(func(_ context.Context, _ Job) error {
		return errors.New("boom")
	})
	w := New(q, proc, Config{PollInterval: 5 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = w.Run(ctx) }()

	waitFor(t, func() bool { _, f := q.counts(); return f == 1 })
	cancel()
}

func TestWorkerDeadLettersWhenAttemptsExhausted(t *testing.T) {
	// Job already on its final attempt (Attempts=1, MaxAttempts=2): the next
	// failure must dead-letter rather than reschedule.
	q := &memQueue{pending: []Job{{ID: "x", Type: "sync", Attempts: 1}}}
	proc := ProcessorFunc(func(_ context.Context, _ Job) error {
		return errors.New("boom")
	})
	w := New(q, proc, Config{PollInterval: 5 * time.Millisecond, MaxAttempts: 2})

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = w.Run(ctx) }()

	waitFor(t, func() bool { return q.deadLetterCount() == 1 })
	cancel()

	if _, f := q.counts(); f != 0 {
		t.Errorf("Fail called %d times, want 0 (job should dead-letter, not reschedule)", f)
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	q := &memQueue{}
	w := New(q, ProcessorFunc(func(context.Context, Job) error { return nil }), Config{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := w.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run err = %v, want context.Canceled", err)
	}
}

func TestBackoffDoublesAndCaps(t *testing.T) {
	w := New(&memQueue{}, ProcessorFunc(func(context.Context, Job) error { return nil }), Config{BaseBackoff: time.Second})
	if d := w.backoff(1); d != time.Second {
		t.Errorf("backoff(1) = %s, want 1s", d)
	}
	if d := w.backoff(3); d != 4*time.Second {
		t.Errorf("backoff(3) = %s, want 4s", d)
	}
	if d := w.backoff(100); d != time.Hour {
		t.Errorf("backoff(100) = %s, want 1h cap", d)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}
