package workflow_engine

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
)

type fakeSweepEngine struct {
	mu       sync.Mutex
	calls    []uuid.UUID
	failOn   uuid.UUID
	failWith error
}

func (e *fakeSweepEngine) ScheduleReviewSweep(_ context.Context, workspaceID uuid.UUID, _, _, _ string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failWith != nil && workspaceID == e.failOn {
		return "", e.failWith
	}
	e.calls = append(e.calls, workspaceID)
	return uuid.NewString(), nil
}

type fakeLister struct {
	ids []uuid.UUID
	err error
}

func (l fakeLister) WorkspaceIDs(_ context.Context) ([]uuid.UUID, error) {
	return l.ids, l.err
}

func TestReviewScheduler_RunOnce_EnqueuesPerWorkspace(t *testing.T) {
	ws1, ws2 := uuid.New(), uuid.New()
	eng := &fakeSweepEngine{}
	s, err := NewReviewScheduler(eng, fakeLister{ids: []uuid.UUID{ws1, ws2}}, ReviewSchedulerConfig{})
	if err != nil {
		t.Fatalf("NewReviewScheduler: %v", err)
	}
	s.runOnce(context.Background())
	if len(eng.calls) != 2 {
		t.Fatalf("want a sweep per workspace (2), got %d", len(eng.calls))
	}
}

func TestReviewScheduler_RunOnce_ContinuesPastWorkspaceFailure(t *testing.T) {
	ws1, ws2, ws3 := uuid.New(), uuid.New(), uuid.New()
	eng := &fakeSweepEngine{failOn: ws2, failWith: errors.New("boom")}
	s, err := NewReviewScheduler(eng, fakeLister{ids: []uuid.UUID{ws1, ws2, ws3}}, ReviewSchedulerConfig{})
	if err != nil {
		t.Fatalf("NewReviewScheduler: %v", err)
	}
	s.runOnce(context.Background())
	// ws2 failed but ws1 and ws3 must still be enqueued.
	if len(eng.calls) != 2 {
		t.Fatalf("one failing workspace must not starve the rest; got %d successes", len(eng.calls))
	}
}

func TestReviewScheduler_RunOnce_ListErrorIsNonFatal(t *testing.T) {
	eng := &fakeSweepEngine{}
	s, err := NewReviewScheduler(eng, fakeLister{err: errors.New("db down")}, ReviewSchedulerConfig{})
	if err != nil {
		t.Fatalf("NewReviewScheduler: %v", err)
	}
	s.runOnce(context.Background()) // must not panic
	if len(eng.calls) != 0 {
		t.Fatalf("no sweeps should be enqueued when listing fails")
	}
}

func TestReviewScheduler_RequiresEngineAndLister(t *testing.T) {
	if _, err := NewReviewScheduler(nil, fakeLister{}, ReviewSchedulerConfig{}); err == nil {
		t.Fatalf("expected error for nil engine")
	}
	if _, err := NewReviewScheduler(&fakeSweepEngine{}, nil, ReviewSchedulerConfig{}); err == nil {
		t.Fatalf("expected error for nil lister")
	}
}

func TestReviewScheduler_RunStopsOnContextCancel(t *testing.T) {
	eng := &fakeSweepEngine{}
	s, err := NewReviewScheduler(eng, fakeLister{ids: []uuid.UUID{uuid.New()}}, ReviewSchedulerConfig{})
	if err != nil {
		t.Fatalf("NewReviewScheduler: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run so it returns immediately without sweeping
	if rerr := s.Run(ctx); !errors.Is(rerr, context.Canceled) {
		t.Fatalf("Run should return context.Canceled, got %v", rerr)
	}
	// An already-cancelled context must enqueue no work: Run honours the
	// cancellation before the immediate sweep round.
	if len(eng.calls) != 0 {
		t.Fatalf("no sweeps should be enqueued when ctx is cancelled before Run; got %d", len(eng.calls))
	}
}
