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

// stubGate is a programmable hibernationGate for the gate-honouring tests.
type stubGate struct {
	dormant map[uuid.UUID]bool // workspaces the gate reports dormant (run=false)
	err     error
	seen    []uuid.UUID
}

func (g *stubGate) ShouldRunPeriodic(_ context.Context, ws uuid.UUID) (bool, error) {
	g.seen = append(g.seen, ws)
	if g.err != nil {
		return false, g.err
	}
	return !g.dormant[ws], nil
}

// TestReviewScheduler_SkipsDormantWorkspaces proves only dormant workspaces are
// deferred: an active workspace is still swept, the dormant one is not, and the
// skip observer counts exactly the deferral.
func TestReviewScheduler_SkipsDormantWorkspaces(t *testing.T) {
	active, dormant := uuid.New(), uuid.New()
	eng := &fakeSweepEngine{}
	skips := 0
	s, err := NewReviewScheduler(eng, fakeLister{ids: []uuid.UUID{active, dormant}}, ReviewSchedulerConfig{})
	if err != nil {
		t.Fatalf("NewReviewScheduler: %v", err)
	}
	s.WithHibernationGate(&stubGate{dormant: map[uuid.UUID]bool{dormant: true}}, func() { skips++ })
	s.runOnce(context.Background())

	if len(eng.calls) != 1 || eng.calls[0] != active {
		t.Fatalf("want only the active workspace swept, got %v", eng.calls)
	}
	if skips != 1 {
		t.Errorf("skip observer fired %d times, want 1 (the dormant workspace)", skips)
	}
}

// TestReviewScheduler_FailOpenOnGateError proves the FAIL-OPEN contract: a gate
// error must NEVER defer a sweep — every workspace is enqueued and none counted
// skipped.
func TestReviewScheduler_FailOpenOnGateError(t *testing.T) {
	ws1, ws2 := uuid.New(), uuid.New()
	eng := &fakeSweepEngine{}
	skips := 0
	s, err := NewReviewScheduler(eng, fakeLister{ids: []uuid.UUID{ws1, ws2}}, ReviewSchedulerConfig{})
	if err != nil {
		t.Fatalf("NewReviewScheduler: %v", err)
	}
	s.WithHibernationGate(&stubGate{err: errors.New("classify boom")}, func() { skips++ })
	s.runOnce(context.Background())

	if len(eng.calls) != 2 {
		t.Fatalf("gate error must fail open (sweep all); got %d sweeps", len(eng.calls))
	}
	if skips != 0 {
		t.Errorf("skip observer fired %d times on gate error, want 0", skips)
	}
}

// TestReviewScheduler_NilGateSweepsAll proves a scheduler built without a gate
// (hibernation disabled / AlwaysRun never attached) sweeps every workspace.
func TestReviewScheduler_NilGateSweepsAll(t *testing.T) {
	ws1, ws2 := uuid.New(), uuid.New()
	eng := &fakeSweepEngine{}
	s, err := NewReviewScheduler(eng, fakeLister{ids: []uuid.UUID{ws1, ws2}}, ReviewSchedulerConfig{})
	if err != nil {
		t.Fatalf("NewReviewScheduler: %v", err)
	}
	s.runOnce(context.Background()) // no WithHibernationGate call
	if len(eng.calls) != 2 {
		t.Fatalf("nil gate must sweep all; got %d", len(eng.calls))
	}
}
