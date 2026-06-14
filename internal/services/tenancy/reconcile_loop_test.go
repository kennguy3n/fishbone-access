package tenancy

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeReconciler is a programmable reconciler for the loop's observer tests. It
// signals each sweep on swept so a test can wait for the immediate startup sweep
// deterministically instead of sleeping.
type fakeReconciler struct {
	mu           sync.Mutex
	dormant      int64
	countErr     error
	reconcileErr error
	swept        chan struct{}
}

func (f *fakeReconciler) Reconcile(context.Context) (ReconcileResult, error) {
	f.mu.Lock()
	err := f.reconcileErr
	f.mu.Unlock()
	if f.swept != nil {
		select {
		case f.swept <- struct{}{}:
		default:
		}
	}
	if err != nil {
		return ReconcileResult{}, err
	}
	return ReconcileResult{}, nil
}

func (f *fakeReconciler) CountDormant(context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dormant, f.countErr
}

// TestReconcileLoopPublishesDormantGauge proves the loop calls the dormant
// observer with the authoritative count after a successful sweep — the seam
// that feeds the scale-to-zero gauge.
func TestReconcileLoopPublishesDormantGauge(t *testing.T) {
	rec := &fakeReconciler{dormant: 42, swept: make(chan struct{}, 4)}
	var got int64 = -1
	var mu sync.Mutex
	loop := NewReconcileLoop(rec, time.Hour).WithDormantObserver(func(n int64) {
		mu.Lock()
		got = n
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	join := loop.Run(ctx)
	<-rec.swept // wait for the immediate startup sweep
	cancel()
	join()

	mu.Lock()
	defer mu.Unlock()
	if got != 42 {
		t.Fatalf("dormant observer got %d, want 42", got)
	}
}

// TestReconcileLoopGaugeSilentOnCountError proves a CountDormant failure does
// not stomp the gauge with a garbage value: the observer is not invoked.
func TestReconcileLoopGaugeSilentOnCountError(t *testing.T) {
	rec := &fakeReconciler{dormant: 7, countErr: errors.New("count boom"), swept: make(chan struct{}, 4)}
	var calls int64
	loop := NewReconcileLoop(rec, time.Hour).WithDormantObserver(func(int64) {
		atomic.AddInt64(&calls, 1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	join := loop.Run(ctx)
	<-rec.swept
	cancel()
	join()

	if n := atomic.LoadInt64(&calls); n != 0 {
		t.Fatalf("observer fired %d times on count error, want 0", n)
	}
}

// TestReconcileLoopNilObserverIsPureClassifier proves the loop runs sweeps
// without an observer (the disabled-observability path) and does not panic.
func TestReconcileLoopNilObserverIsPureClassifier(t *testing.T) {
	rec := &fakeReconciler{swept: make(chan struct{}, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	join := NewReconcileLoop(rec, time.Hour).Run(ctx) // no observer
	<-rec.swept
	cancel()
	join()
}
