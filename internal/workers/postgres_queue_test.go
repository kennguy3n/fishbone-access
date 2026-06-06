package workers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

func newQueueDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	return db
}

func TestPostgresQueueEnqueueClaim(t *testing.T) {
	q := NewPostgresQueue(newQueueDB(t))
	ctx := context.Background()
	ws := uuid.New()

	id, err := q.Enqueue(ctx, ws, uuid.Nil, "sync", []byte(`{"k":"v"}`))
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if id == "" {
		t.Fatal("Enqueue returned empty id")
	}

	jobs, err := q.Claim(ctx, 10)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("claimed %d jobs, want 1", len(jobs))
	}
	if jobs[0].Type != "sync" || string(jobs[0].Payload) != `{"k":"v"}` {
		t.Errorf("claimed job = %+v", jobs[0])
	}

	// A claimed job is now running and must not be re-claimed.
	again, err := q.Claim(ctx, 10)
	if err != nil {
		t.Fatalf("Claim 2: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("re-claimed %d running jobs, want 0", len(again))
	}
}

func TestPostgresQueueEnqueueValidation(t *testing.T) {
	q := NewPostgresQueue(newQueueDB(t))
	ctx := context.Background()
	if _, err := q.Enqueue(ctx, uuid.Nil, uuid.Nil, "sync", nil); err == nil {
		t.Error("Enqueue with nil workspace should error")
	}
	if _, err := q.Enqueue(ctx, uuid.New(), uuid.Nil, "", nil); err == nil {
		t.Error("Enqueue with empty type should error")
	}
}

func TestPostgresQueueComplete(t *testing.T) {
	db := newQueueDB(t)
	q := NewPostgresQueue(db)
	ctx := context.Background()
	id, _ := q.Enqueue(ctx, uuid.New(), uuid.Nil, "sync", nil)

	if err := q.Complete(ctx, id); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	var job models.AccessJob
	db.First(&job, "id = ?", id)
	if job.Status != StatusDone {
		t.Errorf("status = %q, want %q", job.Status, StatusDone)
	}
}

func TestPostgresQueueFailReschedules(t *testing.T) {
	db := newQueueDB(t)
	q := NewPostgresQueue(db)
	ctx := context.Background()
	id, _ := q.Enqueue(ctx, uuid.New(), uuid.Nil, "sync", nil)
	if _, err := q.Claim(ctx, 10); err != nil {
		t.Fatalf("Claim: %v", err)
	}

	// Fail with a future retry time: the job should not be immediately due.
	if err := q.Fail(ctx, id, 1, errors.New("boom"), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Fail: %v", err)
	}
	var job models.AccessJob
	db.First(&job, "id = ?", id)
	if job.Status != StatusRetry || job.Attempts != 1 || job.LastError != "boom" {
		t.Errorf("after Fail: status=%q attempts=%d err=%q", job.Status, job.Attempts, job.LastError)
	}
	if due, _ := q.Claim(ctx, 10); len(due) != 0 {
		t.Errorf("claimed %d jobs scheduled in the future, want 0", len(due))
	}

	// Fail with a past retry time: the job becomes due again.
	if err := q.Fail(ctx, id, 2, errors.New("boom2"), time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("Fail 2: %v", err)
	}
	due, err := q.Claim(ctx, 10)
	if err != nil {
		t.Fatalf("Claim due: %v", err)
	}
	if len(due) != 1 || due[0].Attempts != 2 {
		t.Errorf("re-claim = %+v, want 1 job with attempts=2", due)
	}
}

func TestPostgresQueueDeadLetter(t *testing.T) {
	db := newQueueDB(t)
	q := NewPostgresQueue(db)
	ctx := context.Background()
	id, _ := q.Enqueue(ctx, uuid.New(), uuid.Nil, "sync", nil)

	if err := q.DeadLetter(ctx, id, 5, errors.New("terminal")); err != nil {
		t.Fatalf("DeadLetter: %v", err)
	}
	var job models.AccessJob
	db.First(&job, "id = ?", id)
	if job.Status != StatusDeadLetter || job.Attempts != 5 || job.LastError != "terminal" {
		t.Errorf("after DeadLetter: status=%q attempts=%d err=%q", job.Status, job.Attempts, job.LastError)
	}
	// A dead-lettered job is terminal and never re-claimed.
	if due, _ := q.Claim(ctx, 10); len(due) != 0 {
		t.Errorf("claimed %d dead-lettered jobs, want 0", len(due))
	}
}

func TestPostgresQueueUpdateUnknownJob(t *testing.T) {
	q := NewPostgresQueue(newQueueDB(t))
	if err := q.Complete(context.Background(), uuid.New().String()); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("Complete unknown job err = %v, want ErrRecordNotFound", err)
	}
	if err := q.Complete(context.Background(), "not-a-uuid"); err == nil {
		t.Error("Complete with malformed id should error")
	}
}

// TestWorkerDeadLettersAfterMaxAttempts drives the real Worker loop against the
// Postgres-backed queue with an always-failing processor, asserting the job
// lands in dead_letter once attempts are exhausted.
func TestWorkerDeadLettersAfterMaxAttempts(t *testing.T) {
	db := newQueueDB(t)
	q := NewPostgresQueue(db)
	ctx := context.Background()
	id, _ := q.Enqueue(ctx, uuid.New(), uuid.Nil, "sync", nil)

	proc := ProcessorFunc(func(_ context.Context, _ Job) error {
		return errors.New("always fails")
	})
	// MaxAttempts=1 so a single failure exhausts retries immediately;
	// BaseBackoff is irrelevant because we dead-letter, not reschedule.
	w := New(q, proc, Config{MaxAttempts: 1, BatchSize: 10})

	n, err := w.drainOnce(ctx)
	if err != nil {
		t.Fatalf("drainOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("drained %d jobs, want 1", n)
	}
	var job models.AccessJob
	db.First(&job, "id = ?", id)
	if job.Status != StatusDeadLetter {
		t.Errorf("status = %q, want %q", job.Status, StatusDeadLetter)
	}
}

// TestPostgresQueueSkipLockedDetection pins the dialect-driven locking
// strategy: Claim must use FOR UPDATE SKIP LOCKED on Postgres (multi-replica
// safety) and must NOT emit it on SQLite (which rejects the clause). The
// decision is resolved once at construction from the driver's dialector, so a
// Postgres-backed queue keeps SKIP LOCKED even though each claim runs inside a
// transaction. We assert via the constructed driver rather than a live DB so
// the invariant is covered without a Postgres instance.
func TestPostgresQueueSkipLockedDetection(t *testing.T) {
	// SQLite (the test driver): no SKIP LOCKED.
	if q := NewPostgresQueue(newQueueDB(t)); q.skipLocked {
		t.Error("SQLite queue has skipLocked=true, want false")
	}

	// Postgres dialector reports name "postgres" without opening a connection,
	// so we can verify detection deterministically. This is the same handle
	// shape ztna-api/worker build in production.
	pg := &gorm.DB{Config: &gorm.Config{Dialector: postgres.Dialector{}}}
	if q := NewPostgresQueue(pg); !q.skipLocked {
		t.Error("Postgres queue has skipLocked=false, want true")
	}
}
