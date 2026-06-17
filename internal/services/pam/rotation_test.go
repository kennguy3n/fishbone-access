package pam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/tenancy"
)

// fixedBudget is a tenancy.budgetResolver returning the same per-tenant cap for
// every workspace, letting a scheduler test pin MaxConcurrentSyncs.
type fixedBudget struct{ max int }

func (b fixedBudget) BudgetFor(context.Context, uuid.UUID) (tenancy.Budget, error) {
	return tenancy.Budget{MaxConcurrentSyncs: b.max}, nil
}

// --- rotation test harness ------------------------------------------------

// fakeExecutor is an in-memory RotationExecutor: it records calls and returns
// scripted results so the engine's orchestration (re-seal, rollback, event
// recording) can be exercised without a live SSH/DB upstream.
type fakeExecutor struct {
	protocol     string
	next         Secret
	rotateErr    error
	restoreErr   error
	rotateCalls  int
	restoreCalls int
	restoreLive  Secret
	restorePrev  Secret
}

func (f *fakeExecutor) Protocol() string { return f.protocol }

func (f *fakeExecutor) Rotate(_ context.Context, _ *models.PAMTarget, _ Secret) (Secret, error) {
	f.rotateCalls++
	if f.rotateErr != nil {
		return Secret{}, f.rotateErr
	}
	return f.next, nil
}

func (f *fakeExecutor) Restore(_ context.Context, _ *models.PAMTarget, liveNow, restore Secret) error {
	f.restoreCalls++
	f.restoreLive = liveNow
	f.restorePrev = restore
	return f.restoreErr
}

// fakeGate is an in-memory hibernation gate keyed by workspace.
type fakeGate struct {
	run map[uuid.UUID]bool
	err error
}

func (g fakeGate) ShouldRunPeriodic(_ context.Context, ws uuid.UUID) (bool, error) {
	if g.err != nil {
		return false, g.err
	}
	return g.run[ws], nil
}

// fakeProvisioner is an in-memory dbCredentialProvisioner recording mint/drop.
type fakeProvisioner struct {
	createErr    error
	dropErr      error
	createCalls  int
	dropCalls    int
	lastUsername string
}

func (p *fakeProvisioner) Create(_ context.Context, _ *models.PAMTarget, _ Secret, username, _ string, _ time.Time) error {
	p.createCalls++
	p.lastUsername = username
	return p.createErr
}

func (p *fakeProvisioner) Drop(_ context.Context, _ *models.PAMTarget, _ Secret, username string) error {
	p.dropCalls++
	p.lastUsername = username
	return p.dropErr
}

func seedRotationTarget(t *testing.T, v *Vault, ws uuid.UUID, name, protocol, password string) *models.PAMTarget {
	t.Helper()
	target, err := v.CreateTarget(context.Background(), CreateTargetInput{
		WorkspaceID: ws,
		Name:        name,
		Protocol:    protocol,
		Address:     "host.internal:5432",
		Username:    "admin",
		Secret:      Secret{Username: "admin", Password: password},
		Actor:       "tester",
	})
	if err != nil {
		t.Fatalf("seed target %s: %v", name, err)
	}
	return target
}

// fixedClock returns a clock function pinned to t.
func fixedClock(at time.Time) func() time.Time {
	return func() time.Time { return at }
}

// --- policy CRUD ----------------------------------------------------------

func TestRotationPolicyService_CRUD(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	target := seedRotationTarget(t, v, ws, "pg-prod", models.PAMProtocolPostgres, "s3cr3t")

	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	svc := NewRotationPolicyService(db, v, NewExecutorRegistry(time.Second))
	svc.SetClock(fixedClock(now))
	ctx := context.Background()

	// Create an interval policy.
	created, err := svc.UpsertPolicy(ctx, ws, target.ID, PolicyInput{
		Mode:            models.RotationModeInterval,
		IntervalSeconds: 24 * 3600,
		Enabled:         true,
	}, "admin")
	if err != nil {
		t.Fatalf("UpsertPolicy create: %v", err)
	}
	if created.NextRotationAt == nil || !created.NextRotationAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("next rotation = %v, want %v", created.NextRotationAt, now.Add(24*time.Hour))
	}

	// Read back.
	got, err := svc.GetPolicy(ctx, ws, target.ID)
	if err != nil || got == nil {
		t.Fatalf("GetPolicy: %v (got=%v)", err, got)
	}
	if got.ID != created.ID {
		t.Fatalf("GetPolicy returned different row: %s != %s", got.ID, created.ID)
	}
	list, err := svc.ListPolicies(ctx, ws)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListPolicies = %d rows, err %v", len(list), err)
	}

	// Update the same policy to disabled mode: schedule must clear and the row
	// id must be stable (idempotent upsert, no duplicate).
	updated, err := svc.UpsertPolicy(ctx, ws, target.ID, PolicyInput{
		Mode:    models.RotationModeDisabled,
		Enabled: true,
	}, "admin")
	if err != nil {
		t.Fatalf("UpsertPolicy update: %v", err)
	}
	if updated.ID != created.ID {
		t.Fatalf("upsert created a new row: %s != %s", updated.ID, created.ID)
	}
	if updated.NextRotationAt != nil {
		t.Fatalf("disabled mode must clear next rotation, got %v", updated.NextRotationAt)
	}

	// Delete soft-deletes the policy.
	if err := svc.DeletePolicy(ctx, ws, target.ID, "admin"); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	if got, err := svc.GetPolicy(ctx, ws, target.ID); err != nil || got != nil {
		t.Fatalf("policy still present after delete: got=%v err=%v", got, err)
	}
}

func TestRotationPolicyService_Validation(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	pg := seedRotationTarget(t, v, ws, "pg", models.PAMProtocolPostgres, "pw")
	ssh := seedRotationTarget(t, v, ws, "ssh", models.PAMProtocolSSH, "pw")

	svc := NewRotationPolicyService(db, v, NewExecutorRegistry(time.Second))
	ctx := context.Background()

	cases := []struct {
		name   string
		target uuid.UUID
		in     PolicyInput
	}{
		{
			name:   "unknown mode",
			target: pg.ID,
			in:     PolicyInput{Mode: "weekly", Enabled: true},
		},
		{
			name:   "interval below floor",
			target: pg.ID,
			in:     PolicyInput{Mode: models.RotationModeInterval, IntervalSeconds: 60, Enabled: true},
		},
		{
			name:   "dynamic on ssh",
			target: ssh.ID,
			in:     PolicyInput{Mode: models.RotationModeDisabled, DynamicEnabled: true, Enabled: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.UpsertPolicy(ctx, ws, tc.target, tc.in, "admin"); !errors.Is(err, ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

// --- engine ---------------------------------------------------------------

func newEngineWithExecutor(t *testing.T, db *gorm.DB, v *Vault, ex *fakeExecutor, now time.Time) *RotationEngine {
	t.Helper()
	reg := &ExecutorRegistry{}
	reg.Register(ex)
	eng := NewRotationEngine(db, v, reg)
	eng.SetClock(fixedClock(now))
	return eng
}

func upsertIntervalPolicy(t *testing.T, db *gorm.DB, v *Vault, ws, target uuid.UUID, now time.Time) {
	t.Helper()
	svc := NewRotationPolicyService(db, v, NewExecutorRegistry(time.Second))
	svc.SetClock(fixedClock(now))
	if _, err := svc.UpsertPolicy(context.Background(), ws, target, PolicyInput{
		Mode:            models.RotationModeInterval,
		IntervalSeconds: 24 * 3600,
		Enabled:         true,
	}, "admin"); err != nil {
		t.Fatalf("seed interval policy: %v", err)
	}
}

func TestRotationEngine_Success(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	target := seedRotationTarget(t, v, ws, "ssh-box", models.PAMProtocolSSH, "old-pw")

	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	upsertIntervalPolicy(t, db, v, ws, target.ID, now.Add(-time.Hour))
	ex := &fakeExecutor{protocol: models.PAMProtocolSSH, next: Secret{Username: "admin", Password: "new-pw"}}
	eng := newEngineWithExecutor(t, db, v, ex, now)
	ctx := context.Background()

	event, err := eng.RotateTarget(ctx, ws, target.ID, models.RotationTriggerManual, "admin", nil)
	if err != nil {
		t.Fatalf("RotateTarget: %v", err)
	}
	if event.Status != models.RotationStatusSuccess {
		t.Fatalf("event status = %q, want success", event.Status)
	}
	if ex.rotateCalls != 1 || ex.restoreCalls != 0 {
		t.Fatalf("executor calls rotate=%d restore=%d, want 1/0", ex.rotateCalls, ex.restoreCalls)
	}

	// The vault must now open the NEW credential.
	reloaded, err := v.GetTarget(ctx, ws, target.ID)
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	sec, err := v.OpenSecret(ctx, reloaded)
	if err != nil {
		t.Fatalf("OpenSecret: %v", err)
	}
	if sec.Password != "new-pw" {
		t.Fatalf("sealed password = %q, want new-pw", sec.Password)
	}

	// Policy health advanced: success, last_rotation_at set, next advanced.
	var p models.RotationPolicy
	if err := db.Where("workspace_id = ? AND target_id = ?", ws, target.ID).Take(&p).Error; err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if p.LastStatus != models.RotationStatusSuccess {
		t.Fatalf("policy last_status = %q, want success", p.LastStatus)
	}
	if p.LastRotationAt == nil || !p.LastRotationAt.Equal(now) {
		t.Fatalf("last_rotation_at = %v, want %v", p.LastRotationAt, now)
	}
	if p.NextRotationAt == nil || !p.NextRotationAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("next_rotation_at = %v, want %v", p.NextRotationAt, now.Add(24*time.Hour))
	}
}

func TestRotationEngine_RotateFailureLeavesUpstreamUntouched(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	target := seedRotationTarget(t, v, ws, "pg", models.PAMProtocolPostgres, "old-pw")

	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	upsertIntervalPolicy(t, db, v, ws, target.ID, now.Add(-time.Hour))
	ex := &fakeExecutor{protocol: models.PAMProtocolPostgres, rotateErr: errors.New("ssh dial refused")}
	eng := newEngineWithExecutor(t, db, v, ex, now)
	ctx := context.Background()

	event, err := eng.RotateTarget(ctx, ws, target.ID, models.RotationTriggerScheduled, "scheduler", nil)
	if err == nil {
		t.Fatal("expected error from failed rotation")
	}
	if event.Status != models.RotationStatusFailed {
		t.Fatalf("event status = %q, want failed", event.Status)
	}
	// Rotate failed → upstream untouched → no rollback attempted.
	if ex.restoreCalls != 0 {
		t.Fatalf("restore called %d times on rotate failure, want 0", ex.restoreCalls)
	}
	// Vault still opens the ORIGINAL credential.
	reloaded, _ := v.GetTarget(ctx, ws, target.ID)
	sec, err := v.OpenSecret(ctx, reloaded)
	if err != nil {
		t.Fatalf("OpenSecret: %v", err)
	}
	if sec.Password != "old-pw" {
		t.Fatalf("sealed password = %q, want unchanged old-pw", sec.Password)
	}
	// Policy records the failure but still advances the schedule (no hammering).
	var p models.RotationPolicy
	_ = db.Where("workspace_id = ? AND target_id = ?", ws, target.ID).Take(&p).Error
	if p.LastStatus != models.RotationStatusFailed {
		t.Fatalf("policy last_status = %q, want failed", p.LastStatus)
	}
	if p.NextRotationAt == nil || !p.NextRotationAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("next_rotation_at = %v, want advanced to %v", p.NextRotationAt, now.Add(24*time.Hour))
	}
}

// TestRotationEngine_UnsupportedProtocolIsPreflight verifies that rotating a
// target whose protocol has no executor is treated as a PREFLIGHT failure: the
// engine returns ErrRotationUnsupported with a NIL event and records no
// RotationEvent (and does not touch policy health), so a manual "rotate now"
// against an unrotatable target can't pollute the history timeline. Only the
// manual API path can reach this — UpsertPolicy rejects interval/checkin
// policies on unsupported protocols.
func TestRotationEngine_UnsupportedProtocolIsPreflight(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	// Seed an RDP target; the registry below only knows Postgres, so RDP has
	// no executor.
	target := seedRotationTarget(t, v, ws, "rdp-box", models.PAMProtocolRDP, "old-pw")

	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	ex := &fakeExecutor{protocol: models.PAMProtocolPostgres}
	eng := newEngineWithExecutor(t, db, v, ex, now)
	ctx := context.Background()

	event, err := eng.RotateTarget(ctx, ws, target.ID, models.RotationTriggerManual, "admin", nil)
	if !errors.Is(err, ErrRotationUnsupported) {
		t.Fatalf("err = %v, want ErrRotationUnsupported", err)
	}
	if event != nil {
		t.Fatalf("event = %+v, want nil (preflight failure records nothing)", event)
	}
	// No RotationEvent row may have been written for the unsupported attempt.
	var count int64
	if err := db.Model(&models.RotationEvent{}).
		Where("workspace_id = ? AND target_id = ?", ws, target.ID).
		Count(&count).Error; err != nil {
		t.Fatalf("count rotation events: %v", err)
	}
	if count != 0 {
		t.Fatalf("recorded %d rotation event(s), want 0 for unsupported protocol", count)
	}
	// The executor was never invoked.
	if ex.rotateCalls != 0 {
		t.Fatalf("executor.Rotate called %d times, want 0", ex.rotateCalls)
	}
}

func TestRotationEngine_PersistFailureRollsBackUpstream(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	target := seedRotationTarget(t, v, ws, "pg", models.PAMProtocolPostgres, "old-pw")

	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	upsertIntervalPolicy(t, db, v, ws, target.ID, now.Add(-time.Hour))
	// The executor "rotates" successfully but returns an EMPTY secret, which the
	// vault refuses to seal (ErrValidation). This deterministically drives the
	// persist-failure path: the upstream already accepts `next`, so the engine
	// must roll the upstream back to `current` via Restore.
	ex := &fakeExecutor{protocol: models.PAMProtocolPostgres, next: Secret{}}
	eng := newEngineWithExecutor(t, db, v, ex, now)
	ctx := context.Background()

	event, err := eng.RotateTarget(ctx, ws, target.ID, models.RotationTriggerManual, "admin", nil)
	if err == nil {
		t.Fatal("expected persist failure error")
	}
	if event.Status != models.RotationStatusFailed {
		t.Fatalf("event status = %q, want failed", event.Status)
	}
	if ex.rotateCalls != 1 || ex.restoreCalls != 1 {
		t.Fatalf("executor calls rotate=%d restore=%d, want 1/1 (rollback)", ex.rotateCalls, ex.restoreCalls)
	}
	// Restore must re-install the ORIGINAL credential, authenticating with what
	// Rotate installed.
	if ex.restorePrev.Password != "old-pw" {
		t.Fatalf("rollback restored %q, want old-pw", ex.restorePrev.Password)
	}
	// Vault still opens the original credential (never persisted the bad one).
	reloaded, _ := v.GetTarget(ctx, ws, target.ID)
	sec, _ := v.OpenSecret(ctx, reloaded)
	if sec.Password != "old-pw" {
		t.Fatalf("sealed password = %q, want unchanged old-pw", sec.Password)
	}
}

// --- scheduler ------------------------------------------------------------

func TestRotationScheduler_IntervalDueSelection(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	due := seedRotationTarget(t, v, ws, "due", models.PAMProtocolPostgres, "old-due")
	notDue := seedRotationTarget(t, v, ws, "notdue", models.PAMProtocolPostgres, "old-notdue")

	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	// `due` was last scheduled a day ago (next_rotation_at in the past); `notDue`
	// is scheduled in the future.
	upsertIntervalPolicy(t, db, v, ws, due.ID, now.Add(-48*time.Hour))
	upsertIntervalPolicy(t, db, v, ws, notDue.ID, now)

	ex := &fakeExecutor{protocol: models.PAMProtocolPostgres, next: Secret{Username: "admin", Password: "rotated"}}
	eng := newEngineWithExecutor(t, db, v, ex, now)
	sched, err := NewRotationScheduler(db, eng, RotationSchedulerConfig{})
	if err != nil {
		t.Fatalf("NewRotationScheduler: %v", err)
	}
	sched.SetClock(fixedClock(now))

	n, err := sched.sweepInterval(context.Background())
	if err != nil {
		t.Fatalf("sweepInterval: %v", err)
	}
	if n != 1 {
		t.Fatalf("rotated %d targets, want 1 (only the due one)", n)
	}
	// Only `due` should have been rotated.
	if got := openPassword(t, v, ws, due.ID); got != "rotated" {
		t.Fatalf("due target password = %q, want rotated", got)
	}
	if got := openPassword(t, v, ws, notDue.ID); got != "old-notdue" {
		t.Fatalf("notDue target password = %q, want unchanged", got)
	}
}

func TestRotationScheduler_HibernationGate(t *testing.T) {
	t.Run("dormant defers", func(t *testing.T) {
		db := newTestDB(t)
		ws := seedWorkspace(t, db, "tenant-a")
		v := NewVault(db, newTestEncryptor(t), nil)
		target := seedRotationTarget(t, v, ws, "pg", models.PAMProtocolPostgres, "old")
		now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
		upsertIntervalPolicy(t, db, v, ws, target.ID, now.Add(-48*time.Hour))
		ex := &fakeExecutor{protocol: models.PAMProtocolPostgres, next: Secret{Password: "rotated"}}
		eng := newEngineWithExecutor(t, db, v, ex, now)
		sched, _ := NewRotationScheduler(db, eng, RotationSchedulerConfig{})
		sched.SetClock(fixedClock(now))
		skips := 0
		sched.WithHibernationGate(fakeGate{run: map[uuid.UUID]bool{ws: false}}, func() { skips++ })

		n, err := sched.sweepInterval(context.Background())
		if err != nil {
			t.Fatalf("sweepInterval: %v", err)
		}
		if n != 0 || ex.rotateCalls != 0 {
			t.Fatalf("dormant tenant rotated (n=%d rotateCalls=%d), want 0", n, ex.rotateCalls)
		}
		if skips != 1 {
			t.Fatalf("onSkipDormant called %d times, want 1", skips)
		}
	})

	t.Run("awake rotates", func(t *testing.T) {
		db := newTestDB(t)
		ws := seedWorkspace(t, db, "tenant-a")
		v := NewVault(db, newTestEncryptor(t), nil)
		target := seedRotationTarget(t, v, ws, "pg", models.PAMProtocolPostgres, "old")
		now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
		upsertIntervalPolicy(t, db, v, ws, target.ID, now.Add(-48*time.Hour))
		ex := &fakeExecutor{protocol: models.PAMProtocolPostgres, next: Secret{Password: "rotated"}}
		eng := newEngineWithExecutor(t, db, v, ex, now)
		sched, _ := NewRotationScheduler(db, eng, RotationSchedulerConfig{})
		sched.SetClock(fixedClock(now))
		sched.WithHibernationGate(fakeGate{run: map[uuid.UUID]bool{ws: true}}, nil)

		n, _ := sched.sweepInterval(context.Background())
		if n != 1 {
			t.Fatalf("awake tenant rotated %d, want 1", n)
		}
	})

	t.Run("gate error fails open", func(t *testing.T) {
		db := newTestDB(t)
		ws := seedWorkspace(t, db, "tenant-a")
		v := NewVault(db, newTestEncryptor(t), nil)
		target := seedRotationTarget(t, v, ws, "pg", models.PAMProtocolPostgres, "old")
		now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
		upsertIntervalPolicy(t, db, v, ws, target.ID, now.Add(-48*time.Hour))
		ex := &fakeExecutor{protocol: models.PAMProtocolPostgres, next: Secret{Password: "rotated"}}
		eng := newEngineWithExecutor(t, db, v, ex, now)
		sched, _ := NewRotationScheduler(db, eng, RotationSchedulerConfig{})
		sched.SetClock(fixedClock(now))
		sched.WithHibernationGate(fakeGate{err: errors.New("classifier down")}, nil)

		n, _ := sched.sweepInterval(context.Background())
		if n != 1 {
			t.Fatalf("gate error must fail open and rotate, got n=%d", n)
		}
	})
}

// TestRotationScheduler_PeriodicRunnerSweep wires the production fair-scheduler
// path (WithPeriodicRunner) end to end: several due targets in one workspace are
// rotated through the runner's bounded fan-out. The global ceiling is pinned to
// 1 so the in-memory SQLite test DB (no concurrent writers) is driven serially
// while still exercising the Sweep launch/Acquire/release/run loop and the
// rotated-count tally.
func TestRotationScheduler_PeriodicRunnerSweep(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	const targets = 4
	ids := make([]uuid.UUID, targets)
	for i := range ids {
		tg := seedRotationTarget(t, v, ws, "pg-"+uuid.NewString()[:8], models.PAMProtocolPostgres, "old")
		upsertIntervalPolicy(t, db, v, ws, tg.ID, now.Add(-48*time.Hour))
		ids[i] = tg.ID
	}

	ex := &fakeExecutor{protocol: models.PAMProtocolPostgres, next: Secret{Username: "admin", Password: "rotated"}}
	eng := newEngineWithExecutor(t, db, v, ex, now)
	sched, _ := NewRotationScheduler(db, eng, RotationSchedulerConfig{})
	sched.SetClock(fixedClock(now))

	// Ceiling 1 serialises the fan-out for the single-writer test DB; no
	// per-tenant cap (nil budgets) so every due target rotates.
	runner := tenancy.NewPeriodicRunner(fakeGate{run: map[uuid.UUID]bool{ws: true}}, nil, tenancy.NewFairScheduler(1))
	dormantSkips, budgetSkips := 0, 0
	sched.WithPeriodicRunner(runner, func() { dormantSkips++ }, func() { budgetSkips++ })

	n, err := sched.sweepInterval(context.Background())
	if err != nil {
		t.Fatalf("sweepInterval: %v", err)
	}
	if n != targets {
		t.Fatalf("rotated %d targets via Sweep, want %d", n, targets)
	}
	if dormantSkips != 0 || budgetSkips != 0 {
		t.Fatalf("unexpected skips (dormant=%d budget=%d), want 0/0", dormantSkips, budgetSkips)
	}
	for _, id := range ids {
		if got := openPassword(t, v, ws, id); got != "rotated" {
			t.Fatalf("target %s password = %q, want rotated", id, got)
		}
	}
}

// TestRotationScheduler_PeriodicRunnerBudgetDefersTarget verifies the budget
// branch of the Sweep path: with the tenant's only concurrency slot pre-held
// (cap 1) the due target is deferred (onSkipBudget fires) and NOT rotated, so a
// later tick can pick it up — deferral never drops a rotation.
func TestRotationScheduler_PeriodicRunnerBudgetDefersTarget(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	target := seedRotationTarget(t, v, ws, "pg", models.PAMProtocolPostgres, "old")
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	upsertIntervalPolicy(t, db, v, ws, target.ID, now.Add(-48*time.Hour))

	ex := &fakeExecutor{protocol: models.PAMProtocolPostgres, next: Secret{Password: "rotated"}}
	eng := newEngineWithExecutor(t, db, v, ex, now)
	sched, _ := NewRotationScheduler(db, eng, RotationSchedulerConfig{})
	sched.SetClock(fixedClock(now))

	fair := tenancy.NewFairScheduler(8)
	hold, ok := fair.TryAcquire(ws, 1) // occupy the tenant's only slot (cap 1)
	if !ok {
		t.Fatal("pre-hold acquire should succeed")
	}
	defer hold()
	runner := tenancy.NewPeriodicRunner(fakeGate{run: map[uuid.UUID]bool{ws: true}}, fixedBudget{max: 1}, fair)
	dormantSkips, budgetSkips := 0, 0
	sched.WithPeriodicRunner(runner, func() { dormantSkips++ }, func() { budgetSkips++ })

	n, err := sched.sweepInterval(context.Background())
	if err != nil {
		t.Fatalf("sweepInterval: %v", err)
	}
	if n != 0 || ex.rotateCalls != 0 {
		t.Fatalf("over-budget target rotated (n=%d rotateCalls=%d), want 0", n, ex.rotateCalls)
	}
	if budgetSkips != 1 || dormantSkips != 0 {
		t.Fatalf("skips = budget:%d dormant:%d, want budget:1 dormant:0", budgetSkips, dormantSkips)
	}
	if got := openPassword(t, v, ws, target.ID); got != "old" {
		t.Fatalf("deferred target password = %q, want unchanged old", got)
	}
}

func TestRotationScheduler_CheckinDueSelection(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	target := seedRotationTarget(t, v, ws, "pg", models.PAMProtocolPostgres, "old")

	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	// rotate-on-checkin policy, never rotated yet.
	svc := NewRotationPolicyService(db, v, NewExecutorRegistry(time.Second))
	svc.SetClock(fixedClock(now.Add(-2 * time.Hour)))
	if _, err := svc.UpsertPolicy(context.Background(), ws, target.ID, PolicyInput{
		Mode:            models.RotationModeDisabled,
		RotateOnCheckin: true,
		Enabled:         true,
	}, "admin"); err != nil {
		t.Fatalf("seed checkin policy: %v", err)
	}
	// Pin created_at to the test timeline (GORM's Base hook stamps wall-clock
	// time otherwise) so the "lease ended after the policy" comparison is
	// deterministic.
	if err := db.Model(&models.RotationPolicy{}).
		Where("workspace_id = ? AND target_id = ?", ws, target.ID).
		Update("created_at", now.Add(-2*time.Hour)).Error; err != nil {
		t.Fatalf("pin created_at: %v", err)
	}

	// A lease that ended (expired) one hour ago — after the policy was created.
	endedAt := now.Add(-time.Hour)
	grantedAt := now.Add(-90 * time.Minute)
	lease := &models.PAMLease{
		WorkspaceID: ws,
		TargetID:    target.ID,
		Subject:     "user@tenant",
		GrantedAt:   &grantedAt,
		ExpiresAt:   &endedAt,
		ExpiredAt:   &endedAt,
	}
	if err := db.Create(lease).Error; err != nil {
		t.Fatalf("seed lease: %v", err)
	}

	ex := &fakeExecutor{protocol: models.PAMProtocolPostgres, next: Secret{Password: "rotated"}}
	eng := newEngineWithExecutor(t, db, v, ex, now)
	sched, _ := NewRotationScheduler(db, eng, RotationSchedulerConfig{})
	sched.SetClock(fixedClock(now))

	n, err := sched.sweepCheckin(context.Background())
	if err != nil {
		t.Fatalf("sweepCheckin: %v", err)
	}
	if n != 1 {
		t.Fatalf("checkin sweep rotated %d, want 1", n)
	}
	// The recorded event must carry the lease id and checkin trigger.
	var ev models.RotationEvent
	if err := db.Where("workspace_id = ? AND target_id = ?", ws, target.ID).Order("created_at DESC").Take(&ev).Error; err != nil {
		t.Fatalf("load event: %v", err)
	}
	if ev.Trigger != models.RotationTriggerCheckin || ev.LeaseID == nil || *ev.LeaseID != lease.ID {
		t.Fatalf("event trigger=%q lease=%v, want checkin + lease %s", ev.Trigger, ev.LeaseID, lease.ID)
	}

	// Running again is idempotent: last_rotation_at advanced past the checkin, so
	// the same ended lease no longer selects.
	n2, err := sched.sweepCheckin(context.Background())
	if err != nil {
		t.Fatalf("sweepCheckin 2: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("second checkin sweep rotated %d, want 0 (idempotent)", n2)
	}
}

// --- dynamic credentials --------------------------------------------------

func enableDynamic(t *testing.T, db *gorm.DB, v *Vault, ws, target uuid.UUID, ttlSeconds int64) {
	t.Helper()
	svc := NewRotationPolicyService(db, v, NewExecutorRegistry(time.Second))
	if _, err := svc.UpsertPolicy(context.Background(), ws, target, PolicyInput{
		Mode:              models.RotationModeDisabled,
		DynamicEnabled:    true,
		DynamicTTLSeconds: ttlSeconds,
		Enabled:           true,
	}, "admin"); err != nil {
		t.Fatalf("enable dynamic: %v", err)
	}
}

func TestDynamicCredential_MintAndReapOnLeaseEnd(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	target := seedRotationTarget(t, v, ws, "pg", models.PAMProtocolPostgres, "admin-pw")
	enableDynamic(t, db, v, ws, target.ID, 3600)

	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	grantedAt := now.Add(-time.Minute)
	expiresAt := now.Add(time.Hour)
	lease := &models.PAMLease{
		WorkspaceID: ws, TargetID: target.ID, Subject: "user@tenant",
		GrantedAt: &grantedAt, ExpiresAt: &expiresAt,
	}
	if err := db.Create(lease).Error; err != nil {
		t.Fatalf("seed live lease: %v", err)
	}

	prov := &fakeProvisioner{}
	svc := NewDynamicCredentialService(db, v, time.Second).withProvisioner(prov)
	svc.SetClock(fixedClock(now))
	ctx := context.Background()

	minted, err := svc.MintForLease(ctx, ws, target.ID, lease.ID, "user@tenant")
	if err != nil {
		t.Fatalf("MintForLease: %v", err)
	}
	if minted.Password == "" || minted.Username == "" {
		t.Fatalf("minted credential incomplete: %+v", minted)
	}
	if prov.createCalls != 1 || prov.lastUsername != minted.Username {
		t.Fatalf("provisioner create calls=%d user=%q, want 1 / %q", prov.createCalls, prov.lastUsername, minted.Username)
	}
	// Active row recorded; password never persisted.
	active, err := NewRotationPolicyService(db, v, nil).ListActiveDynamicCredentials(ctx, ws, target.ID)
	if err != nil || len(active) != 1 {
		t.Fatalf("active creds = %d, err %v", len(active), err)
	}

	// Live lease → reaper leaves it alone.
	if reaped, err := svc.ReapDue(ctx); err != nil || reaped != 0 {
		t.Fatalf("reaped %d while lease live (err %v), want 0", reaped, err)
	}

	// End the lease (revoke) → reaper drops the credential.
	revokedAt := now.Add(2 * time.Minute)
	if err := db.Model(&models.PAMLease{}).Where("id = ?", lease.ID).
		Update("revoked_at", revokedAt).Error; err != nil {
		t.Fatalf("revoke lease: %v", err)
	}
	svc.SetClock(fixedClock(now.Add(3 * time.Minute)))
	reaped, err := svc.ReapDue(ctx)
	if err != nil {
		t.Fatalf("ReapDue: %v", err)
	}
	if reaped != 1 || prov.dropCalls != 1 {
		t.Fatalf("reaped=%d dropCalls=%d, want 1/1", reaped, prov.dropCalls)
	}
	var cred models.DynamicCredential
	_ = db.Where("workspace_id = ? AND target_id = ?", ws, target.ID).Take(&cred).Error
	if cred.State != models.DynamicCredentialStateRevoked {
		t.Fatalf("cred state = %q, want revoked", cred.State)
	}
}

func TestDynamicCredential_ReapOnTTLExpiry(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	target := seedRotationTarget(t, v, ws, "pg", models.PAMProtocolPostgres, "admin-pw")
	enableDynamic(t, db, v, ws, target.ID, 60) // 60s TTL

	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	grantedAt := now.Add(-time.Minute)
	expiresAt := now.Add(time.Hour) // lease stays live; TTL is the trigger
	lease := &models.PAMLease{
		WorkspaceID: ws, TargetID: target.ID, Subject: "user@tenant",
		GrantedAt: &grantedAt, ExpiresAt: &expiresAt,
	}
	if err := db.Create(lease).Error; err != nil {
		t.Fatalf("seed lease: %v", err)
	}

	prov := &fakeProvisioner{}
	svc := NewDynamicCredentialService(db, v, time.Second).withProvisioner(prov)
	svc.SetClock(fixedClock(now))
	ctx := context.Background()
	if _, err := svc.MintForLease(ctx, ws, target.ID, lease.ID, "user@tenant"); err != nil {
		t.Fatalf("MintForLease: %v", err)
	}

	// Advance past the TTL → reaper drops with state=expired.
	svc.SetClock(fixedClock(now.Add(2 * time.Minute)))
	reaped, err := svc.ReapDue(ctx)
	if err != nil {
		t.Fatalf("ReapDue: %v", err)
	}
	if reaped != 1 || prov.dropCalls != 1 {
		t.Fatalf("reaped=%d dropCalls=%d, want 1/1", reaped, prov.dropCalls)
	}
	var cred models.DynamicCredential
	_ = db.Where("workspace_id = ? AND target_id = ?", ws, target.ID).Take(&cred).Error
	if cred.State != models.DynamicCredentialStateExpired {
		t.Fatalf("cred state = %q, want expired", cred.State)
	}
}

func TestDynamicCredential_MintRejections(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	ctx := context.Background()
	leaseID := uuid.New()

	// Unsupported protocol (ssh) → ErrDynamicUnsupported.
	ssh := seedRotationTarget(t, v, ws, "ssh", models.PAMProtocolSSH, "pw")
	svc := NewDynamicCredentialService(db, v, time.Second).withProvisioner(&fakeProvisioner{})
	if _, err := svc.MintForLease(ctx, ws, ssh.ID, leaseID, "user"); !errors.Is(err, ErrDynamicUnsupported) {
		t.Fatalf("ssh mint err = %v, want ErrDynamicUnsupported", err)
	}

	// Supported protocol but dynamic not enabled → ErrDynamicNotEnabled.
	pg := seedRotationTarget(t, v, ws, "pg", models.PAMProtocolPostgres, "pw")
	if _, err := svc.MintForLease(ctx, ws, pg.ID, leaseID, "user"); !errors.Is(err, ErrDynamicNotEnabled) {
		t.Fatalf("pg mint (no policy) err = %v, want ErrDynamicNotEnabled", err)
	}
}

func TestSQLLiteralQuoting(t *testing.T) {
	// quoteSQLLiteral (PostgreSQL, standard_conforming_strings=on) only doubles
	// single quotes; a backslash is a literal and must be left untouched.
	pgCases := map[string]string{
		`abc`:   `'abc'`,
		`a'b`:   `'a''b'`,
		`a\b`:   `'a\b'`,
		`back\`: `'back\'`,
	}
	for in, want := range pgCases {
		if got := quoteSQLLiteral(in); got != want {
			t.Errorf("quoteSQLLiteral(%q) = %q, want %q", in, got, want)
		}
	}

	// mysqlQuoteLiteral must escape BOTH backslashes and single quotes, since
	// MySQL's default sql_mode treats backslash as an escape character. A value
	// ending in a backslash is the case the rollback/Restore path must survive:
	// it must not escape the closing quote.
	mysqlCases := map[string]string{
		`abc`:     `'abc'`,
		`a'b`:     `'a''b'`,
		`a\b`:     `'a\\b'`,
		`back\`:   `'back\\'`,
		`a\'b`:    `'a\\''b'`,
		"a\x00b":  `'a\0b'`,  // raw NUL escaped as \0
		"a\\\x00": `'a\\\0'`, // trailing backslash then NUL: backslash doubled, NUL -> \0
	}
	for in, want := range mysqlCases {
		if got := mysqlQuoteLiteral(in); got != want {
			t.Errorf("mysqlQuoteLiteral(%q) = %q, want %q", in, got, want)
		}
	}
}

// openPassword decrypts a target's current sealed password (test helper).
func openPassword(t *testing.T, v *Vault, ws, target uuid.UUID) string {
	t.Helper()
	tgt, err := v.GetTarget(context.Background(), ws, target)
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	sec, err := v.OpenSecret(context.Background(), tgt)
	if err != nil {
		t.Fatalf("OpenSecret: %v", err)
	}
	return sec.Password
}
