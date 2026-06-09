package access

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

// fakeDeltaConnector is a test double implementing AccessConnector +
// IdentityDeltaSyncer with scriptable delta/full behaviour. It records the
// cursors it was invoked with so the test can assert idempotent resumption.
type fakeDeltaConnector struct {
	// full enumeration pages, keyed by the starting checkpoint passed in.
	fullPages []fakePage
	// delta behaviour
	deltaErr       error // returned by SyncIdentitiesDelta (e.g. ErrDeltaTokenExpired)
	deltaPages     []fakePage
	finalDeltaLink string
	// handler error injection: return an error from the Nth (1-based) delta page.
	failDeltaOnPage int
	seededCursor    string
	seedErr         error

	// observed
	deltaCalledWith []string
	fullCalledWith  []string
	seedCalls       int
}

type fakePage struct {
	batch      []*Identity
	removed    []string
	nextCursor string
}

func (f *fakeDeltaConnector) Validate(context.Context, map[string]interface{}, map[string]interface{}) error {
	return nil
}
func (f *fakeDeltaConnector) Connect(context.Context, map[string]interface{}, map[string]interface{}) error {
	return nil
}
func (f *fakeDeltaConnector) VerifyPermissions(context.Context, map[string]interface{}, map[string]interface{}, []string) ([]string, error) {
	return nil, nil
}
func (f *fakeDeltaConnector) CountIdentities(context.Context, map[string]interface{}, map[string]interface{}) (int, error) {
	return 0, nil
}

func (f *fakeDeltaConnector) SyncIdentities(ctx context.Context, cfg, secrets map[string]interface{}, checkpoint string, handler func(batch []*Identity, nextCheckpoint string) error) error {
	f.fullCalledWith = append(f.fullCalledWith, checkpoint)
	for _, p := range f.fullPages {
		if err := handler(p.batch, p.nextCursor); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeDeltaConnector) ProvisionAccess(context.Context, map[string]interface{}, map[string]interface{}, AccessGrant) error {
	return nil
}
func (f *fakeDeltaConnector) RevokeAccess(context.Context, map[string]interface{}, map[string]interface{}, AccessGrant) error {
	return nil
}
func (f *fakeDeltaConnector) ListEntitlements(context.Context, map[string]interface{}, map[string]interface{}, string) ([]Entitlement, error) {
	return nil, nil
}
func (f *fakeDeltaConnector) GetSSOMetadata(context.Context, map[string]interface{}, map[string]interface{}) (*SSOMetadata, error) {
	return nil, nil
}
func (f *fakeDeltaConnector) GetCredentialsMetadata(context.Context, map[string]interface{}, map[string]interface{}) (map[string]interface{}, error) {
	return nil, nil
}

func (f *fakeDeltaConnector) SyncIdentitiesDelta(ctx context.Context, cfg, secrets map[string]interface{}, deltaLink string, handler func(batch []*Identity, removedExternalIDs []string, nextLink string) error) (string, error) {
	f.deltaCalledWith = append(f.deltaCalledWith, deltaLink)
	if f.deltaErr != nil {
		return "", f.deltaErr
	}
	for i, p := range f.deltaPages {
		if err := handler(p.batch, p.removed, p.nextCursor); err != nil {
			return "", err
		}
		if f.failDeltaOnPage == i+1 {
			return "", errors.New("simulated mid-stream handler/transport failure")
		}
	}
	return f.finalDeltaLink, nil
}

func (f *fakeDeltaConnector) InitialDeltaCursor(context.Context, map[string]interface{}, map[string]interface{}) (string, error) {
	f.seedCalls++
	if f.seedErr != nil {
		return "", f.seedErr
	}
	return f.seededCursor, nil
}

var _ AccessConnector = (*fakeDeltaConnector)(nil)
var _ IdentityDeltaSyncer = (*fakeDeltaConnector)(nil)

func newOrchTestStore(t *testing.T) *SyncStateStore {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("auto-migrate: %v", err)
	}
	return NewSyncStateStore(db)
}

func id(n byte) *Identity { return &Identity{ExternalID: string(rune('a' + n))} }

// TestOrchestratorFirstRunIsFullThenSeedsCursor: with no stored cursor, a
// delta-capable connector runs full and seeds a baseline cursor for next time.
func TestOrchestratorFirstRunIsFullThenSeedsCursor(t *testing.T) {
	store := newOrchTestStore(t)
	o := NewIdentityDeltaSyncOrchestrator(store)
	ws, conn := uuid.New(), uuid.New()

	fc := &fakeDeltaConnector{
		fullPages:    []fakePage{{batch: []*Identity{id(0), id(1)}}},
		seededCursor: "delta-cursor-v1",
	}
	res, err := o.Run(context.Background(), ws, conn, "", fc, nil, nil, func([]*Identity, []string) error { return nil })
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Mode != SyncModeFull {
		t.Errorf("mode = %q, want full", res.Mode)
	}
	if fc.seedCalls != 1 {
		t.Errorf("expected exactly one cursor-seed call, got %d", fc.seedCalls)
	}
	if got, _ := store.Load(context.Background(), ws, conn, ""); got != "delta-cursor-v1" {
		t.Errorf("stored cursor = %q, want seeded delta-cursor-v1", got)
	}
}

// TestOrchestratorDeltaPathPersistsFinalLink: with a stored cursor, the delta
// path runs and the provider's final delta link becomes the new watermark.
func TestOrchestratorDeltaPathPersistsFinalLink(t *testing.T) {
	store := newOrchTestStore(t)
	o := NewIdentityDeltaSyncOrchestrator(store)
	ws, conn := uuid.New(), uuid.New()
	if err := store.Save(context.Background(), ws, conn, "", "cursor-start"); err != nil {
		t.Fatal(err)
	}

	fc := &fakeDeltaConnector{
		deltaPages:     []fakePage{{batch: []*Identity{id(0)}, removed: []string{"x"}}},
		finalDeltaLink: "cursor-next",
	}
	res, err := o.Run(context.Background(), ws, conn, "", fc, nil, nil, func([]*Identity, []string) error { return nil })
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Mode != SyncModeDelta {
		t.Errorf("mode = %q, want delta", res.Mode)
	}
	if len(fc.deltaCalledWith) != 1 || fc.deltaCalledWith[0] != "cursor-start" {
		t.Errorf("delta invoked with %v, want [cursor-start]", fc.deltaCalledWith)
	}
	if res.RemovedSeen != 1 || res.IdentitiesSeen != 1 {
		t.Errorf("counters: identities=%d removed=%d", res.IdentitiesSeen, res.RemovedSeen)
	}
	if got, _ := store.Load(context.Background(), ws, conn, ""); got != "cursor-next" {
		t.Errorf("watermark = %q, want cursor-next", got)
	}
}

// TestOrchestratorPartialFailureLeavesCursorIntact is the idempotent
// partial-failure recovery guarantee: a mid-stream failure must NOT advance the
// watermark, so the next run re-enters delta from the SAME cursor.
func TestOrchestratorPartialFailureLeavesCursorIntact(t *testing.T) {
	store := newOrchTestStore(t)
	o := NewIdentityDeltaSyncOrchestrator(store)
	ws, conn := uuid.New(), uuid.New()
	if err := store.Save(context.Background(), ws, conn, "", "cursor-start"); err != nil {
		t.Fatal(err)
	}

	fc := &fakeDeltaConnector{
		deltaPages: []fakePage{
			{batch: []*Identity{id(0)}},
			{batch: []*Identity{id(1)}},
		},
		failDeltaOnPage: 1, // fail after the first page is handed off
		finalDeltaLink:  "cursor-next",
	}
	_, err := o.Run(context.Background(), ws, conn, "", fc, nil, nil, func([]*Identity, []string) error { return nil })
	if err == nil {
		t.Fatal("expected error on mid-stream failure")
	}
	// Watermark unchanged — next run resumes from the same cursor.
	if got, _ := store.Load(context.Background(), ws, conn, ""); got != "cursor-start" {
		t.Errorf("watermark advanced to %q on partial failure; want cursor-start", got)
	}

	// Second run with the same cursor (failure cleared) succeeds and advances.
	fc.failDeltaOnPage = 0
	if _, err := o.Run(context.Background(), ws, conn, "", fc, nil, nil, func([]*Identity, []string) error { return nil }); err != nil {
		t.Fatalf("resume run: %v", err)
	}
	if len(fc.deltaCalledWith) != 2 || fc.deltaCalledWith[1] != "cursor-start" {
		t.Errorf("resume did not re-enter delta from cursor-start: %v", fc.deltaCalledWith)
	}
	if got, _ := store.Load(context.Background(), ws, conn, ""); got != "cursor-next" {
		t.Errorf("watermark after resume = %q, want cursor-next", got)
	}
}

// TestOrchestratorExpiredCursorFallsBackToFull is the 410-Gone path: the
// provider rejects the cursor, the orchestrator drops it, runs a full sync, and
// seeds a fresh cursor.
func TestOrchestratorExpiredCursorFallsBackToFull(t *testing.T) {
	store := newOrchTestStore(t)
	o := NewIdentityDeltaSyncOrchestrator(store)
	ws, conn := uuid.New(), uuid.New()
	if err := store.Save(context.Background(), ws, conn, "", "stale-cursor"); err != nil {
		t.Fatal(err)
	}

	fc := &fakeDeltaConnector{
		deltaErr:     ErrDeltaTokenExpired,
		fullPages:    []fakePage{{batch: []*Identity{id(0), id(1), id(2)}}},
		seededCursor: "fresh-cursor",
	}
	res, err := o.Run(context.Background(), ws, conn, "", fc, nil, nil, func([]*Identity, []string) error { return nil })
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Mode != SyncModeDeltaThenFullFallback {
		t.Errorf("mode = %q, want delta_then_full_fallback", res.Mode)
	}
	if len(fc.fullCalledWith) != 1 || fc.fullCalledWith[0] != "" {
		t.Errorf("full sync should run from empty checkpoint, got %v", fc.fullCalledWith)
	}
	if res.IdentitiesSeen != 3 {
		t.Errorf("identities seen = %d, want 3", res.IdentitiesSeen)
	}
	if got, _ := store.Load(context.Background(), ws, conn, ""); got != "fresh-cursor" {
		t.Errorf("watermark after fallback = %q, want fresh-cursor", got)
	}
}

// TestOrchestratorSeedFailureIsNonFatal: a failure to seed the baseline cursor
// after a full sync is logged but does not fail the sync; the cursor is cleared
// so the next run does another full sync.
func TestOrchestratorSeedFailureIsNonFatal(t *testing.T) {
	store := newOrchTestStore(t)
	o := NewIdentityDeltaSyncOrchestrator(store)
	ws, conn := uuid.New(), uuid.New()

	fc := &fakeDeltaConnector{
		fullPages: []fakePage{{batch: []*Identity{id(0)}}},
		seedErr:   errors.New("provider unavailable for baseline"),
	}
	res, err := o.Run(context.Background(), ws, conn, "", fc, nil, nil, func([]*Identity, []string) error { return nil })
	if err != nil {
		t.Fatalf("seed failure should be non-fatal, got %v", err)
	}
	if res.Mode != SyncModeFull {
		t.Errorf("mode = %q, want full", res.Mode)
	}
	if got, _ := store.Load(context.Background(), ws, conn, ""); got != "" {
		t.Errorf("cursor should be empty after seed failure, got %q", got)
	}
}
