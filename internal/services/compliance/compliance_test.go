package compliance

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// newTestDB opens an in-memory SQLite database with the full schema migrated.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("auto-migrate: %v", err)
	}
	return db
}

func seedWorkspace(t *testing.T, db *gorm.DB, tenant string) uuid.UUID {
	t.Helper()
	ws := &models.Workspace{Name: tenant, IAMCoreTenantID: tenant, Plan: "base"}
	if err := db.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	return ws.ID
}

func seedConnector(t *testing.T, db *gorm.DB, workspaceID uuid.UUID, provider string) uuid.UUID {
	t.Helper()
	c := &models.AccessConnector{WorkspaceID: workspaceID, Provider: provider, Status: "active"}
	if err := db.Create(c).Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}
	return c.ID
}

// seedGrant inserts an active grant. The compliance services only read grant
// rows (enumeration, worklist join), so a directly-inserted row is sufficient
// and avoids dragging the whole provisioning pipeline into these tests.
func seedGrant(t *testing.T, db *gorm.DB, workspaceID, connectorID uuid.UUID, subject, resource, role string) uuid.UUID {
	t.Helper()
	g := &models.AccessGrant{
		WorkspaceID:   workspaceID,
		ConnectorID:   connectorID,
		IAMCoreUserID: subject,
		ResourceRef:   resource,
		Role:          role,
		State:         lifecycle.GrantStateActive,
		GrantedAt:     time.Now().UTC(),
	}
	if err := db.Create(g).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	return g.ID
}

// seedPolicy inserts a policy row. The pack writer only reads policy rows for
// the export snapshot, so a directly-inserted row is sufficient.
func seedPolicy(t *testing.T, db *gorm.DB, workspaceID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	p := &models.Policy{WorkspaceID: workspaceID, Name: name, State: "active", Version: 1}
	if err := db.Create(p).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	return p.ID
}

// seedRevokedGrant inserts a grant already revoked at revokedAt, so the pack
// writer's "active at any point in the period" filter (revoked_at >= from) is
// exercised — the exact branch the cross-tenant OR-precedence guard covers.
func seedRevokedGrant(t *testing.T, db *gorm.DB, workspaceID, connectorID uuid.UUID, subject, resource string, grantedAt, revokedAt time.Time) uuid.UUID {
	t.Helper()
	g := &models.AccessGrant{
		WorkspaceID:   workspaceID,
		ConnectorID:   connectorID,
		IAMCoreUserID: subject,
		ResourceRef:   resource,
		Role:          "reader",
		State:         lifecycle.GrantStateRevoked,
		GrantedAt:     grantedAt.UTC(),
		RevokedAt:     &revokedAt,
	}
	if err := db.Create(g).Error; err != nil {
		t.Fatalf("seed revoked grant: %v", err)
	}
	return g.ID
}

// appendEvent appends one audit event to a workspace's hash chain through the
// real lifecycle appender, so the chain bookkeeping (seq, prev/chain hash,
// micro-truncated timestamp) matches production exactly.
func appendEvent(t *testing.T, db *gorm.DB, workspaceID uuid.UUID, action, target string) {
	t.Helper()
	if err := lifecycle.AppendAudit(context.Background(), db, time.Now(), lifecycle.AuditInput{
		WorkspaceID: workspaceID,
		Actor:       "tester",
		Action:      action,
		TargetRef:   target,
	}); err != nil {
		t.Fatalf("append event %q: %v", action, err)
	}
}

// fakeRevoker records the grants it was asked to revoke and flips their state,
// standing in for the real provisioning-service teardown (which would need live
// connectors). A mock is appropriate here because the connector-side teardown
// is an external dependency exercised by the lifecycle package's own tests; the
// certification service contract under test is only "close drives RevokeGrant
// once per staged revoke".
type fakeRevoker struct {
	mu     sync.Mutex
	db     *gorm.DB
	calls  map[uuid.UUID]int
	failOn map[uuid.UUID]bool
	// beforeCall, if set, runs at the top of each RevokeGrant before any work.
	// Tests use it to perturb state mid-loop (e.g. cancel the request context)
	// and prove the post-commit teardown is resilient to it.
	beforeCall func(grantID uuid.UUID)
}

func newFakeRevoker(db *gorm.DB) *fakeRevoker {
	return &fakeRevoker{db: db, calls: map[uuid.UUID]int{}, failOn: map[uuid.UUID]bool{}}
}

func (f *fakeRevoker) RevokeGrant(ctx context.Context, workspaceID, grantID uuid.UUID, actor, reason string) error {
	// Run the perturbation hook BEFORE taking f.mu so a hook is free to call the
	// revoker's own lock-taking helpers (e.g. callCount) without deadlocking.
	// beforeCall is set once during test setup, so reading it here is race-free.
	if f.beforeCall != nil {
		f.beforeCall(grantID)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[grantID]++
	if f.failOn[grantID] {
		return context.DeadlineExceeded // any non-nil error to exercise retry
	}
	// Honour the GrantRevoker idempotency contract: a grant that is no longer
	// active (e.g. already revoked out-of-band) is a clean no-op returning nil,
	// exactly as AccessProvisioningService.RevokeGrant does — no second state
	// flip and no duplicate evidence event.
	var g models.AccessGrant
	if err := f.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, grantID).
		Take(&g).Error; err != nil {
		return err
	}
	if g.State != lifecycle.GrantStateActive {
		return nil
	}
	now := time.Now().UTC()
	if err := f.db.WithContext(ctx).Model(&models.AccessGrant{}).
		Where("workspace_id = ? AND id = ?", workspaceID, grantID).
		Updates(map[string]any{"state": lifecycle.GrantStateRevoked, "revoked_at": now}).Error; err != nil {
		return err
	}
	// Mirror the real revoke path appending an evidence event to the chain.
	return lifecycle.AppendAudit(ctx, f.db, now, lifecycle.AuditInput{
		WorkspaceID: workspaceID,
		Actor:       actor,
		Action:      "access_grant.revoked",
		TargetRef:   grantID.String(),
	})
}

func (f *fakeRevoker) callCount(grantID uuid.UUID) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[grantID]
}
