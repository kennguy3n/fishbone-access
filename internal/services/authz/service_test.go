package authz

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

func newTestService(t *testing.T, cacheTTL time.Duration) (*RBACService, *gorm.DB) {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewRBACService(db, cacheTTL), db
}

func ctx() context.Context { return context.Background() }

func TestGetMembershipHappyPath(t *testing.T) {
	svc, _ := newTestService(t, 0)
	ws := uuid.New()
	if err := svc.UpsertMember(ctx(), ws, "user-1", RoleAdmin, SystemActor); err != nil {
		t.Fatalf("seed: %v", err)
	}
	m, err := svc.GetMembership(ctx(), ws, "user-1")
	if err != nil {
		t.Fatalf("GetMembership: %v", err)
	}
	if m.Role != RoleAdmin {
		t.Fatalf("role = %q, want admin", m.Role)
	}
}

func TestGetMembershipNotFound(t *testing.T) {
	svc, _ := newTestService(t, 0)
	_, err := svc.GetMembership(ctx(), uuid.New(), "ghost")
	if !errors.Is(err, ErrMembershipNotFound) {
		t.Fatalf("err = %v, want ErrMembershipNotFound", err)
	}
}

// TestGetMembershipPositiveCache proves a hit within TTL is served from cache
// (an out-of-band row delete is not observed until the entry expires), and that
// invalidation/expiry restores DB truth.
func TestGetMembershipPositiveCache(t *testing.T) {
	svc, db := newTestService(t, 60*time.Second)
	now := time.Unix(1_700_000_000, 0)
	svc.SetClock(func() time.Time { return now })

	ws := uuid.New()
	if err := svc.UpsertMember(ctx(), ws, "user-1", RoleOperator, SystemActor); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Prime the cache.
	if _, err := svc.GetMembership(ctx(), ws, "user-1"); err != nil {
		t.Fatalf("prime: %v", err)
	}
	// Delete the row out-of-band (bypassing the service so the cache is NOT
	// invalidated).
	if err := db.Where("workspace_id = ? AND user_id = ?", ws, "user-1").
		Delete(&models.WorkspaceMember{}).Error; err != nil {
		t.Fatalf("oob delete: %v", err)
	}
	// Still within TTL: cached role returned.
	if m, err := svc.GetMembership(ctx(), ws, "user-1"); err != nil || m.Role != RoleOperator {
		t.Fatalf("cached read = (%v, %v), want operator", m, err)
	}
	// Advance past TTL: cache expires, DB truth (gone) surfaces.
	now = now.Add(61 * time.Second)
	if _, err := svc.GetMembership(ctx(), ws, "user-1"); !errors.Is(err, ErrMembershipNotFound) {
		t.Fatalf("post-expiry err = %v, want ErrMembershipNotFound", err)
	}
}

// TestGetMembershipNegativeCache proves a non-member lookup is cached so a flood
// of non-member JWTs does not hammer the DB, and that a member added afterwards
// becomes visible once the short negative TTL lapses.
func TestGetMembershipNegativeCache(t *testing.T) {
	svc, db := newTestService(t, 60*time.Second)
	now := time.Unix(1_700_000_000, 0)
	svc.SetClock(func() time.Time { return now })
	ws := uuid.New()

	if _, err := svc.GetMembership(ctx(), ws, "user-1"); !errors.Is(err, ErrMembershipNotFound) {
		t.Fatalf("first lookup err = %v, want ErrMembershipNotFound", err)
	}
	// Insert a row out-of-band (no cache invalidation).
	if err := db.Create(&models.WorkspaceMember{
		WorkspaceID: ws, UserID: "user-1", Role: string(RoleAdmin), CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("oob insert: %v", err)
	}
	// Within negative TTL: still cached as not-found.
	if _, err := svc.GetMembership(ctx(), ws, "user-1"); !errors.Is(err, ErrMembershipNotFound) {
		t.Fatalf("within neg-TTL err = %v, want still cached not-found", err)
	}
	// After negative TTL (5s default): the new member is visible.
	now = now.Add(6 * time.Second)
	if m, err := svc.GetMembership(ctx(), ws, "user-1"); err != nil || m.Role != RoleAdmin {
		t.Fatalf("post neg-TTL = (%v, %v), want admin", m, err)
	}
}

func TestUpsertMemberRoleChangeAudited(t *testing.T) {
	svc, db := newTestService(t, 0)
	ws := uuid.New()
	if err := svc.UpsertMember(ctx(), ws, "user-1", RoleOperator, SystemActor); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.UpsertMember(ctx(), ws, "user-1", RoleAdmin, "actor-9"); err != nil {
		t.Fatalf("update: %v", err)
	}
	m, err := svc.GetMembership(ctx(), ws, "user-1")
	if err != nil || m.Role != RoleAdmin {
		t.Fatalf("post-update = (%v, %v), want admin", m, err)
	}
	// Two audit rows: added + role_changed.
	var count int64
	if err := db.Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND action LIKE 'rbac.member.%'", ws).
		Count(&count).Error; err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if count != 2 {
		t.Fatalf("audit rows = %d, want 2 (added + role_changed)", count)
	}
}

// TestUpsertMemberNoOpReStampNotAudited proves re-asserting the same role emits
// no audit row (only real transitions are recorded).
func TestUpsertMemberNoOpReStampNotAudited(t *testing.T) {
	svc, db := newTestService(t, 0)
	ws := uuid.New()
	if err := svc.UpsertMember(ctx(), ws, "user-1", RoleAdmin, SystemActor); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.UpsertMember(ctx(), ws, "user-1", RoleAdmin, SystemActor); err != nil {
		t.Fatalf("re-stamp: %v", err)
	}
	var count int64
	db.Model(&models.AuditEvent{}).Where("workspace_id = ? AND action LIKE 'rbac.member.%'", ws).Count(&count)
	if count != 1 {
		t.Fatalf("audit rows = %d, want 1 (only the initial add)", count)
	}
}

func TestUpsertMemberLastOwnerProtected(t *testing.T) {
	svc, _ := newTestService(t, 0)
	ws := uuid.New()
	if err := svc.UpsertMember(ctx(), ws, "owner-1", RoleOwner, SystemActor); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	// Demoting the only owner must be rejected.
	err := svc.UpsertMember(ctx(), ws, "owner-1", RoleAdmin, SystemActor)
	if !errors.Is(err, ErrLastOwnerProtected) {
		t.Fatalf("demote last owner err = %v, want ErrLastOwnerProtected", err)
	}
	// With a second owner present, the demote is allowed.
	if err := svc.UpsertMember(ctx(), ws, "owner-2", RoleOwner, SystemActor); err != nil {
		t.Fatalf("add second owner: %v", err)
	}
	if err := svc.UpsertMember(ctx(), ws, "owner-1", RoleAdmin, SystemActor); err != nil {
		t.Fatalf("demote with co-owner present: %v", err)
	}
}

func TestUpsertMemberAsOwnerEscalationForbidden(t *testing.T) {
	svc, _ := newTestService(t, 0)
	ws := uuid.New()
	// An admin actor cannot promote anyone to owner.
	err := svc.UpsertMemberAs(ctx(), ws, "victim", RoleOwner, RoleAdmin, "admin-actor")
	if !errors.Is(err, ErrOwnerEscalationForbidden) {
		t.Fatalf("admin promoting to owner err = %v, want ErrOwnerEscalationForbidden", err)
	}
	// An owner actor can.
	if err := svc.UpsertMemberAs(ctx(), ws, "new-owner", RoleOwner, RoleOwner, "owner-actor"); err != nil {
		t.Fatalf("owner promoting to owner: %v", err)
	}
}

func TestUpsertMemberAsCannotModifyExistingOwner(t *testing.T) {
	svc, _ := newTestService(t, 0)
	ws := uuid.New()
	if err := svc.UpsertMember(ctx(), ws, "the-owner", RoleOwner, SystemActor); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	// A non-owner cannot modify an existing owner row, even to a lower role.
	err := svc.UpsertMemberAs(ctx(), ws, "the-owner", RoleAdmin, RoleAdmin, "admin-actor")
	if !errors.Is(err, ErrOwnerEscalationForbidden) {
		t.Fatalf("admin modifying owner err = %v, want ErrOwnerEscalationForbidden", err)
	}
}

func TestUpsertMemberAsRequiresActorContext(t *testing.T) {
	svc, _ := newTestService(t, 0)
	ws := uuid.New()
	if err := svc.UpsertMemberAs(ctx(), ws, "u", RoleAdmin, "", "actor"); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("empty actorRole err = %v, want ErrInvalidRole", err)
	}
	if err := svc.UpsertMemberAs(ctx(), ws, "u", RoleAdmin, RoleAdmin, ""); !errors.Is(err, ErrValidation) {
		t.Fatalf("empty actorUserID err = %v, want ErrValidation", err)
	}
}

func TestDeleteMemberLastOwnerProtected(t *testing.T) {
	svc, _ := newTestService(t, 0)
	ws := uuid.New()
	if err := svc.UpsertMember(ctx(), ws, "owner-1", RoleOwner, SystemActor); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := svc.DeleteMember(ctx(), ws, "owner-1", "actor"); !errors.Is(err, ErrLastOwnerProtected) {
		t.Fatalf("delete last owner err = %v, want ErrLastOwnerProtected", err)
	}
}

func TestDeleteMemberAsOwnerEscalationForbidden(t *testing.T) {
	svc, _ := newTestService(t, 0)
	ws := uuid.New()
	// Two owners so the last-owner guard does not mask the escalation guard.
	if err := svc.UpsertMember(ctx(), ws, "owner-1", RoleOwner, SystemActor); err != nil {
		t.Fatalf("seed owner-1: %v", err)
	}
	if err := svc.UpsertMember(ctx(), ws, "owner-2", RoleOwner, SystemActor); err != nil {
		t.Fatalf("seed owner-2: %v", err)
	}
	// A non-owner actor must not be able to remove an owner, even when a
	// co-owner remains (so this is not the last-owner path).
	err := svc.DeleteMemberAs(ctx(), ws, "owner-2", RoleAdmin, "admin-actor")
	if !errors.Is(err, ErrOwnerEscalationForbidden) {
		t.Fatalf("admin deleting owner err = %v, want ErrOwnerEscalationForbidden", err)
	}
	// The owner row must still be present.
	if _, err := svc.GetMembership(ctx(), ws, "owner-2"); err != nil {
		t.Fatalf("owner-2 should still exist after forbidden delete: %v", err)
	}
	// An owner actor can remove a co-owner.
	if err := svc.DeleteMemberAs(ctx(), ws, "owner-2", RoleOwner, "owner-actor"); err != nil {
		t.Fatalf("owner deleting co-owner: %v", err)
	}
}

func TestDeleteMemberAsNonOwnerCanRemoveNonOwner(t *testing.T) {
	svc, _ := newTestService(t, 0)
	ws := uuid.New()
	if err := svc.UpsertMember(ctx(), ws, "operator-1", RoleOperator, SystemActor); err != nil {
		t.Fatalf("seed operator: %v", err)
	}
	// An admin removing a non-owner is allowed.
	if err := svc.DeleteMemberAs(ctx(), ws, "operator-1", RoleAdmin, "admin-actor"); err != nil {
		t.Fatalf("admin deleting operator: %v", err)
	}
}

func TestDeleteMemberAsRequiresActorContext(t *testing.T) {
	svc, _ := newTestService(t, 0)
	ws := uuid.New()
	if err := svc.DeleteMemberAs(ctx(), ws, "u", "", "actor"); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("empty actorRole err = %v, want ErrInvalidRole", err)
	}
	if err := svc.DeleteMemberAs(ctx(), ws, "u", RoleAdmin, ""); !errors.Is(err, ErrValidation) {
		t.Fatalf("empty actorUserID err = %v, want ErrValidation", err)
	}
}

func TestDeleteMemberIdempotent(t *testing.T) {
	svc, _ := newTestService(t, 0)
	ws := uuid.New()
	// Deleting a non-member is a no-op success.
	if err := svc.DeleteMember(ctx(), ws, "ghost", "actor"); err != nil {
		t.Fatalf("idempotent delete err = %v, want nil", err)
	}
}

func TestDeleteMemberRemovesAndInvalidatesCache(t *testing.T) {
	svc, _ := newTestService(t, 60*time.Second)
	ws := uuid.New()
	if err := svc.UpsertMember(ctx(), ws, "owner-1", RoleOwner, SystemActor); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	if err := svc.UpsertMember(ctx(), ws, "user-2", RoleOperator, SystemActor); err != nil {
		t.Fatalf("seed member: %v", err)
	}
	if _, err := svc.GetMembership(ctx(), ws, "user-2"); err != nil {
		t.Fatalf("prime cache: %v", err)
	}
	if err := svc.DeleteMember(ctx(), ws, "user-2", "owner-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// Cache was invalidated by the delete, so the next read reflects removal.
	if _, err := svc.GetMembership(ctx(), ws, "user-2"); !errors.Is(err, ErrMembershipNotFound) {
		t.Fatalf("post-delete err = %v, want ErrMembershipNotFound", err)
	}
}

func TestListMembersScopedAndOrdered(t *testing.T) {
	svc, _ := newTestService(t, 0)
	now := time.Unix(1_700_000_000, 0)
	svc.SetClock(func() time.Time { return now })
	wsA, wsB := uuid.New(), uuid.New()

	// wsA: two members added in order; wsB: one member that must not leak.
	if err := svc.UpsertMember(ctx(), wsA, "first", RoleOwner, SystemActor); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if err := svc.UpsertMember(ctx(), wsA, "second", RoleOperator, SystemActor); err != nil {
		t.Fatal(err)
	}
	if err := svc.UpsertMember(ctx(), wsB, "other", RoleAdmin, SystemActor); err != nil {
		t.Fatal(err)
	}

	members, err := svc.ListMembers(ctx(), wsA)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("wsA members = %d, want 2 (wsB must not leak)", len(members))
	}
	if members[0].UserID != "first" || members[1].UserID != "second" {
		t.Fatalf("ordering = [%s, %s], want [first, second]", members[0].UserID, members[1].UserID)
	}
}

// TestGetMembershipInvalidStoredRole proves a corrupt role string (which the DB
// CHECK constraint would normally block, but a bad manual write could land)
// fails closed rather than granting an empty set silently.
func TestGetMembershipInvalidStoredRole(t *testing.T) {
	svc, db := newTestService(t, 0)
	ws := uuid.New()
	// The role CHECK constraint (mirrored from the migration via the GORM tag)
	// normally blocks an invalid role at insert time, so to drive the defensive
	// branch we suspend CHECK enforcement just for this seed insert — modelling
	// a row that a manual SQL write or an older schema could leave behind.
	if err := db.Exec("PRAGMA ignore_check_constraints = ON").Error; err != nil {
		t.Fatalf("disable checks: %v", err)
	}
	if err := db.Create(&models.WorkspaceMember{
		WorkspaceID: ws, UserID: "user-x", Role: "superadmin",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("insert bad row: %v", err)
	}
	if err := db.Exec("PRAGMA ignore_check_constraints = OFF").Error; err != nil {
		t.Fatalf("re-enable checks: %v", err)
	}
	if _, err := svc.GetMembership(ctx(), ws, "user-x"); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("err = %v, want ErrInvalidRole", err)
	}
}
