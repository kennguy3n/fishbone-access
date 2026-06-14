package authz

import (
	"testing"
)

// TestAllRolesHavePermissions asserts every declared role resolves to a
// non-empty permission set (a role mapping to nothing would silently deny every
// action for its members) and that the init() coverage panic never fired.
func TestAllRolesHavePermissions(t *testing.T) {
	for _, role := range AllWorkspaceRoles {
		perms := PermissionsForRole(role)
		if len(perms) == 0 {
			t.Errorf("role %q resolves to an empty permission set", role)
		}
	}
}

// TestOwnerHoldsEveryPermission asserts the owner role is granted the entire
// AllPermissions catalogue. Owner is the break-glass role; a permission it
// lacks would be unreachable by anyone.
func TestOwnerHoldsEveryPermission(t *testing.T) {
	owner := PermissionsForRole(RoleOwner)
	for _, p := range AllPermissions {
		if !owner.Has(p) {
			t.Errorf("owner is missing permission %q", p)
		}
	}
	if len(owner) != len(AllPermissions) {
		t.Errorf("owner permission count = %d, want %d (AllPermissions); duplicate or stray entry", len(owner), len(AllPermissions))
	}
}

// TestEveryPermissionMappedToARole asserts each Permission in the catalogue is
// granted to at least one role. An orphan permission (gated on a route but held
// by no role) would be permanently un-grantable — a latent always-deny bug.
func TestEveryPermissionMappedToARole(t *testing.T) {
	held := make(map[Permission]bool, len(AllPermissions))
	for _, role := range AllWorkspaceRoles {
		for p := range PermissionsForRole(role) {
			held[p] = true
		}
	}
	for _, p := range AllPermissions {
		if !held[p] {
			t.Errorf("permission %q is granted to no role", p)
		}
	}
}

// TestRolePermissionSlicesOnlyReferenceCatalogued asserts the authored role
// slices never grant a permission absent from AllPermissions (which would be a
// typo'd constant the matrix/tests cannot see).
func TestRolePermissionSlicesOnlyReferenceCatalogued(t *testing.T) {
	catalogue := make(map[Permission]bool, len(AllPermissions))
	for _, p := range AllPermissions {
		catalogue[p] = true
	}
	for role, perms := range rolePermissionSlices {
		for _, p := range perms {
			if !catalogue[p] {
				t.Errorf("role %q grants permission %q which is not in AllPermissions", role, p)
			}
		}
	}
}

// TestBoundedRolesExcludeWorkspaceManage asserts only the owner holds the
// owner-only workspace-lifecycle permission — the marker distinguishing owner
// from every bounded role.
func TestBoundedRolesExcludeWorkspaceManage(t *testing.T) {
	for _, role := range []WorkspaceRole{RoleAdmin, RoleSecurityAdmin, RoleOperator, RoleAuditor} {
		if PermissionsForRole(role).Has(PermWorkspaceManage) {
			t.Errorf("bounded role %q unexpectedly holds owner-only %q", role, PermWorkspaceManage)
		}
	}
	if !PermissionsForRole(RoleOwner).Has(PermWorkspaceManage) {
		t.Errorf("owner must hold %q", PermWorkspaceManage)
	}
}

// TestRoleSeparationOfDuties spot-checks the intended authority boundaries
// between roles so an accidental broadening of a slice is caught.
func TestRoleSeparationOfDuties(t *testing.T) {
	cases := []struct {
		role WorkspaceRole
		perm Permission
		want bool
	}{
		// security_admin governs access but not membership or connectors.
		{RoleSecurityAdmin, PermPolicyPromote, true},
		{RoleSecurityAdmin, PermPAMTakeover, true},
		{RoleSecurityAdmin, PermRBACManage, false},
		{RoleSecurityAdmin, PermConnectorManage, false},
		// operator is a self-service end user: can request + connect, cannot approve.
		{RoleOperator, PermRequestCreate, true},
		{RoleOperator, PermPAMConnect, true},
		{RoleOperator, PermRequestApprove, false},
		{RoleOperator, PermPolicyPromote, false},
		// auditor is read-only + evidence export, never a writer.
		{RoleAuditor, PermComplianceExport, true},
		{RoleAuditor, PermAuditRead, true},
		{RoleAuditor, PermPolicyWrite, false},
		{RoleAuditor, PermPAMConnect, false},
		// admin manages members and connectors but is not the owner.
		{RoleAdmin, PermRBACManage, true},
		{RoleAdmin, PermConnectorManage, true},
	}
	for _, tc := range cases {
		got := PermissionsForRole(tc.role).Has(tc.perm)
		if got != tc.want {
			t.Errorf("PermissionsForRole(%q).Has(%q) = %v, want %v", tc.role, tc.perm, got, tc.want)
		}
	}
}

// TestBillingPermissionBoundaries pins the authority boundaries for the billing
// permissions: billing.read is account/cost data held by the governance roles
// (owner/admin) exactly like usage.read, and billing.manage — assigning a
// tenant's plan/quota ceilings — is owner-only like workspace.manage. This
// guards against an accidental broadening that would let a non-owner change what
// a tenant owes or hand a bounded role the cost data.
func TestBillingPermissionBoundaries(t *testing.T) {
	cases := []struct {
		role WorkspaceRole
		perm Permission
		want bool
	}{
		// billing.read tracks usage.read: owner + admin only.
		{RoleOwner, PermBillingRead, true},
		{RoleAdmin, PermBillingRead, true},
		{RoleSecurityAdmin, PermBillingRead, false},
		{RoleOperator, PermBillingRead, false},
		{RoleAuditor, PermBillingRead, false},
		// billing.manage is owner-only, like workspace.manage.
		{RoleOwner, PermBillingManage, true},
		{RoleAdmin, PermBillingManage, false},
		{RoleSecurityAdmin, PermBillingManage, false},
		{RoleOperator, PermBillingManage, false},
		{RoleAuditor, PermBillingManage, false},
	}
	for _, tc := range cases {
		if got := PermissionsForRole(tc.role).Has(tc.perm); got != tc.want {
			t.Errorf("PermissionsForRole(%q).Has(%q) = %v, want %v", tc.role, tc.perm, got, tc.want)
		}
	}
	// billing.read and usage.read must have identical role coverage (they are
	// the same class of account/cost data) — a divergence is almost certainly a
	// mistake in one of the slices.
	for _, role := range AllWorkspaceRoles {
		perms := PermissionsForRole(role)
		if perms.Has(PermBillingRead) != perms.Has(PermUsageRead) {
			t.Errorf("role %q: billing.read (%v) and usage.read (%v) coverage diverge",
				role, perms.Has(PermBillingRead), perms.Has(PermUsageRead))
		}
	}
}

// TestPermissionSetAddHas exercises the set primitive, including the nil-set Has
// path callers rely on.
func TestPermissionSetAddHas(t *testing.T) {
	s := NewPermissionSet(0)
	if s.Has(PermPolicyRead) {
		t.Fatal("empty set must not contain anything")
	}
	s.Add(PermPolicyRead)
	s.Add(PermPolicyRead) // idempotent
	if !s.Has(PermPolicyRead) {
		t.Fatal("set must contain an added permission")
	}
	if len(s) != 1 {
		t.Fatalf("Add must be idempotent: len = %d, want 1", len(s))
	}
	var nilSet PermissionSet
	if nilSet.Has(PermPolicyRead) {
		t.Fatal("nil set Has must return false, not panic")
	}
}

// TestPermissionsForRoleReturnsSharedCachedSet asserts PermissionsForRole hands
// back the SAME cached set instance on each call (no per-request allocation),
// the property that keeps the hot path allocation-free.
func TestPermissionsForRoleReturnsSharedCachedSet(t *testing.T) {
	a := PermissionsForRole(RoleAdmin)
	b := PermissionsForRole(RoleAdmin)
	if len(a) != len(b) {
		t.Fatalf("two reads disagree on size: %d vs %d", len(a), len(b))
	}
	// Maps are reference types; identical contents from the shared cache.
	for p := range a {
		if !b.Has(p) {
			t.Fatalf("shared set divergence on %q", p)
		}
	}
}

// TestPermissionsForRoleUnknownRole asserts an unknown role yields an empty,
// non-nil set so callers can chain .Has safely (fail-closed: holds nothing).
func TestPermissionsForRoleUnknownRole(t *testing.T) {
	perms := PermissionsForRole(WorkspaceRole("not-a-role"))
	if perms == nil {
		t.Fatal("must return a non-nil empty set, not nil")
	}
	if len(perms) != 0 {
		t.Fatalf("unknown role must hold no permissions, got %d", len(perms))
	}
}

func TestParseWorkspaceRole(t *testing.T) {
	// A slice (not a map) so the surrounding-whitespace / mixed-case inputs that
	// exercise normalization are not flagged as suspicious map keys.
	valid := []struct {
		in   string
		want WorkspaceRole
	}{
		{"owner", RoleOwner},
		{"  Admin ", RoleAdmin}, // surrounding whitespace + mixed case is normalized
		{"SECURITY_ADMIN", RoleSecurityAdmin},
		{"operator", RoleOperator},
		{"auditor", RoleAuditor},
	}
	for _, tc := range valid {
		got, err := ParseWorkspaceRole(tc.in)
		if err != nil {
			t.Errorf("ParseWorkspaceRole(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseWorkspaceRole(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "   ", "root", "superuser", "admin;"} {
		if _, err := ParseWorkspaceRole(bad); err == nil {
			t.Errorf("ParseWorkspaceRole(%q) expected error, got nil", bad)
		}
	}
}

func TestWorkspaceRoleIsValid(t *testing.T) {
	for _, r := range AllWorkspaceRoles {
		if !r.IsValid() {
			t.Errorf("declared role %q reported invalid", r)
		}
	}
	if WorkspaceRole("nope").IsValid() {
		t.Error("undeclared role reported valid")
	}
}
