// Package authz is the role-based access-control layer for the ShieldNet
// Access control plane.
//
// Up to WS1 the handlers enforced workspace scoping (every query filters by
// the workspace resolved from the verified iam-core tenant claim) but had NO
// role/permission model: any principal holding a valid JWT for a workspace
// could call every sensitive endpoint (policy promotion, access-request
// approval, connector management, the PAM gateway). This package adds the
// missing authorization tier.
//
// Three concepts live in this file:
//
//   - WorkspaceRole: the membership tier a user holds within a workspace
//     (owner / admin / security_admin / operator / auditor). Persisted on the
//     workspace_members row (see internal/models WorkspaceMember + migration
//     0015) and resolved per request by RBACService.
//
//   - Permission: a typed string naming one guarded action
//     (e.g. "policy.promote", "pam.connect"). Handlers reference these via the
//     RequirePermission(perm) middleware helper, so the wire format is stable
//     while the constants stay refactor-safe.
//
//   - the role -> permission mapping: the in-code, hardcoded set of
//     permissions each role holds. Hardcoded (not config-driven) because the
//     role definitions ARE part of the platform trust model — changing them is
//     a code-review event, not a runtime tweak — and because the resolver is
//     on the hot path (every authenticated request) so we want zero DB
//     round-trips on the permission-lookup side. Membership is DB-driven; the
//     role -> permission mapping is code-driven.
//
// The mapping is materialized once at init() into an immutable, shared
// PermissionSet per role so AuthzMiddleware never allocates on the hot path.
package authz

import (
	"fmt"
	"sort"
	"strings"
)

// WorkspaceRole names the membership tier a user holds within a workspace. The
// string value is the wire format stored in workspace_members.role and emitted
// on audit events. Renaming or removing a role is a breaking change requiring
// a migration to re-key the workspace_members table.
type WorkspaceRole string

const (
	// RoleOwner holds every Permission AND the owner-only actions
	// (workspace lifecycle, ownership transfer). A workspace may have more
	// than one owner (co-owners); the service enforces that AT LEAST ONE
	// owner always remains (the last-owner guard in RBACService) and that
	// only an owner may promote to — or modify — an owner.
	RoleOwner WorkspaceRole = "owner"

	// RoleAdmin holds every Permission EXCEPT the owner-only set. Manages
	// connectors, members, policies, and the full operational surface.
	RoleAdmin WorkspaceRole = "admin"

	// RoleSecurityAdmin runs the access-governance surface: authors and
	// promotes policies, approves/denies access requests, drives access
	// reviews, and administers the PAM gateway (connect / takeover / secret
	// reveal) — but does NOT manage workspace membership or connector
	// infrastructure (those are admin/owner concerns).
	RoleSecurityAdmin WorkspaceRole = "security_admin"

	// RoleOperator is the standard end-user tier: raise access requests,
	// view their own grants, connect through the PAM gateway to resources
	// they have grants on, and read the operational surface. No
	// administrative authority.
	RoleOperator WorkspaceRole = "operator"

	// RoleAuditor is read-only and scoped to compliance artefacts (audit
	// trail, evidence/exports, access-review outputs). Designed for external
	// auditors during a fixed window; holds no operational write authority.
	RoleAuditor WorkspaceRole = "auditor"
)

// AllWorkspaceRoles is the canonical ordered slice of every defined role.
// Tests enumerate it as the universe for permission-matrix coverage; the
// migration uses it as the allowed-value set for the workspace_members.role
// CHECK constraint.
var AllWorkspaceRoles = []WorkspaceRole{
	RoleOwner,
	RoleAdmin,
	RoleSecurityAdmin,
	RoleOperator,
	RoleAuditor,
}

// IsValid reports whether r is one of the defined WorkspaceRole constants.
// Callers receiving a role string from the DB or an inbound request MUST
// validate before trusting it to look up permissions.
func (r WorkspaceRole) IsValid() bool {
	for _, valid := range AllWorkspaceRoles {
		if r == valid {
			return true
		}
	}
	return false
}

// ParseWorkspaceRole validates and returns a WorkspaceRole from a raw string.
// Trims and lower-cases for tolerant comparison (so an admin UI sending
// "Admin" or " owner " still resolves) and rejects unknown values with a
// structured error so the API layer can return a useful 400.
func ParseWorkspaceRole(raw string) (WorkspaceRole, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return "", fmt.Errorf("authz: workspace role is required")
	}
	candidate := WorkspaceRole(trimmed)
	if !candidate.IsValid() {
		valid := make([]string, 0, len(AllWorkspaceRoles))
		for _, v := range AllWorkspaceRoles {
			valid = append(valid, string(v))
		}
		sort.Strings(valid)
		return "", fmt.Errorf("authz: unknown workspace role %q (valid: %s)", raw, strings.Join(valid, ", "))
	}
	return candidate, nil
}

// Permission names one action the RBAC layer guards. The string value is the
// wire format used in middleware calls (RequirePermission("policy.promote"))
// and emitted on audit records when a request is denied. Naming convention is
// <surface>.<resource>.<verb> (or <surface>.<verb> for single-resource
// surfaces) so the catalogue enumerates alphabetically and extends by
// appending new segments.
//
// New permissions append to the constant block below AND to a role entry in
// rolePermissionSlices (owner is granted everything automatically). Tests
// assert every Permission has a role assignment so a constant added without a
// mapping fails at test time rather than silently always-denying.
type Permission string

const (
	// --- Access requests ----------------------------------------------
	PermRequestCreate    Permission = "request.create"
	PermRequestRead      Permission = "request.read"
	PermRequestApprove   Permission = "request.approve"
	PermRequestDeny      Permission = "request.deny"
	PermRequestCancel    Permission = "request.cancel"
	PermRequestProvision Permission = "request.provision"
	PermRequestAdmin     Permission = "request.admin"

	// --- Access grants ------------------------------------------------
	PermGrantRead   Permission = "grant.read"
	PermGrantRevoke Permission = "grant.revoke"
	PermGrantAdmin  Permission = "grant.admin"

	// --- Policies -----------------------------------------------------
	PermPolicyRead     Permission = "policy.read"
	PermPolicyWrite    Permission = "policy.write"
	PermPolicySimulate Permission = "policy.simulate"
	PermPolicyPromote  Permission = "policy.promote"
	PermPolicyArchive  Permission = "policy.archive"

	// --- Access reviews -----------------------------------------------
	PermReviewRead     Permission = "review.read"
	PermReviewStart    Permission = "review.start"
	PermReviewRespond  Permission = "review.respond"
	PermReviewComplete Permission = "review.complete"
	PermReviewAdmin    Permission = "review.admin"

	// --- Joiner/Mover/Leaver + SCIM inbound ---------------------------
	PermJMLRead       Permission = "jml.read"
	PermJMLEventWrite Permission = "jml.event.write"

	// --- Orphan-account reconciliation --------------------------------
	PermOrphanRead        Permission = "orphan.read"
	PermOrphanScan        Permission = "orphan.scan"
	PermOrphanDisposition Permission = "orphan.disposition"

	// --- Connectors ---------------------------------------------------
	PermConnectorRead    Permission = "connector.read"
	PermConnectorManage  Permission = "connector.manage"
	PermConnectorSSORead Permission = "connector.sso.read"

	// --- Policy packs (curated templates) -----------------------------
	PermPackRead  Permission = "pack.read"
	PermPackApply Permission = "pack.apply"

	// --- PAM: privileged-access targets -------------------------------
	PermPAMTargetRead  Permission = "pam.target.read"
	PermPAMTargetWrite Permission = "pam.target.write"

	// --- PAM: brokered secrets ----------------------------------------
	PermPAMSecretRead   Permission = "pam.secret.read"
	PermPAMSecretWrite  Permission = "pam.secret.write"
	PermPAMSecretReveal Permission = "pam.secret.reveal"

	// --- PAM: live sessions -------------------------------------------
	PermPAMSessionRead  Permission = "pam.session.read"
	PermPAMSessionAdmin Permission = "pam.session.admin"

	// --- PAM: high-risk gateway actions -------------------------------
	PermPAMConnect  Permission = "pam.connect"
	PermPAMTakeover Permission = "pam.takeover"

	// --- Workflow engine ----------------------------------------------
	PermWorkflowRead Permission = "workflow.read"
	PermWorkflowEdit Permission = "workflow.edit"

	// --- Compliance / evidence ----------------------------------------
	PermComplianceRead   Permission = "compliance.read"
	PermComplianceExport Permission = "compliance.export"

	// --- Audit trail --------------------------------------------------
	PermAuditRead Permission = "audit.read"

	// --- Directory / teams --------------------------------------------
	PermDirectoryRead Permission = "directory.read"
	PermTeamRead      Permission = "team.read"
	PermTeamWrite     Permission = "team.write"

	// --- RBAC self-administration -------------------------------------
	//
	// PermRBACRead gates reading the role catalogue, permission matrix, and
	// the workspace member list; PermRBACManage gates assigning/removing
	// member roles. The owner-only "promote to owner / modify an owner"
	// path is additionally gated at the service layer because a string
	// permission cannot express a row-conditional rule.
	PermRBACRead   Permission = "rbac.read"
	PermRBACManage Permission = "rbac.manage"

	// --- Workspace lifecycle (owner-only) -----------------------------
	//
	// PermWorkspaceManage covers destructive workspace-lifecycle actions
	// (rename, plan/residency changes, deletion). Held only by RoleOwner so
	// it is the marker permission distinguishing owner from admin.
	PermWorkspaceManage Permission = "workspace.manage"
)

// AllPermissions is the canonical catalogue of every defined Permission.
// RoleOwner is granted every entry at init(); tests use it to assert coverage
// (every permission maps to at least one role, owner holds all).
var AllPermissions = []Permission{
	PermRequestCreate, PermRequestRead, PermRequestApprove, PermRequestDeny,
	PermRequestCancel, PermRequestProvision, PermRequestAdmin,
	PermGrantRead, PermGrantRevoke, PermGrantAdmin,
	PermPolicyRead, PermPolicyWrite, PermPolicySimulate, PermPolicyPromote, PermPolicyArchive,
	PermReviewRead, PermReviewStart, PermReviewRespond, PermReviewComplete, PermReviewAdmin,
	PermJMLRead, PermJMLEventWrite,
	PermOrphanRead, PermOrphanScan, PermOrphanDisposition,
	PermConnectorRead, PermConnectorManage, PermConnectorSSORead,
	PermPackRead, PermPackApply,
	PermPAMTargetRead, PermPAMTargetWrite,
	PermPAMSecretRead, PermPAMSecretWrite, PermPAMSecretReveal,
	PermPAMSessionRead, PermPAMSessionAdmin,
	PermPAMConnect, PermPAMTakeover,
	PermWorkflowRead, PermWorkflowEdit,
	PermComplianceRead, PermComplianceExport,
	PermAuditRead,
	PermDirectoryRead, PermTeamRead, PermTeamWrite,
	PermRBACRead, PermRBACManage,
	PermWorkspaceManage,
}

// PermissionSet is an unordered, hash-backed set of Permission values,
// optimized for the hot-path "does this user have this permission?" check
// every authenticated request performs. The zero value is a usable empty set;
// prefer NewPermissionSet for cap-hinted construction.
type PermissionSet map[Permission]struct{}

// NewPermissionSet returns an empty PermissionSet pre-sized for the supplied
// capacity hint. Use 0 if the size is unknown — the map grows naturally.
func NewPermissionSet(hint int) PermissionSet {
	if hint < 0 {
		hint = 0
	}
	return make(PermissionSet, hint)
}

// Add inserts perm into the set. Idempotent.
func (s PermissionSet) Add(perm Permission) {
	s[perm] = struct{}{}
}

// Has reports whether the set contains perm. Returns false for the nil/empty
// set so callers need not nil-check.
func (s PermissionSet) Has(perm Permission) bool {
	if s == nil {
		return false
	}
	_, ok := s[perm]
	return ok
}

// Slice returns the set's permissions as a sorted []Permission for audit-log
// emission and test assertions where stable ordering matters. Not for hot-path
// checks (use Has).
func (s PermissionSet) Slice() []Permission {
	out := make([]Permission, 0, len(s))
	for p := range s {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// rolePermissionSlices is the authored source of truth for each bounded role's
// permissions. RoleOwner is intentionally absent: it is granted the full
// AllPermissions catalogue at init() so a newly-added permission is
// automatically owned by owners without editing this map.
//
// Editing this map is a security-review event.
var rolePermissionSlices = map[WorkspaceRole][]Permission{
	RoleAdmin: {
		// Admin holds the full operational + governance surface, plus
		// member and connector management, EXCEPT the owner-only
		// workspace-lifecycle permission (PermWorkspaceManage).
		PermRequestCreate, PermRequestRead, PermRequestApprove, PermRequestDeny,
		PermRequestCancel, PermRequestProvision, PermRequestAdmin,
		PermGrantRead, PermGrantRevoke, PermGrantAdmin,
		PermPolicyRead, PermPolicyWrite, PermPolicySimulate, PermPolicyPromote, PermPolicyArchive,
		PermReviewRead, PermReviewStart, PermReviewRespond, PermReviewComplete, PermReviewAdmin,
		PermJMLRead, PermJMLEventWrite,
		PermOrphanRead, PermOrphanScan, PermOrphanDisposition,
		PermConnectorRead, PermConnectorManage, PermConnectorSSORead,
		PermPackRead, PermPackApply,
		PermPAMTargetRead, PermPAMTargetWrite,
		PermPAMSecretRead, PermPAMSecretWrite, PermPAMSecretReveal,
		PermPAMSessionRead, PermPAMSessionAdmin,
		PermPAMConnect, PermPAMTakeover,
		PermWorkflowRead, PermWorkflowEdit,
		PermComplianceRead, PermComplianceExport,
		PermAuditRead,
		PermDirectoryRead, PermTeamRead, PermTeamWrite,
		PermRBACRead, PermRBACManage,
	},
	RoleSecurityAdmin: {
		// Access-governance + PAM administration. No member management
		// (PermRBACManage), no connector infrastructure
		// (PermConnectorManage), no workspace lifecycle.
		//
		// Separation of duties: this is the approver role
		// (PermRequestApprove/Deny), so it deliberately does NOT hold
		// PermRequestCreate / PermRequestCancel — an approver must not be
		// able to raise AND then approve their own elevation request. A
		// security_admin who needs access is themselves a requester and
		// holds RoleOperator (which carries PermRequestCreate); the
		// governance seat stays a pure reviewer. Granting create here would
		// reopen the self-approval path, so it is excluded by design.
		PermRequestRead, PermRequestApprove, PermRequestDeny, PermRequestProvision, PermRequestAdmin,
		PermGrantRead, PermGrantRevoke, PermGrantAdmin,
		PermPolicyRead, PermPolicyWrite, PermPolicySimulate, PermPolicyPromote, PermPolicyArchive,
		PermReviewRead, PermReviewStart, PermReviewRespond, PermReviewComplete, PermReviewAdmin,
		PermJMLRead,
		PermOrphanRead, PermOrphanScan, PermOrphanDisposition,
		PermConnectorRead, PermConnectorSSORead,
		PermPackRead, PermPackApply,
		PermPAMTargetRead, PermPAMTargetWrite,
		PermPAMSecretRead, PermPAMSecretReveal,
		PermPAMSessionRead, PermPAMSessionAdmin,
		PermPAMConnect, PermPAMTakeover,
		PermWorkflowRead, PermWorkflowEdit,
		PermComplianceRead, PermComplianceExport,
		PermAuditRead,
		PermDirectoryRead, PermTeamRead,
		PermRBACRead,
	},
	RoleOperator: {
		// Standard end-user: raise requests, view own grants, connect to
		// resources they have grants on, read the operational surface.
		PermRequestCreate, PermRequestRead, PermRequestCancel,
		PermGrantRead,
		PermPolicyRead,
		PermReviewRead, PermReviewRespond,
		PermConnectorRead,
		PermPackRead,
		PermPAMTargetRead,
		PermPAMSecretReveal,
		PermPAMSessionRead,
		PermPAMConnect,
		PermWorkflowRead,
		PermDirectoryRead, PermTeamRead,
	},
	RoleAuditor: {
		// Compliance-scoped read-only. Sees audit/evidence and the read
		// surfaces audit workflows depend on; no write authority anywhere.
		PermRequestRead,
		PermGrantRead,
		PermPolicyRead,
		PermReviewRead,
		PermOrphanRead,
		PermPAMSessionRead,
		PermWorkflowRead,
		PermComplianceRead, PermComplianceExport,
		PermAuditRead,
		PermDirectoryRead,
		PermRBACRead,
	},
}

// rolePermissionCache is the init()-built immutable cache of
// WorkspaceRole -> PermissionSet. AuthzMiddleware calls PermissionsForRole
// once per authenticated request, so a per-request map allocation would
// generate steady GC pressure proportional to RPS. The cache is built once and
// never mutated; the returned sets are SHARED read-only — see PermissionsForRole.
var rolePermissionCache map[WorkspaceRole]PermissionSet

func init() {
	rolePermissionCache = make(map[WorkspaceRole]PermissionSet, len(AllWorkspaceRoles))

	// Owner: every permission in AllPermissions, computed from the slice so a
	// newly-added Permission constant is automatically granted to owners.
	ownerSet := NewPermissionSet(len(AllPermissions))
	for _, p := range AllPermissions {
		ownerSet.Add(p)
	}
	rolePermissionCache[RoleOwner] = ownerSet

	// Bounded roles: materialize each declared slice into a PermissionSet once.
	for role, perms := range rolePermissionSlices {
		set := NewPermissionSet(len(perms))
		for _, p := range perms {
			set.Add(p)
		}
		rolePermissionCache[role] = set
	}

	// Every declared WorkspaceRole must have an entry. A role constant added
	// without a mapping panics at process start (before the listener binds)
	// rather than silently always-denying every request for that role.
	for _, role := range AllWorkspaceRoles {
		if _, ok := rolePermissionCache[role]; !ok {
			panic("authz: rolePermissionCache missing entry for declared WorkspaceRole " + string(role))
		}
	}
}

// PermissionsForRole returns the PermissionSet a member of the supplied role
// holds. Returns an empty (non-nil) PermissionSet for unknown roles so callers
// can chain .Has(...) without a nil-check.
//
// The returned set is the SHARED cached set built at init(); callers MUST treat
// it as read-only (only Has() is called on it in the request path). This is
// what eliminates the per-request allocation on the platform's hottest path.
func PermissionsForRole(role WorkspaceRole) PermissionSet {
	if set, ok := rolePermissionCache[role]; ok {
		return set
	}
	return NewPermissionSet(0)
}
