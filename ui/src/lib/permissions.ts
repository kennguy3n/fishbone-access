// Frontend permission helpers.
//
// The server is always authoritative — every mutating endpoint is gated by a
// RequirePermission middleware (internal/services/authz). These hooks only
// decide which affordances to *show*, so the UI doesn't dangle a button the
// caller's role can't use. They read the caller's resolved permission set from
// GET /rbac/permissions (useMyPermissions).
//
// Fail-OPEN by design: when the permission set is unavailable — the RBAC tier
// isn't mounted (404 → useMyPermissions resolves to undefined) or it's still
// loading — we treat the action as *allowed*. This mirrors the server, where an
// un-mounted RBAC tier makes the RequirePermission gates no-op, so the UI must
// not hide affordances the server would actually accept. A genuine 403 still
// surfaces from the mutation if the role lacks the permission.

import { useMyPermissions } from "@/api/access";

// The permission wire strings (internal/services/authz/rbac.go). Only the ones
// the onboarding + self-service surfaces gate on are listed here.
export const Perm = {
  ConnectorManage: "connector.manage",
  PolicyWrite: "policy.write",
  RbacManage: "rbac.manage",
  RbacRead: "rbac.read",
  RequestCreate: "request.create",
  PamTargetWrite: "pam.target.write",
  WorkspaceManage: "workspace.manage",
} as const;

export type PermKey = (typeof Perm)[keyof typeof Perm];

/**
 * useHasPermission reports whether the caller holds `perm`. Returns true while
 * the permission set is loading or absent (unenforced tier) — see the fail-open
 * rationale above — so callers can use it directly to gate rendering.
 */
export function useHasPermission(perm: PermKey): boolean {
  const { data } = useMyPermissions();
  if (!data) return true;
  return data.permissions.includes(perm);
}

/**
 * useIsWorkspaceAdmin reports whether the caller can perform day-1 setup —
 * i.e. holds any of the administrative permissions the onboarding wizard drives
 * (connector setup, policy authoring, or member invitation). Owners/admins have
 * these; a plain operator (end user) does not, so the wizard entry point is
 * hidden for them and the self-service portal is surfaced instead.
 */
export function isWorkspaceAdmin(permissions: string[]): boolean {
  return (
    permissions.includes(Perm.ConnectorManage) ||
    permissions.includes(Perm.PolicyWrite) ||
    permissions.includes(Perm.RbacManage) ||
    permissions.includes(Perm.WorkspaceManage)
  );
}

export function useIsWorkspaceAdmin(): boolean {
  const { data } = useMyPermissions();
  if (!data) return true;
  return isWorkspaceAdmin(data.permissions);
}
