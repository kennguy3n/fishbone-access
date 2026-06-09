import { useMemo, useState } from "react";
import { useIntl } from "react-intl";
import { PageHeader, Card, Badge, LoadingState, ErrorState } from "@/components/ui";
import { Modal } from "@/components/Modal";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { useToast } from "@/components/Toast";
import {
  useMe,
  useRbacRoles,
  useRbacMembers,
  useAssignRbacMember,
  type RbacRole,
  type RbacMember,
} from "@/api/access";

// MANAGE_PERMISSION is the fine-grained permission that gates membership
// mutation. The server is the source of truth (the PUT/DELETE routes are
// gated by it); the UI mirrors it only to decide whether to OFFER the
// controls, and still fails closed if the caller's role is unknown.
const MANAGE_PERMISSION = "rbac.manage";

// roleTone maps a role to an SN360 Badge tone so the privilege gradient reads
// at a glance (owner=danger, down to auditor=neutral).
function roleTone(role: string): "ok" | "warn" | "danger" | "info" | "neutral" {
  switch (role) {
    case "owner":
      return "danger";
    case "admin":
      return "warn";
    case "security_admin":
      return "info";
    case "operator":
      return "ok";
    default:
      return "neutral";
  }
}

// groupByResource buckets permissions by the segment before the first dot
// (e.g. "policy.promote" → "policy") so the matrix renders as readable
// resource sections rather than one flat 60-row wall.
function groupByResource(permissions: string[]): [string, string[]][] {
  const groups = new Map<string, string[]>();
  for (const p of permissions) {
    const resource = p.includes(".") ? p.slice(0, p.indexOf(".")) : p;
    const list = groups.get(resource) ?? [];
    list.push(p);
    groups.set(resource, list);
  }
  return [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]));
}

export function RolesPermissions() {
  const intl = useIntl();
  const toast = useToast();
  const me = useMe();
  const rolesQ = useRbacRoles();
  const membersQ = useRbacMembers();
  const assign = useAssignRbacMember();

  const [assignTarget, setAssignTarget] = useState<RbacMember | null>(null);
  const [newMemberMode, setNewMemberMode] = useState(false);

  const catalog = rolesQ.data;

  // Permission set per role, materialized once for O(1) matrix cell lookups.
  const permsByRole = useMemo(() => {
    const map = new Map<string, Set<string>>();
    for (const r of catalog?.roles ?? []) {
      map.set(r.role, new Set(r.permissions));
    }
    return map;
  }, [catalog]);

  // The caller's own workspace role + whether it grants rbac.manage. Derived
  // from the membership list + role catalogue so the UI never hardcodes a
  // privilege assumption; absence (caller not found) fails closed to read-only.
  const canManage = useMemo(() => {
    const myId = me.data?.user_id;
    if (!myId) return false;
    const mine = membersQ.data?.find((m) => m.user_id === myId);
    if (!mine) return false;
    return permsByRole.get(mine.role)?.has(MANAGE_PERMISSION) ?? false;
  }, [me.data, membersQ.data, permsByRole]);

  // Fail-closed: a 403 on the read endpoints means the caller lacks rbac.read.
  // Render an explicit access-restricted state rather than an empty matrix.
  const forbidden =
    rolesQ.error?.status === 403 || membersQ.error?.status === 403;

  const title = intl.formatMessage({
    id: "nav.rolesPermissions",
    defaultMessage: "Roles & permissions",
  });

  if (forbidden) {
    return (
      <>
        <PageHeader title={title} />
        <Card title={intl.formatMessage({
          id: "rbac.restricted.title",
          defaultMessage: "Access restricted",
        })}>
          <p className="muted">
            {intl.formatMessage({
              id: "rbac.restricted.body",
              defaultMessage:
                "You do not have permission to view roles and permissions for this workspace. Ask a workspace owner or admin for the rbac.read permission.",
            })}
          </p>
        </Card>
      </>
    );
  }

  if (rolesQ.isLoading || membersQ.isLoading) return <LoadingState />;
  if (rolesQ.error)
    return <ErrorState error={rolesQ.error} onRetry={() => rolesQ.refetch()} />;
  if (!catalog) return <ErrorState error={new Error("No role catalogue")} />;

  const resourceGroups = groupByResource(catalog.permissions);

  const memberColumns: Column<RbacMember>[] = [
    {
      header: intl.formatMessage({ id: "rbac.col.user", defaultMessage: "User" }),
      cell: (m) => <code>{m.user_id}</code>,
    },
    {
      header: intl.formatMessage({ id: "rbac.col.role", defaultMessage: "Role" }),
      width: 160,
      cell: (m) => <Badge tone={roleTone(m.role)}>{m.role}</Badge>,
    },
    {
      header: intl.formatMessage({
        id: "rbac.col.actions",
        defaultMessage: "Actions",
      }),
      width: 140,
      cell: (m) =>
        canManage ? (
          <button
            className="btn btn--ghost btn--sm"
            onClick={() => {
              setNewMemberMode(false);
              setAssignTarget(m);
            }}
          >
            {intl.formatMessage({
              id: "rbac.action.changeRole",
              defaultMessage: "Change role",
            })}
          </button>
        ) : (
          <span className="muted">—</span>
        ),
    },
  ];

  return (
    <>
      <PageHeader
        title={title}
        subtitle={intl.formatMessage({
          id: "rbac.subtitle",
          defaultMessage:
            "Workspace roles map to a fixed set of fine-grained permissions. Each member holds exactly one role per workspace.",
        })}
        actions={
          canManage ? (
            <button
              className="btn btn--primary"
              onClick={() => {
                setAssignTarget(null);
                setNewMemberMode(true);
              }}
            >
              {intl.formatMessage({
                id: "rbac.action.addMember",
                defaultMessage: "Assign a member",
              })}
            </button>
          ) : undefined
        }
      />

      <Card
        title={intl.formatMessage({
          id: "rbac.members.title",
          defaultMessage: "Members",
        })}
        subtitle={intl.formatMessage({
          id: "rbac.members.subtitle",
          defaultMessage: "Everyone with a role in this workspace.",
        })}
      >
        {membersQ.data && membersQ.data.length > 0 ? (
          <DataTable
            columns={memberColumns}
            rows={membersQ.data}
            rowKey={(m) => m.user_id}
          />
        ) : (
          <EmptyState
            illustration={undefined}
            title={intl.formatMessage({
              id: "rbac.members.empty.title",
              defaultMessage: "No members yet",
            })}
            description={intl.formatMessage({
              id: "rbac.members.empty.body",
              defaultMessage:
                "Assign the first member a role to start administering this workspace.",
            })}
          />
        )}
      </Card>

      <Card
        title={intl.formatMessage({
          id: "rbac.matrix.title",
          defaultMessage: "Permission matrix",
        })}
        subtitle={intl.formatMessage({
          id: "rbac.matrix.subtitle",
          defaultMessage:
            "Read-only. The role → permission mapping is fixed in the control plane; owner implicitly holds every permission.",
        })}
      >
        <div className="table-wrap">
          <table className="data rbac-matrix">
            <thead>
              <tr>
                <th>
                  {intl.formatMessage({
                    id: "rbac.matrix.permission",
                    defaultMessage: "Permission",
                  })}
                </th>
                {catalog.roles.map((r) => (
                  <th key={r.role} style={{ textAlign: "center", width: 96 }}>
                    <Badge tone={roleTone(r.role)}>{r.role}</Badge>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {resourceGroups.map(([resource, perms]) => (
                <RbacMatrixGroup
                  key={resource}
                  resource={resource}
                  perms={perms}
                  roles={catalog.roles}
                  permsByRole={permsByRole}
                />
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {(assignTarget || newMemberMode) && (
        <AssignRoleModal
          roles={catalog.roles}
          permsByRole={permsByRole}
          target={assignTarget}
          busy={assign.isPending}
          onClose={() => {
            setAssignTarget(null);
            setNewMemberMode(false);
          }}
          onApply={(userId, role) => {
            assign.mutate(
              { userId, role },
              {
                onSuccess: () => {
                  toast.success(
                    intl.formatMessage({
                      id: "rbac.assign.success",
                      defaultMessage: "Role updated",
                    }),
                    `${userId} → ${role}`,
                  );
                  setAssignTarget(null);
                  setNewMemberMode(false);
                },
                onError: (err) =>
                  toast.error(
                    intl.formatMessage({
                      id: "rbac.assign.error",
                      defaultMessage: "Could not update role",
                    }),
                    err.message,
                  ),
              },
            );
          }}
        />
      )}
    </>
  );
}

// RbacMatrixGroup renders one resource section: a sub-header row then a row per
// permission with a held/not-held marker under each role column.
function RbacMatrixGroup({
  resource,
  perms,
  roles,
  permsByRole,
}: {
  resource: string;
  perms: string[];
  roles: RbacRole[];
  permsByRole: Map<string, Set<string>>;
}) {
  return (
    <>
      <tr>
        <td
          colSpan={roles.length + 1}
          style={{ fontWeight: 600, textTransform: "capitalize" }}
        >
          {resource}
        </td>
      </tr>
      {perms.map((perm) => (
        <tr key={perm}>
          <td>
            <code style={{ fontSize: 12 }}>{perm}</code>
          </td>
          {roles.map((r) => {
            const held = permsByRole.get(r.role)?.has(perm) ?? false;
            return (
              <td key={r.role} style={{ textAlign: "center" }}>
                {held ? (
                  <span aria-label="granted" style={{ color: "var(--ok, #16a34a)" }}>
                    ●
                  </span>
                ) : (
                  <span aria-label="not granted" className="muted">
                    ·
                  </span>
                )}
              </td>
            );
          })}
        </tr>
      ))}
    </>
  );
}

// AssignRoleModal is the membership mutation surface. It implements the
// mandatory JIT-before-effect guardrail: the operator selects a role and the
// modal PREVIEWS the exact permission set (and the diff against the member's
// current role) BEFORE the change is applied — mirroring the policy
// simulate-before-promote gate.
function AssignRoleModal({
  roles,
  permsByRole,
  target,
  busy,
  onClose,
  onApply,
}: {
  roles: RbacRole[];
  permsByRole: Map<string, Set<string>>;
  target: RbacMember | null;
  busy: boolean;
  onClose: () => void;
  onApply: (userId: string, role: string) => void;
}) {
  const intl = useIntl();
  const [userId, setUserId] = useState(target?.user_id ?? "");
  const [role, setRole] = useState(target?.role ?? roles[0]?.role ?? "");

  const currentRole = target?.role;
  const nextPerms = permsByRole.get(role) ?? new Set<string>();
  const currentPerms = currentRole
    ? permsByRole.get(currentRole) ?? new Set<string>()
    : new Set<string>();

  // The diff the operator is about to enact: permissions the new role adds and
  // those it removes relative to the member's current role.
  const added = [...nextPerms].filter((p) => !currentPerms.has(p)).sort();
  const removed = [...currentPerms].filter((p) => !nextPerms.has(p)).sort();

  const canSubmit = userId.trim() !== "" && role !== "" && !busy;

  return (
    <Modal
      title={
        target
          ? intl.formatMessage(
              {
                id: "rbac.modal.changeTitle",
                defaultMessage: "Change role for {user}",
              },
              { user: target.user_id },
            )
          : intl.formatMessage({
              id: "rbac.modal.assignTitle",
              defaultMessage: "Assign a member",
            })
      }
      onClose={onClose}
      footer={
        <>
          <button className="btn btn--ghost" onClick={onClose} disabled={busy}>
            {intl.formatMessage({ id: "rbac.modal.cancel", defaultMessage: "Cancel" })}
          </button>
          <button
            className="btn btn--primary"
            disabled={!canSubmit}
            onClick={() => onApply(userId.trim(), role)}
          >
            {intl.formatMessage({
              id: "rbac.modal.apply",
              defaultMessage: "Apply role change",
            })}
          </button>
        </>
      }
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        {!target && (
          <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span className="muted" style={{ fontSize: 12 }}>
              {intl.formatMessage({
                id: "rbac.modal.userId",
                defaultMessage: "User ID",
              })}
            </span>
            <input
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              placeholder="user-id"
              autoFocus
            />
          </label>
        )}

        <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <span className="muted" style={{ fontSize: 12 }}>
            {intl.formatMessage({ id: "rbac.modal.role", defaultMessage: "Role" })}
          </span>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
          >
            {roles.map((r) => (
              <option key={r.role} value={r.role}>
                {r.role}
              </option>
            ))}
          </select>
        </label>

        {/* JIT-before-effect preview: the resulting permissions + the diff. */}
        <div className="rbac-preview">
          <b style={{ fontSize: 13 }}>
            {intl.formatMessage({
              id: "rbac.modal.preview",
              defaultMessage: "Preview of effect",
            })}
          </b>
          <p className="muted" style={{ fontSize: 12, margin: "4px 0 10px" }}>
            {intl.formatMessage(
              {
                id: "rbac.modal.previewBody",
                defaultMessage:
                  "Role {role} grants {count} permission(s). Review the change before applying.",
              },
              { role, count: nextPerms.size },
            )}
          </p>
          {target && (added.length > 0 || removed.length > 0) ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {added.length > 0 && (
                <div>
                  <Badge tone="ok">
                    {intl.formatMessage(
                      { id: "rbac.modal.adds", defaultMessage: "+{n} added" },
                      { n: added.length },
                    )}
                  </Badge>{" "}
                  <span className="muted" style={{ fontSize: 12 }}>
                    {added.join(", ")}
                  </span>
                </div>
              )}
              {removed.length > 0 && (
                <div>
                  <Badge tone="danger">
                    {intl.formatMessage(
                      { id: "rbac.modal.removes", defaultMessage: "-{n} removed" },
                      { n: removed.length },
                    )}
                  </Badge>{" "}
                  <span className="muted" style={{ fontSize: 12 }}>
                    {removed.join(", ")}
                  </span>
                </div>
              )}
            </div>
          ) : target ? (
            <p className="muted" style={{ fontSize: 12 }}>
              {intl.formatMessage({
                id: "rbac.modal.noChange",
                defaultMessage: "No permission change — same role.",
              })}
            </p>
          ) : (
            <div className="rbac-perm-list">
              {[...nextPerms].sort().map((p) => (
                <code key={p} style={{ fontSize: 11, marginRight: 8 }}>
                  {p}
                </code>
              ))}
            </div>
          )}
        </div>
      </div>
    </Modal>
  );
}
