import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { PageHeader, Badge, StatusBadge, AsyncBoundary } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/Toast";
import {
  useAccessRequests,
  useCreateRequest,
  type AccessRequest,
  type CreateRequestInput,
  ApiError,
} from "@/api/access";
import { formatRelative } from "@/lib/format";

function riskTone(level?: string) {
  switch ((level ?? "").toLowerCase()) {
    case "high":
    case "critical":
      return "danger" as const;
    case "medium":
      return "warn" as const;
    case "low":
      return "ok" as const;
    default:
      return "neutral" as const;
  }
}

const emptyDraft: CreateRequestInput = {
  target_user_id: "",
  connector_id: "",
  resource_ref: "",
  role: "",
  justification: "",
};

export function Requests() {
  const navigate = useNavigate();
  const toast = useToast();
  const { data, isLoading, error, refetch } = useAccessRequests();
  const createMut = useCreateRequest();
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<CreateRequestInput>(emptyDraft);

  const valid = draft.resource_ref.trim() && draft.justification.trim();

  const submit = async () => {
    if (!valid) return;
    const body: CreateRequestInput = {
      resource_ref: draft.resource_ref.trim(),
      justification: draft.justification.trim(),
      ...(draft.target_user_id?.trim()
        ? { target_user_id: draft.target_user_id.trim() }
        : {}),
      ...(draft.connector_id?.trim()
        ? { connector_id: draft.connector_id.trim() }
        : {}),
      ...(draft.role?.trim() ? { role: draft.role.trim() } : {}),
    };
    try {
      const created = await createMut.mutateAsync(body);
      toast.success("Access request created");
      setOpen(false);
      setDraft(emptyDraft);
      navigate({
        to: "/requests/$requestId",
        params: { requestId: created.id },
      });
    } catch (err) {
      toast.error(
        "Could not create request",
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  const columns: Column<AccessRequest>[] = [
    {
      header: "Resource",
      cell: (r) => (
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <b>
            <code>{r.resource_ref}</code>
          </b>
          <span className="muted" style={{ fontSize: 12 }}>
            {r.role ? `role ${r.role} · ` : ""}
            for {r.target_user_id || r.requester_id}
          </span>
        </div>
      ),
    },
    {
      header: "State",
      width: 130,
      cell: (r) => <StatusBadge status={r.state} />,
    },
    {
      header: "Risk",
      width: 90,
      cell: (r) =>
        r.risk_level ? (
          <Badge tone={riskTone(r.risk_level)}>{r.risk_level}</Badge>
        ) : (
          <span className="muted">—</span>
        ),
    },
    {
      header: "Requested",
      width: 120,
      cell: (r) => <span className="muted">{formatRelative(r.created_at)}</span>,
    },
  ];

  return (
    <>
      <PageHeader
        title="Access requests"
        subtitle="Joiner / mover provisioning lane — request, approve, and provision access through connectors."
        actions={
          <button className="btn btn--primary" onClick={() => setOpen(true)}>
            New request
          </button>
        }
      />
      <AsyncBoundary
        isLoading={isLoading}
        error={error}
        data={data}
        onRetry={refetch}
        isEmpty={(rows) => rows.length === 0}
        empty={
          <EmptyState
            title="No access requests"
            description="Requests created here run through approval and connector provisioning, with every state change recorded."
            action={
              <button
                className="btn btn--primary btn--sm"
                onClick={() => setOpen(true)}
              >
                New request
              </button>
            }
          />
        }
      >
        {(rows) => (
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(r) => r.id}
            onRowClick={(r) =>
              navigate({
                to: "/requests/$requestId",
                params: { requestId: r.id },
              })
            }
          />
        )}
      </AsyncBoundary>

      {open && (
        <Modal
          title="New access request"
          onClose={() => setOpen(false)}
          footer={
            <>
              <button className="btn btn--ghost" onClick={() => setOpen(false)}>
                Cancel
              </button>
              <button
                className="btn btn--primary"
                disabled={!valid || createMut.isPending}
                onClick={submit}
              >
                Create request
              </button>
            </>
          }
        >
          <label className="field">
            <span>Resource reference (required)</span>
            <input
              value={draft.resource_ref}
              placeholder="app:salesforce, host:10.0.0.0/24…"
              onChange={(e) =>
                setDraft({ ...draft, resource_ref: e.target.value })
              }
            />
          </label>
          <div className="field-row">
            <label className="field">
              <span>Role (optional)</span>
              <input
                value={draft.role}
                placeholder="viewer, admin…"
                onChange={(e) => setDraft({ ...draft, role: e.target.value })}
              />
            </label>
            <label className="field">
              <span>Target user (optional)</span>
              <input
                value={draft.target_user_id}
                placeholder="iam-core user id (defaults to you)"
                onChange={(e) =>
                  setDraft({ ...draft, target_user_id: e.target.value })
                }
              />
            </label>
          </div>
          <label className="field">
            <span>Connector (optional)</span>
            <input
              value={draft.connector_id}
              placeholder="connector id for automated provisioning"
              onChange={(e) =>
                setDraft({ ...draft, connector_id: e.target.value })
              }
            />
          </label>
          <label className="field">
            <span>Justification (required)</span>
            <textarea
              rows={3}
              value={draft.justification}
              placeholder="Why is this access needed?"
              onChange={(e) =>
                setDraft({ ...draft, justification: e.target.value })
              }
            />
          </label>
        </Modal>
      )}
    </>
  );
}
