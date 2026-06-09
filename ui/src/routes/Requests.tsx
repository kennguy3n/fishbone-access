import { useState } from "react";
import { useIntl } from "react-intl";
import { useNavigate } from "@tanstack/react-router";
import { PageHeader, Badge, StatusBadge, AsyncBoundary } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/Toast";
import { RiskPanel, RecommendationBadge } from "@/components/RiskPanel";
import {
  useAccessRequests,
  useCreateRequest,
  type AccessRequest,
  type CreateRequestInput,
  type CreateRequestResult,
  ApiError,
} from "@/api/access";
import { formatRelative, riskScoreTone } from "@/lib/format";

interface Draft {
  target_user_id: string;
  connector_id: string;
  resource_ref: string;
  role: string;
  justification: string;
  resource_tags: string;
  duration_hours: string;
}

const emptyDraft: Draft = {
  target_user_id: "",
  connector_id: "",
  resource_ref: "",
  role: "",
  justification: "",
  resource_tags: "",
  duration_hours: "",
};

export function Requests() {
  const intl = useIntl();
  const navigate = useNavigate();
  const toast = useToast();
  const { data, isLoading, error, refetch } = useAccessRequests();
  const createMut = useCreateRequest();
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<Draft>(emptyDraft);
  // The synchronous AI verdict from the most recent create, shown inline so the
  // requester sees the risk panel before navigating away.
  const [reviewed, setReviewed] = useState<CreateRequestResult | null>(null);

  const valid =
    draft.resource_ref.trim() && draft.role.trim() && draft.justification.trim();

  const reset = () => {
    setOpen(false);
    setDraft(emptyDraft);
    setReviewed(null);
  };

  const submit = async () => {
    if (!valid) return;
    const tags = draft.resource_tags
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);
    const hours = Number.parseInt(draft.duration_hours, 10);
    const body: CreateRequestInput = {
      resource_ref: draft.resource_ref.trim(),
      justification: draft.justification.trim(),
      ...(draft.target_user_id.trim()
        ? { target_user_id: draft.target_user_id.trim() }
        : {}),
      ...(draft.connector_id.trim()
        ? { connector_id: draft.connector_id.trim() }
        : {}),
      role: draft.role.trim(),
      ...(tags.length > 0 ? { resource_tags: tags } : {}),
      ...(Number.isFinite(hours) && hours > 0
        ? { duration_hours: hours }
        : {}),
    };
    try {
      const result = await createMut.mutateAsync(body);
      toast.success(intl.formatMessage({ id: "requests.created", defaultMessage: "Access request created" }));
      // Surface the AI verdict inline rather than navigating away immediately,
      // so the requester sees how the request was scored and routed.
      setReviewed(result);
    } catch (err) {
      toast.error(
        intl.formatMessage({ id: "requests.createFailed", defaultMessage: "Could not create request" }),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  const columns: Column<AccessRequest>[] = [
    {
      header: intl.formatMessage({ id: "requests.col.resource", defaultMessage: "Resource" }),
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
      header: intl.formatMessage({ id: "requests.col.state", defaultMessage: "State" }),
      width: 130,
      cell: (r) => <StatusBadge status={r.state} />,
    },
    {
      header: intl.formatMessage({ id: "requests.risk.score", defaultMessage: "Risk score" }),
      width: 90,
      cell: (r) =>
        r.risk_level ? (
          <Badge tone={riskScoreTone(r.risk_level)}>{r.risk_level}</Badge>
        ) : (
          <span className="muted">—</span>
        ),
    },
    {
      header: intl.formatMessage({ id: "requests.col.requested", defaultMessage: "Requested" }),
      width: 120,
      cell: (r) => <span className="muted">{formatRelative(r.created_at)}</span>,
    },
  ];

  return (
    <>
      <PageHeader
        title={intl.formatMessage({ id: "nav.requests", defaultMessage: "Access requests" })}
        subtitle={intl.formatMessage({
          id: "requests.subtitle",
          defaultMessage:
            "Joiner / mover provisioning lane — request, approve, and provision access through connectors.",
        })}
        actions={
          <button className="btn btn--primary" onClick={() => setOpen(true)}>
            {intl.formatMessage({ id: "requests.new", defaultMessage: "New request" })}
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
            title={intl.formatMessage({ id: "requests.empty.title", defaultMessage: "No access requests" })}
            description={intl.formatMessage({
              id: "requests.empty.desc",
              defaultMessage:
                "Requests created here run through approval and connector provisioning, with every state change recorded.",
            })}
            action={
              <button
                className="btn btn--primary btn--sm"
                onClick={() => setOpen(true)}
              >
                {intl.formatMessage({ id: "requests.new", defaultMessage: "New request" })}
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
          title={
            reviewed
              ? intl.formatMessage({ id: "requests.risk.title", defaultMessage: "AI risk review" })
              : intl.formatMessage({ id: "requests.new", defaultMessage: "New access request" })
          }
          onClose={reset}
          footer={
            reviewed ? (
              <>
                <button className="btn btn--ghost" onClick={reset}>
                  {intl.formatMessage({ id: "common.close", defaultMessage: "Close" })}
                </button>
                <button
                  className="btn btn--primary"
                  onClick={() =>
                    navigate({
                      to: "/requests/$requestId",
                      params: { requestId: reviewed.request.id },
                    })
                  }
                >
                  {intl.formatMessage({ id: "requests.view", defaultMessage: "View request" })}
                </button>
              </>
            ) : (
              <>
                <button className="btn btn--ghost" onClick={reset}>
                  {intl.formatMessage({ id: "common.cancel", defaultMessage: "Cancel" })}
                </button>
                <button
                  className="btn btn--primary"
                  disabled={!valid || createMut.isPending}
                  onClick={submit}
                >
                  {intl.formatMessage({ id: "requests.create", defaultMessage: "Create request" })}
                </button>
              </>
            )
          }
        >
          {reviewed ? (
            <RiskPanel verdict={reviewed.risk} />
          ) : (
            <>
              <label className="field">
                <span>
                  {intl.formatMessage({
                    id: "requests.create.resource",
                    defaultMessage: "Resource reference (required)",
                  })}
                </span>
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
                  <span>
                    {intl.formatMessage({ id: "requests.create.role", defaultMessage: "Role (required)" })}
                  </span>
                  <input
                    value={draft.role}
                    placeholder="viewer, admin…"
                    onChange={(e) => setDraft({ ...draft, role: e.target.value })}
                  />
                </label>
                <label className="field">
                  <span>
                    {intl.formatMessage({
                      id: "requests.create.target",
                      defaultMessage: "Target user (optional)",
                    })}
                  </span>
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
                <span>
                  {intl.formatMessage({
                    id: "requests.create.connector",
                    defaultMessage: "Connector (optional)",
                  })}
                </span>
                <input
                  value={draft.connector_id}
                  placeholder="connector id for automated provisioning"
                  onChange={(e) =>
                    setDraft({ ...draft, connector_id: e.target.value })
                  }
                />
              </label>
              <div className="field-row">
                <label className="field">
                  <span>
                    {intl.formatMessage({ id: "requests.create.tags", defaultMessage: "Resource tags (optional)" })}
                  </span>
                  <input
                    value={draft.resource_tags}
                    placeholder="prod, pii, finance…"
                    onChange={(e) =>
                      setDraft({ ...draft, resource_tags: e.target.value })
                    }
                  />
                </label>
                <label className="field">
                  <span>
                    {intl.formatMessage({ id: "requests.create.duration", defaultMessage: "Duration in hours (optional)" })}
                  </span>
                  <input
                    type="number"
                    min={1}
                    value={draft.duration_hours}
                    placeholder="8"
                    onChange={(e) =>
                      setDraft({ ...draft, duration_hours: e.target.value })
                    }
                  />
                </label>
              </div>
              <label className="field">
                <span>
                  {intl.formatMessage({
                    id: "requests.create.justification",
                    defaultMessage: "Justification (required)",
                  })}
                </span>
                <textarea
                  rows={3}
                  value={draft.justification}
                  placeholder="Why is this access needed?"
                  onChange={(e) =>
                    setDraft({ ...draft, justification: e.target.value })
                  }
                />
              </label>
              <p className="muted" style={{ fontSize: 12, margin: "4px 0 0" }}>
                <RecommendationBadge rec={undefined} />{" "}
                {intl.formatMessage({
                  id: "requests.create.aiHint",
                  defaultMessage:
                    "On submit, the access AI agent scores this request server-side and routes it. A high-risk request is never auto-approved.",
                })}
              </p>
            </>
          )}
        </Modal>
      )}
    </>
  );
}
