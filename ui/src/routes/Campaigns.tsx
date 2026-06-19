import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useIntl, type IntlShape } from "react-intl";
import { useLaneA5Scope } from "./lane-a5";
import {
  PageHeader,
  Card,
  Badge,
  StatusBadge,
  AsyncBoundary,
} from "@/components/ui";
import { EmptyState } from "@/components/EmptyState";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/Toast";
import { DataTable, type Column } from "@/components/DataTable";
import { formatDateTime } from "@/lib/format";
import {
  useCampaigns,
  useStartCampaign,
  useEnforceOverdue,
  FRAMEWORKS,
  type CertificationCampaign,
  type StartCampaignInput,
} from "@/api/access";

// Certification campaigns expand access reviews into scoped, reviewer-assigned,
// due-dated certifications. Closing a campaign applies the staged revoke
// decisions (previewed first) — the same test-before-effect guardrail the
// policy promote path enforces. Each decision and the close append evidence to
// the workspace audit chain, so the campaign surface doubles as evidence.
export function Campaigns() {
  useLaneA5Scope();
  const intl = useIntl();
  const navigate = useNavigate();
  const toast = useToast();
  const { data, isLoading, error, refetch } = useCampaigns();
  const enforceMut = useEnforceOverdue();
  const [creating, setCreating] = useState(false);

  const enforceOverdue = async () => {
    try {
      const res = await enforceMut.mutateAsync();
      toast.success(
        res.marked_overdue === 0
          ? intl.formatMessage({
              id: "campaigns.toast.noneOverdue",
              defaultMessage: "No campaigns are overdue",
            })
          : intl.formatMessage(
              {
                id: "campaigns.toast.markedOverdue",
                defaultMessage:
                  "{n, plural, one {# campaign marked overdue} other {# campaigns marked overdue}}",
              },
              { n: res.marked_overdue },
            ),
        intl.formatMessage({
          id: "campaigns.toast.overdueBody",
          defaultMessage: "Overdue transitions are recorded as evidence.",
        }),
      );
    } catch (e) {
      toast.error(
        intl.formatMessage({
          id: "campaigns.toast.sweepError",
          defaultMessage: "Could not run overdue sweep",
        }),
        e instanceof Error
          ? e.message
          : intl.formatMessage({
              id: "campaigns.toast.retry",
              defaultMessage: "Please try again.",
            }),
      );
    }
  };

  const columns: Column<CertificationCampaign>[] = [
    {
      header: intl.formatMessage({
        id: "campaigns.col.campaign",
        defaultMessage: "Campaign",
      }),
      cell: (c) => (
        <div>
          <div style={{ fontWeight: 600 }}>{c.name}</div>
          <div className="muted" style={{ fontSize: 12 }}>
            {scopeSummary(c, intl)}
          </div>
        </div>
      ),
    },
    {
      header: intl.formatMessage({
        id: "campaigns.col.framework",
        defaultMessage: "Framework",
      }),
      cell: (c) =>
        c.framework ? (
          <Badge tone="info">{c.framework}</Badge>
        ) : (
          <span className="muted">—</span>
        ),
      width: 130,
    },
    {
      header: intl.formatMessage({
        id: "campaigns.col.state",
        defaultMessage: "State",
      }),
      cell: (c) => <StatusBadge status={campaignStatus(c)} />,
      width: 120,
    },
    {
      header: intl.formatMessage({
        id: "campaigns.col.due",
        defaultMessage: "Due",
      }),
      cell: (c) =>
        c.due_at ? (
          formatDateTime(c.due_at)
        ) : (
          <span className="muted">
            {intl.formatMessage({
              id: "campaigns.noDueDate",
              defaultMessage: "No due date",
            })}
          </span>
        ),
      width: 180,
    },
    {
      header: intl.formatMessage({
        id: "campaigns.col.created",
        defaultMessage: "Created",
      }),
      cell: (c) => formatDateTime(c.created_at),
      width: 180,
    },
  ];

  return (
    <>
      <PageHeader
        title={intl.formatMessage({
          id: "campaigns.title",
          defaultMessage: "Certification campaigns",
        })}
        subtitle={intl.formatMessage({
          id: "campaigns.subtitle",
          defaultMessage:
            "Scope a set of live grants to reviewers, capture certify / revoke decisions, and apply the staged revocations on close. Every decision is recorded as tamper-evident compliance evidence.",
        })}
        actions={
          <>
            <button
              className="btn btn--ghost"
              onClick={enforceOverdue}
              disabled={enforceMut.isPending}
            >
              {intl.formatMessage({
                id: "campaigns.action.sweep",
                defaultMessage: "Run overdue sweep",
              })}
            </button>
            <button
              className="btn btn--primary"
              onClick={() => setCreating(true)}
            >
              {intl.formatMessage({
                id: "campaigns.action.new",
                defaultMessage: "New campaign",
              })}
            </button>
          </>
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
            title={intl.formatMessage({
              id: "campaigns.empty.title",
              defaultMessage: "No certification campaigns yet",
            })}
            description={intl.formatMessage({
              id: "campaigns.empty.body",
              defaultMessage:
                "Create a campaign to certify who has access to what. Scope it by resource, role, or connector and assign reviewers.",
            })}
            action={
              <button
                className="btn btn--primary"
                onClick={() => setCreating(true)}
              >
                {intl.formatMessage({
                  id: "campaigns.action.new",
                  defaultMessage: "New campaign",
                })}
              </button>
            }
          />
        }
      >
        {(rows) => (
          <Card>
            <DataTable
              columns={columns}
              rows={rows}
              rowKey={(c) => c.id}
              onRowClick={(c) =>
                navigate({
                  to: "/compliance/campaigns/$campaignId",
                  params: { campaignId: c.id },
                })
              }
            />
          </Card>
        )}
      </AsyncBoundary>

      {creating && (
        <CreateCampaignModal
          onClose={() => setCreating(false)}
          onCreated={(id) =>
            navigate({
              to: "/compliance/campaigns/$campaignId",
              params: { campaignId: id },
            })
          }
        />
      )}
    </>
  );
}

function scopeSummary(c: CertificationCampaign, intl: IntlShape): string {
  const parts: string[] = [];
  if (c.scope_resource)
    parts.push(
      intl.formatMessage(
        { id: "campaigns.scope.resource", defaultMessage: "resource {v}" },
        { v: c.scope_resource },
      ),
    );
  if (c.scope_role)
    parts.push(
      intl.formatMessage(
        { id: "campaigns.scope.role", defaultMessage: "role {v}" },
        { v: c.scope_role },
      ),
    );
  if (c.scope_connector_id)
    parts.push(
      intl.formatMessage({
        id: "campaigns.scope.connector",
        defaultMessage: "scoped connector",
      }),
    );
  return parts.length > 0
    ? intl.formatMessage(
        { id: "campaigns.scope.some", defaultMessage: "Scope: {parts}" },
        { parts: parts.join(", ") },
      )
    : intl.formatMessage({
        id: "campaigns.scope.all",
        defaultMessage: "Scope: all grants",
      });
}

// A running campaign past its due date with pending items reads as "overdue"
// even before the periodic sweep stamps it, mirroring the report's derivation.
function campaignStatus(c: CertificationCampaign): string {
  if (c.state === "running" && c.overdue_at) return "overdue";
  return c.state;
}

function CreateCampaignModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (id: string) => void;
}) {
  const intl = useIntl();
  const toast = useToast();
  const startMut = useStartCampaign();
  const [name, setName] = useState("");
  const [framework, setFramework] = useState("");
  const [scopeResource, setScopeResource] = useState("");
  const [scopeRole, setScopeRole] = useState("");
  const [reviewers, setReviewers] = useState("");
  const [dueAt, setDueAt] = useState("");

  const submit = async () => {
    if (name.trim() === "") return;
    const body: StartCampaignInput = {
      name: name.trim(),
      framework: framework || undefined,
      scope_resource: scopeResource.trim() || undefined,
      scope_role: scopeRole.trim() || undefined,
      reviewers: parseReviewers(reviewers),
      // The native datetime-local value has no timezone; treat it as local and
      // serialize to an absolute RFC3339 instant the control plane can parse.
      due_at: dueAt ? new Date(dueAt).toISOString() : null,
    };
    try {
      const res = await startMut.mutateAsync(body);
      toast.success(
        intl.formatMessage(
          {
            id: "campaigns.toast.created",
            defaultMessage:
              "Campaign created with {n, plural, one {# item} other {# items}}",
          },
          { n: res.item_count },
        ),
        intl.formatMessage({
          id: "campaigns.toast.createdBody",
          defaultMessage:
            "Reviewers can now certify or revoke each grant in scope.",
        }),
      );
      onCreated(res.campaign.id);
    } catch (e) {
      toast.error(
        intl.formatMessage({
          id: "campaigns.toast.createError",
          defaultMessage: "Could not create campaign",
        }),
        e instanceof Error
          ? e.message
          : intl.formatMessage({
              id: "campaigns.toast.retry",
              defaultMessage: "Please try again.",
            }),
      );
    }
  };

  return (
    <Modal
      title={intl.formatMessage({
        id: "campaigns.create.title",
        defaultMessage: "New certification campaign",
      })}
      onClose={onClose}
      footer={
        <>
          <button className="btn btn--ghost" onClick={onClose}>
            {intl.formatMessage({
              id: "campaigns.create.cancel",
              defaultMessage: "Cancel",
            })}
          </button>
          <button
            className="btn btn--primary"
            disabled={name.trim() === "" || startMut.isPending}
            onClick={submit}
          >
            {intl.formatMessage({
              id: "campaigns.create.submit",
              defaultMessage: "Create campaign",
            })}
          </button>
        </>
      }
    >
      <label className="field">
        <span>
          {intl.formatMessage({
            id: "campaigns.create.name",
            defaultMessage: "Campaign name",
          })}
        </span>
        <input
          value={name}
          autoFocus
          placeholder={intl.formatMessage({
            id: "campaigns.create.namePlaceholder",
            defaultMessage: "e.g. Q3 production access certification",
          })}
          onChange={(e) => setName(e.target.value)}
        />
      </label>

      <label className="field">
        <span>
          {intl.formatMessage({
            id: "campaigns.create.framework",
            defaultMessage: "Framework (optional)",
          })}
        </span>
        <select value={framework} onChange={(e) => setFramework(e.target.value)}>
          <option value="">
            {intl.formatMessage({
              id: "campaigns.create.noFramework",
              defaultMessage: "Not framework-tagged",
            })}
          </option>
          {FRAMEWORKS.map((f) => (
            <option key={f} value={f}>
              {f}
            </option>
          ))}
        </select>
      </label>

      <div className="field-row">
        <label className="field">
          <span>
            {intl.formatMessage({
              id: "campaigns.create.scopeResource",
              defaultMessage: "Scope — resource (optional)",
            })}
          </span>
          <input
            value={scopeResource}
            placeholder={intl.formatMessage({
              id: "campaigns.create.scopeResourcePlaceholder",
              defaultMessage: "e.g. prod-db (blank = all)",
            })}
            onChange={(e) => setScopeResource(e.target.value)}
          />
        </label>
        <label className="field">
          <span>
            {intl.formatMessage({
              id: "campaigns.create.scopeRole",
              defaultMessage: "Scope — role (optional)",
            })}
          </span>
          <input
            value={scopeRole}
            placeholder={intl.formatMessage({
              id: "campaigns.create.scopeRolePlaceholder",
              defaultMessage: "e.g. admin (blank = all)",
            })}
            onChange={(e) => setScopeRole(e.target.value)}
          />
        </label>
      </div>

      <label className="field">
        <span>
          {intl.formatMessage({
            id: "campaigns.create.reviewers",
            defaultMessage: "Reviewers (optional, comma-separated)",
          })}
        </span>
        <input
          value={reviewers}
          placeholder={intl.formatMessage({
            id: "campaigns.create.reviewersPlaceholder",
            defaultMessage: "e.g. alice@acme.com, bob@acme.com",
          })}
          onChange={(e) => setReviewers(e.target.value)}
        />
      </label>

      <label className="field">
        <span>
          {intl.formatMessage({
            id: "campaigns.create.due",
            defaultMessage: "Due date (optional)",
          })}
        </span>
        <input
          type="datetime-local"
          value={dueAt}
          onChange={(e) => setDueAt(e.target.value)}
        />
      </label>
    </Modal>
  );
}

function parseReviewers(raw: string): string[] {
  return raw
    .split(",")
    .map((r) => r.trim())
    .filter((r) => r !== "");
}
