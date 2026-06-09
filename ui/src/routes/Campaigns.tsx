import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
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
          ? "No campaigns are overdue"
          : `${res.marked_overdue} campaign${res.marked_overdue === 1 ? "" : "s"} marked overdue`,
        "Overdue transitions are recorded as evidence.",
      );
    } catch (e) {
      toast.error(
        "Could not run overdue sweep",
        e instanceof Error ? e.message : "Please try again.",
      );
    }
  };

  const columns: Column<CertificationCampaign>[] = [
    {
      header: "Campaign",
      cell: (c) => (
        <div>
          <div style={{ fontWeight: 600 }}>{c.name}</div>
          <div className="muted" style={{ fontSize: 12 }}>
            {scopeSummary(c)}
          </div>
        </div>
      ),
    },
    {
      header: "Framework",
      cell: (c) =>
        c.framework ? <Badge tone="info">{c.framework}</Badge> : <span className="muted">—</span>,
      width: 130,
    },
    {
      header: "State",
      cell: (c) => <StatusBadge status={campaignStatus(c)} />,
      width: 120,
    },
    {
      header: "Due",
      cell: (c) => (c.due_at ? formatDateTime(c.due_at) : <span className="muted">No due date</span>),
      width: 180,
    },
    {
      header: "Created",
      cell: (c) => formatDateTime(c.created_at),
      width: 180,
    },
  ];

  return (
    <>
      <PageHeader
        title="Certification campaigns"
        subtitle="Scope a set of live grants to reviewers, capture certify / revoke decisions, and apply the staged revocations on close. Every decision is recorded as tamper-evident compliance evidence."
        actions={
          <>
            <button
              className="btn btn--ghost"
              onClick={enforceOverdue}
              disabled={enforceMut.isPending}
            >
              Run overdue sweep
            </button>
            <button className="btn btn--primary" onClick={() => setCreating(true)}>
              New campaign
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
            title="No certification campaigns yet"
            description="Create a campaign to certify who has access to what. Scope it by resource, role, or connector and assign reviewers."
            action={
              <button className="btn btn--primary" onClick={() => setCreating(true)}>
                New campaign
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

function scopeSummary(c: CertificationCampaign): string {
  const parts: string[] = [];
  if (c.scope_resource) parts.push(`resource ${c.scope_resource}`);
  if (c.scope_role) parts.push(`role ${c.scope_role}`);
  if (c.scope_connector_id) parts.push("scoped connector");
  return parts.length > 0 ? `Scope: ${parts.join(", ")}` : "Scope: all grants";
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
        `Campaign created with ${res.items.length} item${res.items.length === 1 ? "" : "s"}`,
        "Reviewers can now certify or revoke each grant in scope.",
      );
      onCreated(res.campaign.id);
    } catch (e) {
      toast.error(
        "Could not create campaign",
        e instanceof Error ? e.message : "Please try again.",
      );
    }
  };

  return (
    <Modal
      title="New certification campaign"
      onClose={onClose}
      footer={
        <>
          <button className="btn btn--ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn--primary"
            disabled={name.trim() === "" || startMut.isPending}
            onClick={submit}
          >
            Create campaign
          </button>
        </>
      }
    >
      <label className="field">
        <span>Campaign name</span>
        <input
          value={name}
          autoFocus
          placeholder="e.g. Q3 production access certification"
          onChange={(e) => setName(e.target.value)}
        />
      </label>

      <label className="field">
        <span>Framework (optional)</span>
        <select value={framework} onChange={(e) => setFramework(e.target.value)}>
          <option value="">Not framework-tagged</option>
          {FRAMEWORKS.map((f) => (
            <option key={f} value={f}>
              {f}
            </option>
          ))}
        </select>
      </label>

      <div className="field-row">
        <label className="field">
          <span>Scope — resource (optional)</span>
          <input
            value={scopeResource}
            placeholder="e.g. prod-db (blank = all)"
            onChange={(e) => setScopeResource(e.target.value)}
          />
        </label>
        <label className="field">
          <span>Scope — role (optional)</span>
          <input
            value={scopeRole}
            placeholder="e.g. admin (blank = all)"
            onChange={(e) => setScopeRole(e.target.value)}
          />
        </label>
      </div>

      <label className="field">
        <span>Reviewers (optional, comma-separated)</span>
        <input
          value={reviewers}
          placeholder="e.g. alice@acme.com, bob@acme.com"
          onChange={(e) => setReviewers(e.target.value)}
        />
      </label>

      <label className="field">
        <span>Due date (optional)</span>
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
