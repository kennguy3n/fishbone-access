import { useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import {
  PageHeader,
  Card,
  Stat,
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
  useCampaignReport,
  useCampaignItems,
  useRevocationPreview,
  useSubmitDecision,
  useCloseCampaign,
  type CampaignItemView,
  type CampaignReport,
  type DecisionInput,
} from "@/api/access";

export function CampaignDetail() {
  const params = useParams({ strict: false }) as { campaignId?: string };
  const id = params.campaignId;
  const navigate = useNavigate();

  const reportQ = useCampaignReport(id);
  const itemsQ = useCampaignItems(id);

  return (
    <>
      <button
        className="btn btn--ghost btn--sm"
        onClick={() => navigate({ to: "/compliance/campaigns" })}
        style={{ marginBottom: 12 }}
      >
        ← All campaigns
      </button>

      <AsyncBoundary
        isLoading={reportQ.isLoading}
        error={reportQ.error}
        data={reportQ.data}
        onRetry={reportQ.refetch}
      >
        {(report) => (
          <CampaignBody
            id={id as string}
            report={report}
            items={itemsQ.data ?? []}
            itemsLoading={itemsQ.isLoading}
            itemsError={itemsQ.error}
            onItemsRetry={itemsQ.refetch}
          />
        )}
      </AsyncBoundary>
    </>
  );
}

function CampaignBody({
  id,
  report,
  items,
  itemsLoading,
  itemsError,
  onItemsRetry,
}: {
  id: string;
  report: CampaignReport;
  items: CampaignItemView[];
  itemsLoading: boolean;
  itemsError: unknown;
  onItemsRetry: () => void;
}) {
  const toast = useToast();
  const decisionMut = useSubmitDecision(id);
  const [pendingItem, setPendingItem] = useState<string | null>(null);
  const [closing, setClosing] = useState(false);

  const running = report.state === "running";
  const progress =
    report.total === 0 ? 0 : Math.round(((report.total - report.pending) / report.total) * 100);

  const decide = async (item: CampaignItemView, decision: DecisionInput["decision"]) => {
    setPendingItem(item.item_id);
    try {
      await decisionMut.mutateAsync({ itemID: item.item_id, body: { decision } });
      toast.success(
        `Marked ${decision}`,
        decision === "revoke"
          ? "Staged — the grant is torn down when the campaign closes."
          : "Recorded as compliance evidence.",
      );
    } catch (e) {
      toast.error(
        "Could not record decision",
        e instanceof Error ? e.message : "Please try again.",
      );
    } finally {
      setPendingItem(null);
    }
  };

  const columns: Column<CampaignItemView>[] = [
    {
      header: "Subject",
      cell: (it) => <span style={{ fontWeight: 600 }}>{it.subject || "—"}</span>,
    },
    {
      header: "Resource",
      cell: (it) => (
        <div>
          <code style={{ fontSize: 12 }}>{it.resource_ref || "—"}</code>
          {it.role && (
            <div className="muted" style={{ fontSize: 12 }}>
              role {it.role}
            </div>
          )}
        </div>
      ),
    },
    {
      header: "Decision",
      cell: (it) => <DecisionBadge item={it} />,
      width: 150,
    },
    {
      header: running ? "Action" : "Decided",
      cell: (it) =>
        running && it.decision === "pending" ? (
          <div className="field-row" style={{ gap: 6 }}>
            <button
              className="btn btn--sm"
              disabled={pendingItem === it.item_id}
              onClick={() => decide(it, "certify")}
            >
              Certify
            </button>
            <button
              className="btn btn--sm btn--danger"
              disabled={pendingItem === it.item_id}
              onClick={() => decide(it, "revoke")}
            >
              Revoke
            </button>
            <button
              className="btn btn--sm btn--ghost"
              disabled={pendingItem === it.item_id}
              onClick={() => decide(it, "escalate")}
            >
              Escalate
            </button>
          </div>
        ) : (
          <span className="muted" style={{ fontSize: 12 }}>
            {it.decided_by ? `${it.decided_by} · ` : ""}
            {it.decided_at ? formatDateTime(it.decided_at) : "—"}
          </span>
        ),
      width: running ? 250 : 220,
    },
  ];

  return (
    <>
      <PageHeader
        title={report.name}
        subtitle={
          report.framework
            ? `Certification campaign · ${report.framework}`
            : "Certification campaign"
        }
        actions={
          running ? (
            <button className="btn btn--primary" onClick={() => setClosing(true)}>
              Close campaign
            </button>
          ) : (
            <StatusBadge status={report.state} />
          )
        }
      />

      <div className="grid grid--stats">
        <Stat label="Items" value={report.total} />
        <Stat label="Certified" value={report.certified} />
        <Stat label="Revoked (staged)" value={report.revoked} />
        <Stat label="Escalated" value={report.escalated} />
        <Stat label="Pending" value={report.pending} />
      </div>

      <Card
        title="Progress"
        subtitle={
          report.overdue
            ? "This campaign is overdue — it is past its due date with items still pending."
            : report.due_at
              ? `Due ${formatDateTime(report.due_at)}`
              : "No due date set."
        }
        actions={
          report.overdue ? <Badge tone="danger">Overdue</Badge> : undefined
        }
      >
        <div className="meter">
          <div className="meter__head">
            <span>{report.all_decided ? "All items decided" : "Decisions recorded"}</span>
            <b>{progress}%</b>
          </div>
          <div className="meter__track">
            <div
              className={`meter__fill${report.all_decided ? " meter__fill--ok" : report.overdue ? " meter__fill--warn" : ""}`}
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      </Card>

      <Card title="Reviewer worklist">
        <AsyncBoundary
          isLoading={itemsLoading}
          error={itemsError}
          data={items}
          onRetry={onItemsRetry}
          isEmpty={(rows) => rows.length === 0}
          empty={
            <EmptyState
              title="No items in scope"
              description="No live grants matched this campaign's scope when it started."
            />
          }
        >
          {(rows) => (
            <DataTable columns={columns} rows={rows} rowKey={(it) => it.item_id} />
          )}
        </AsyncBoundary>
      </Card>

      {closing && (
        <CloseCampaignModal
          id={id}
          report={report}
          onClose={() => setClosing(false)}
        />
      )}
    </>
  );
}

function DecisionBadge({ item }: { item: CampaignItemView }) {
  if (item.decision === "revoke") {
    return (
      <Badge tone="danger">
        {item.revoked_at ? "Revoked" : "Revoke (staged)"}
      </Badge>
    );
  }
  if (item.decision === "certify") return <Badge tone="ok">Certified</Badge>;
  if (item.decision === "escalate") return <Badge tone="warn">Escalated</Badge>;
  return <Badge tone="neutral">Pending</Badge>;
}

// CloseCampaignModal is the test-before-effect guardrail for the destructive
// step: it shows the exact set of grants the close would tear down (the staged
// revokes) BEFORE the operator commits — mirroring the policy promote
// simulate-before-apply gate.
function CloseCampaignModal({
  id,
  report,
  onClose,
}: {
  id: string;
  report: CampaignReport;
  onClose: () => void;
}) {
  const toast = useToast();
  const navigate = useNavigate();
  const previewQ = useRevocationPreview(id);
  const closeMut = useCloseCampaign(id);

  const confirm = async () => {
    try {
      const res = await closeMut.mutateAsync();
      toast.success(
        "Campaign closed",
        `${res.revoked} staged revocation${res.revoked === 1 ? "" : "s"} applied. The close is recorded as evidence.`,
      );
      onClose();
      navigate({ to: "/compliance/campaigns" });
    } catch (e) {
      toast.error(
        "Could not close campaign",
        e instanceof Error ? e.message : "Please try again.",
      );
    }
  };

  return (
    <Modal
      title="Close campaign"
      onClose={onClose}
      footer={
        <>
          <button className="btn btn--ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn--danger"
            disabled={closeMut.isPending || previewQ.isLoading}
            onClick={confirm}
          >
            Close &amp; apply revocations
          </button>
        </>
      }
    >
      {report.pending > 0 && (
        <p className="muted">
          {report.pending} item{report.pending === 1 ? " is" : "s are"} still
          pending. Closing now certifies nothing further — only the staged
          revocations below are applied.
        </p>
      )}
      <p style={{ fontWeight: 600 }}>
        Closing this campaign will revoke the following grants:
      </p>
      <AsyncBoundary
        isLoading={previewQ.isLoading}
        error={previewQ.error}
        data={previewQ.data}
        onRetry={previewQ.refetch}
        isEmpty={(rows) => rows.length === 0}
        empty={
          <EmptyState
            title="No revocations staged"
            description="No items were decided 'revoke', so closing tears down nothing. Decisions remain recorded as evidence."
          />
        }
      >
        {(rows) => (
          <ul className="timeline" style={{ marginTop: 8 }}>
            {rows.map((r) => (
              <li className="timeline__item" key={r.item_id}>
                <span className="timeline__dot" />
                <div style={{ fontWeight: 600 }}>{r.subject || r.grant_id}</div>
                <div className="muted" style={{ fontSize: 12 }}>
                  <code>{r.resource_ref || "—"}</code>
                  {r.role ? ` · role ${r.role}` : ""}
                  {r.reason ? ` · ${r.reason}` : ""}
                </div>
              </li>
            ))}
          </ul>
        )}
      </AsyncBoundary>
    </Modal>
  );
}
