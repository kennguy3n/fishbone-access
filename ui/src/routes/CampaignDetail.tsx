import { useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useIntl } from "react-intl";
import { useLaneA5Scope } from "./lane-a5";
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
  useLaneA5Scope();
  const intl = useIntl();
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
        {intl.formatMessage({
          id: "campaignDetail.back",
          defaultMessage: "← All campaigns",
        })}
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
  const intl = useIntl();
  const toast = useToast();
  const decisionMut = useSubmitDecision(id);
  const [pendingItem, setPendingItem] = useState<string | null>(null);
  const [closing, setClosing] = useState(false);

  const running = report.state === "running";
  // Progress tracks TERMINAL decisions only (certify/revoke). Escalation is a
  // non-terminal intermediate state that still needs resolving, so it does not
  // count toward completion — mirrors the server's all_decided derivation
  // (escalated == open). An all-escalated campaign therefore reads 0%, not 100%.
  const decidedTerminal = report.certified + report.revoked;
  const progress =
    report.total === 0 ? 0 : Math.round((decidedTerminal / report.total) * 100);

  const decide = async (
    item: CampaignItemView,
    decision: DecisionInput["decision"],
  ) => {
    setPendingItem(item.item_id);
    try {
      await decisionMut.mutateAsync({ itemID: item.item_id, body: { decision } });
      const title =
        decision === "revoke"
          ? intl.formatMessage({
              id: "campaignDetail.toast.markedRevoke",
              defaultMessage: "Marked to revoke",
            })
          : decision === "certify"
            ? intl.formatMessage({
                id: "campaignDetail.toast.markedCertify",
                defaultMessage: "Certified",
              })
            : intl.formatMessage({
                id: "campaignDetail.toast.markedEscalate",
                defaultMessage: "Escalated",
              });
      const body =
        decision === "revoke"
          ? intl.formatMessage({
              id: "campaignDetail.toast.revokeBody",
              defaultMessage:
                "Staged — the grant is torn down when the campaign closes.",
            })
          : decision === "escalate"
            ? intl.formatMessage({
                id: "campaignDetail.toast.escalateBody",
                defaultMessage: "Escalated for another reviewer to decide.",
              })
            : intl.formatMessage({
                id: "campaignDetail.toast.recordedBody",
                defaultMessage: "Recorded as compliance evidence.",
              });
      toast.success(title, body);
    } catch (e) {
      toast.error(
        intl.formatMessage({
          id: "campaignDetail.toast.decisionError",
          defaultMessage: "Could not record decision",
        }),
        e instanceof Error
          ? e.message
          : intl.formatMessage({
              id: "campaignDetail.toast.retry",
              defaultMessage: "Please try again.",
            }),
      );
    } finally {
      setPendingItem(null);
    }
  };

  const columns: Column<CampaignItemView>[] = [
    {
      header: intl.formatMessage({
        id: "campaignDetail.col.subject",
        defaultMessage: "Subject",
      }),
      cell: (it) => (
        <span style={{ fontWeight: 600 }}>{it.subject || "—"}</span>
      ),
    },
    {
      header: intl.formatMessage({
        id: "campaignDetail.col.resource",
        defaultMessage: "Resource",
      }),
      cell: (it) => (
        <div>
          <code style={{ fontSize: 12 }}>{it.resource_ref || "—"}</code>
          {it.role && (
            <div className="muted" style={{ fontSize: 12 }}>
              {intl.formatMessage(
                { id: "campaignDetail.role", defaultMessage: "role {role}" },
                { role: it.role },
              )}
            </div>
          )}
        </div>
      ),
    },
    {
      header: intl.formatMessage({
        id: "campaignDetail.col.decision",
        defaultMessage: "Decision",
      }),
      cell: (it) => <DecisionBadge item={it} />,
      width: 150,
    },
    {
      header: running
        ? intl.formatMessage({
            id: "campaignDetail.col.action",
            defaultMessage: "Action",
          })
        : intl.formatMessage({
            id: "campaignDetail.col.decided",
            defaultMessage: "Decided",
          }),
      cell: (it) =>
        // Escalated is non-terminal: the server allows resolving it to a
        // terminal certify/revoke, so a running campaign must keep the action
        // affordances for escalated items (not just pending ones) — otherwise
        // an escalation can never be worked off.
        running && (it.decision === "pending" || it.decision === "escalate") ? (
          <div className="field-row" style={{ gap: 6 }}>
            <button
              className="btn btn--sm"
              disabled={pendingItem === it.item_id}
              onClick={() => decide(it, "certify")}
            >
              {intl.formatMessage({
                id: "campaignDetail.action.certify",
                defaultMessage: "Certify",
              })}
            </button>
            <button
              className="btn btn--sm btn--danger"
              disabled={pendingItem === it.item_id}
              onClick={() => decide(it, "revoke")}
            >
              {intl.formatMessage({
                id: "campaignDetail.action.revoke",
                defaultMessage: "Revoke",
              })}
            </button>
            <button
              className="btn btn--sm btn--ghost"
              disabled={pendingItem === it.item_id}
              onClick={() => decide(it, "escalate")}
            >
              {intl.formatMessage({
                id: "campaignDetail.action.escalate",
                defaultMessage: "Escalate",
              })}
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
            ? intl.formatMessage(
                {
                  id: "campaignDetail.subtitle.framework",
                  defaultMessage: "Certification campaign · {framework}",
                },
                { framework: report.framework },
              )
            : intl.formatMessage({
                id: "campaignDetail.subtitle",
                defaultMessage: "Certification campaign",
              })
        }
        actions={
          running ? (
            <button
              className="btn btn--primary"
              onClick={() => setClosing(true)}
            >
              {intl.formatMessage({
                id: "campaignDetail.action.close",
                defaultMessage: "Close campaign",
              })}
            </button>
          ) : (
            <StatusBadge status={report.state} />
          )
        }
      />

      <div className="grid grid--stats">
        <Stat
          label={intl.formatMessage({
            id: "campaignDetail.stat.items",
            defaultMessage: "Items",
          })}
          value={report.total}
        />
        <Stat
          label={intl.formatMessage({
            id: "campaignDetail.stat.certified",
            defaultMessage: "Certified",
          })}
          value={report.certified}
        />
        <Stat
          label={intl.formatMessage({
            id: "campaignDetail.stat.revoked",
            defaultMessage: "Revoked (staged)",
          })}
          value={report.revoked}
        />
        <Stat
          label={intl.formatMessage({
            id: "campaignDetail.stat.escalated",
            defaultMessage: "Escalated",
          })}
          value={report.escalated}
        />
        <Stat
          label={intl.formatMessage({
            id: "campaignDetail.stat.pending",
            defaultMessage: "Pending",
          })}
          value={report.pending}
        />
      </div>

      <Card
        title={intl.formatMessage({
          id: "campaignDetail.progress.title",
          defaultMessage: "Progress",
        })}
        subtitle={
          report.overdue
            ? intl.formatMessage({
                id: "campaignDetail.progress.overdue",
                defaultMessage:
                  "This campaign is overdue — it is past its due date with items still pending.",
              })
            : report.due_at
              ? intl.formatMessage(
                  {
                    id: "campaignDetail.progress.due",
                    defaultMessage: "Due {date}",
                  },
                  { date: formatDateTime(report.due_at) },
                )
              : intl.formatMessage({
                  id: "campaignDetail.progress.noDue",
                  defaultMessage: "No due date set.",
                })
        }
        actions={
          report.overdue ? (
            <Badge tone="danger">
              {intl.formatMessage({
                id: "campaignDetail.badge.overdue",
                defaultMessage: "Overdue",
              })}
            </Badge>
          ) : undefined
        }
      >
        <div className="meter">
          <div className="meter__head">
            <span>
              {report.all_decided
                ? intl.formatMessage({
                    id: "campaignDetail.meter.allDecided",
                    defaultMessage: "All items decided",
                  })
                : intl.formatMessage({
                    id: "campaignDetail.meter.recorded",
                    defaultMessage: "Decisions recorded",
                  })}
            </span>
            <b>
              {intl.formatMessage(
                {
                  id: "campaignDetail.meter.percent",
                  defaultMessage: "{pct}%",
                },
                { pct: progress },
              )}
            </b>
          </div>
          <div className="meter__track">
            <div
              className={`meter__fill${report.all_decided ? " meter__fill--ok" : report.overdue ? " meter__fill--warn" : ""}`}
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      </Card>

      <Card
        title={intl.formatMessage({
          id: "campaignDetail.worklist.title",
          defaultMessage: "Reviewer worklist",
        })}
      >
        <AsyncBoundary
          isLoading={itemsLoading}
          error={itemsError}
          data={items}
          onRetry={onItemsRetry}
          isEmpty={(rows) => rows.length === 0}
          empty={
            <EmptyState
              title={intl.formatMessage({
                id: "campaignDetail.empty.title",
                defaultMessage: "No items in scope",
              })}
              description={intl.formatMessage({
                id: "campaignDetail.empty.body",
                defaultMessage:
                  "No live grants matched this campaign's scope when it started.",
              })}
            />
          }
        >
          {(rows) => (
            <DataTable
              columns={columns}
              rows={rows}
              rowKey={(it) => it.item_id}
            />
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
  const intl = useIntl();
  if (item.decision === "revoke") {
    return (
      <Badge tone="danger">
        {item.revoked_at
          ? intl.formatMessage({
              id: "campaignDetail.decision.revoked",
              defaultMessage: "Revoked",
            })
          : intl.formatMessage({
              id: "campaignDetail.decision.revokeStaged",
              defaultMessage: "Revoke (staged)",
            })}
      </Badge>
    );
  }
  if (item.decision === "certify")
    return (
      <Badge tone="ok">
        {intl.formatMessage({
          id: "campaignDetail.decision.certified",
          defaultMessage: "Certified",
        })}
      </Badge>
    );
  if (item.decision === "escalate")
    return (
      <Badge tone="warn">
        {intl.formatMessage({
          id: "campaignDetail.decision.escalated",
          defaultMessage: "Escalated",
        })}
      </Badge>
    );
  return (
    <Badge tone="neutral">
      {intl.formatMessage({
        id: "campaignDetail.decision.pending",
        defaultMessage: "Pending",
      })}
    </Badge>
  );
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
  const intl = useIntl();
  const toast = useToast();
  const navigate = useNavigate();
  const previewQ = useRevocationPreview(id);
  const closeMut = useCloseCampaign(id);

  const confirm = async () => {
    try {
      const res = await closeMut.mutateAsync();
      toast.success(
        intl.formatMessage({
          id: "campaignDetail.close.toast.title",
          defaultMessage: "Campaign closed",
        }),
        intl.formatMessage(
          {
            id: "campaignDetail.close.toast.body",
            defaultMessage:
              "{n, plural, one {# staged revocation applied} other {# staged revocations applied}}. The close is recorded as evidence.",
          },
          { n: res.revoked },
        ),
      );
      onClose();
      navigate({ to: "/compliance/campaigns" });
    } catch (e) {
      toast.error(
        intl.formatMessage({
          id: "campaignDetail.close.toast.error",
          defaultMessage: "Could not close campaign",
        }),
        e instanceof Error
          ? e.message
          : intl.formatMessage({
              id: "campaignDetail.toast.retry",
              defaultMessage: "Please try again.",
            }),
      );
    }
  };

  return (
    <Modal
      title={intl.formatMessage({
        id: "campaignDetail.close.title",
        defaultMessage: "Close campaign",
      })}
      onClose={onClose}
      footer={
        <>
          <button className="btn btn--ghost" onClick={onClose}>
            {intl.formatMessage({
              id: "campaignDetail.close.cancel",
              defaultMessage: "Cancel",
            })}
          </button>
          <button
            className="btn btn--danger"
            disabled={closeMut.isPending || previewQ.isLoading}
            onClick={confirm}
          >
            {intl.formatMessage({
              id: "campaignDetail.close.confirm",
              defaultMessage: "Close & apply revocations",
            })}
          </button>
        </>
      }
    >
      {report.pending > 0 && (
        <p className="muted">
          {intl.formatMessage(
            {
              id: "campaignDetail.close.pendingWarn",
              defaultMessage:
                "{n, plural, one {# item is} other {# items are}} still pending. Closing now certifies nothing further — only the staged revocations below are applied.",
            },
            { n: report.pending },
          )}
        </p>
      )}
      <p style={{ fontWeight: 600 }}>
        {intl.formatMessage({
          id: "campaignDetail.close.heading",
          defaultMessage: "Closing this campaign will revoke the following grants:",
        })}
      </p>
      <AsyncBoundary
        isLoading={previewQ.isLoading}
        error={previewQ.error}
        data={previewQ.data}
        onRetry={previewQ.refetch}
        isEmpty={(rows) => rows.length === 0}
        empty={
          <EmptyState
            title={intl.formatMessage({
              id: "campaignDetail.close.noneTitle",
              defaultMessage: "No revocations staged",
            })}
            description={intl.formatMessage({
              id: "campaignDetail.close.noneBody",
              defaultMessage:
                "No items were decided 'revoke', so closing tears down nothing. Decisions remain recorded as evidence.",
            })}
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
                  {r.role
                    ? intl.formatMessage(
                        {
                          id: "campaignDetail.close.roleSuffix",
                          defaultMessage: " · role {role}",
                        },
                        { role: r.role },
                      )
                    : ""}
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
