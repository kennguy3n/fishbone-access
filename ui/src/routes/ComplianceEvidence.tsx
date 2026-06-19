import { useState } from "react";
import { useIntl } from "react-intl";
import { useLaneA5Scope } from "./lane-a5";
import {
  PageHeader,
  Card,
  Stat,
  Badge,
  AsyncBoundary,
} from "@/components/ui";
import { EmptyState } from "@/components/EmptyState";
import { useToast } from "@/components/Toast";
import { HelpTooltip } from "@/components/HelpTooltip";
import { formatDateTime, titleCase } from "@/lib/format";
import {
  useMe,
  useMyPermissions,
  useCoverage,
  useChainVerification,
  useEvidence,
  useExportEvidencePack,
  FRAMEWORKS,
  type ControlCoverage,
  type EvidenceRecord,
  type Framework,
} from "@/api/access";

const EXPORT_PERMISSION = "compliance.export";

// Compliance evidence dashboard: control coverage by framework (computed from
// the audit hash chain), a tamper-evidence check on that chain, an evidence
// timeline, and one-click framework-mapped pack export. Export is gated
// server-side by RequirePermission("compliance.export") + step-up MFA; the UI
// mirrors that gate so the affordance reads honestly.
export function ComplianceEvidence() {
  useLaneA5Scope();
  const intl = useIntl();
  const [framework, setFramework] = useState<Framework>("SOC 2");

  const coverageQ = useCoverage(framework);
  // order: "desc" so the bounded read returns the most-recent events (matching
  // the "Most recent" timeline label); without it the chain scans oldest-first
  // and a workspace with >50 events would permanently show its oldest 50.
  const evidenceQ = useEvidence({ limit: 50, order: "desc" });

  return (
    <>
      <PageHeader
        title={intl.formatMessage({
          id: "evidence.title",
          defaultMessage: "Compliance evidence",
        })}
        subtitle={intl.formatMessage({
          id: "evidence.subtitle",
          defaultMessage:
            "Control coverage and tamper-evident evidence assembled as a side effect of normal access operations — every grant, revocation, policy promotion, review and certification is recorded on the workspace audit hash chain.",
        })}
        actions={<ExportButton framework={framework} />}
      />

      <ChainStatus />

      <div
        className="pill-tabs"
        role="tablist"
        aria-label={intl.formatMessage({
          id: "evidence.framework.aria",
          defaultMessage: "Framework",
        })}
      >
        {FRAMEWORKS.map((f) => (
          <button
            key={f}
            role="tab"
            aria-selected={framework === f}
            className={framework === f ? "active" : ""}
            onClick={() => setFramework(f)}
          >
            {f}
          </button>
        ))}
      </div>

      <AsyncBoundary
        isLoading={coverageQ.isLoading}
        error={coverageQ.error}
        data={coverageQ.data}
        onRetry={coverageQ.refetch}
      >
        {(cov) => (
          <>
            <div className="grid grid--stats">
              <Stat
                label={intl.formatMessage({
                  id: "evidence.stat.covered",
                  defaultMessage: "Controls covered",
                })}
                value={`${cov.controls_covered} / ${cov.controls_total}`}
              />
              <Stat
                label={intl.formatMessage({
                  id: "evidence.stat.records",
                  defaultMessage: "Evidence records",
                })}
                value={cov.evidence_total}
              />
              <Stat
                label={intl.formatMessage({
                  id: "evidence.stat.coverage",
                  defaultMessage: "Coverage",
                })}
                value={`${cov.controls_total === 0 ? 0 : Math.round((cov.controls_covered / cov.controls_total) * 100)}%`}
              />
            </div>

            <Card
              title={intl.formatMessage(
                {
                  id: "evidence.coverage.title",
                  defaultMessage: "{framework} control coverage",
                },
                { framework: cov.framework },
              )}
              subtitle={intl.formatMessage({
                id: "evidence.coverage.subtitle",
                defaultMessage:
                  "A control is covered when the chain holds at least one evidence record of a kind that demonstrates it.",
              })}
            >
              {cov.controls.map((ctrl) => (
                <ControlMeter
                  key={ctrl.id}
                  control={ctrl}
                  total={cov.evidence_total}
                />
              ))}
            </Card>
          </>
        )}
      </AsyncBoundary>

      <Card
        title={intl.formatMessage({
          id: "evidence.timeline.title",
          defaultMessage: "Evidence timeline",
        })}
        subtitle={intl.formatMessage({
          id: "evidence.timeline.subtitle",
          defaultMessage: "Most recent control-relevant events on the audit chain.",
        })}
      >
        <AsyncBoundary
          isLoading={evidenceQ.isLoading}
          error={evidenceQ.error}
          data={evidenceQ.data}
          onRetry={evidenceQ.refetch}
          isEmpty={(rows) => rows.length === 0}
          empty={
            <EmptyState
              title={intl.formatMessage({
                id: "evidence.empty.title",
                defaultMessage: "No evidence yet",
              })}
              description={intl.formatMessage({
                id: "evidence.empty.body",
                defaultMessage:
                  "As access is granted, reviewed and certified, tamper-evident records will appear here.",
              })}
            />
          }
        >
          {(rows) => <EvidenceTimeline records={rows} />}
        </AsyncBoundary>
      </Card>
    </>
  );
}

function ChainStatus() {
  const intl = useIntl();
  const chainQ = useChainVerification();
  if (chainQ.isLoading || !chainQ.data) return null;
  const v = chainQ.data;
  return (
    <Card className={v.ok ? "card--accent-ok" : "card--accent-danger"}>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <Badge tone={v.ok ? "ok" : "danger"} dot>
          {v.ok
            ? intl.formatMessage({
                id: "evidence.chain.intact",
                defaultMessage: "Chain intact",
              })
            : intl.formatMessage({
                id: "evidence.chain.broken",
                defaultMessage: "Chain broken",
              })}
        </Badge>
        <div>
          <div style={{ fontWeight: 600 }}>
            {v.ok
              ? intl.formatMessage(
                  {
                    id: "evidence.chain.verified",
                    defaultMessage:
                      "{n, plural, one {# evidence record verified} other {# evidence records verified}}",
                  },
                  { n: v.length },
                )
              : intl.formatMessage({
                  id: "evidence.chain.tamper",
                  defaultMessage: "Tamper detected on the audit hash chain",
                })}
          </div>
          <div className="muted" style={{ fontSize: 12.5 }}>
            {v.ok
              ? intl.formatMessage({
                  id: "evidence.chain.okBody",
                  defaultMessage:
                    "Every record's SHA-256 link was recomputed and matched.",
                })
              : v.reason
                ? `${v.reason}${v.broken_at_seq != null ? intl.formatMessage({ id: "evidence.chain.seq", defaultMessage: " (sequence {seq})" }, { seq: v.broken_at_seq }) : ""}`
                : intl.formatMessage({
                    id: "evidence.chain.mismatch",
                    defaultMessage:
                      "Recomputed hashes did not match stored links.",
                  })}
          </div>
        </div>
      </div>
    </Card>
  );
}

function ControlMeter({
  control,
  total,
}: {
  control: ControlCoverage;
  total: number;
}) {
  const intl = useIntl();
  const pct = total === 0 ? 0 : Math.round((control.evidence_count / total) * 100);
  return (
    <div className="meter">
      <div className="meter__head">
        <span>
          <b style={{ marginRight: 6 }}>{control.id}</b>
          {control.title}{" "}
          {control.covered ? (
            <Badge tone="ok">
              {intl.formatMessage({
                id: "evidence.control.covered",
                defaultMessage: "Covered",
              })}
            </Badge>
          ) : (
            <Badge tone="warn">
              {intl.formatMessage({
                id: "evidence.control.none",
                defaultMessage: "No evidence",
              })}
            </Badge>
          )}
        </span>
        <b>
          {intl.formatMessage(
            {
              id: "evidence.control.count",
              defaultMessage: "{n, plural, one {# record} other {# records}}",
            },
            { n: control.evidence_count },
          )}
        </b>
      </div>
      <div className="meter__track">
        <div
          className={`meter__fill${control.covered ? " meter__fill--ok" : ""}`}
          style={{ width: `${control.covered ? Math.max(pct, 4) : 0}%` }}
        />
      </div>
    </div>
  );
}

function EvidenceTimeline({ records }: { records: EvidenceRecord[] }) {
  const intl = useIntl();
  const systemLabel = intl.formatMessage({
    id: "evidence.timeline.system",
    defaultMessage: "system",
  });
  return (
    <ul className="timeline">
      {records.map((r) => (
        <li className="timeline__item" key={r.id}>
          <span className="timeline__dot" />
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              flexWrap: "wrap",
            }}
          >
            <Badge tone={r.kind === "other" ? "neutral" : "info"}>
              {titleCase(r.kind)}
            </Badge>
            <span style={{ fontWeight: 600 }}>{r.action}</span>
            <span className="muted" style={{ fontSize: 12 }}>
              #{r.chain_seq}
            </span>
          </div>
          <div className="muted" style={{ fontSize: 12.5, marginTop: 2 }}>
            {r.actor || systemLabel}
            {r.target_ref ? ` · ${r.target_ref}` : ""} ·{" "}
            {formatDateTime(r.occurred_at)}
          </div>
        </li>
      ))}
    </ul>
  );
}

function ExportButton({ framework }: { framework: Framework }) {
  const intl = useIntl();
  const toast = useToast();
  const { data: me } = useMe();
  const { data: myPerms } = useMyPermissions();
  const exportMut = useExportEvidencePack();

  // Gate against the server's RBAC-resolved permission set (the exact set
  // RequirePermission enforces), not the JWT scopes which no longer drive RBAC.
  // undefined = still loading or the RBAC tier isn't mounted (server gate then
  // no-ops) → treat as allowed so an authorized auditor never sees a
  // false-negative disabled button; the server stays the authority either way.
  const hasPerm =
    myPerms === undefined
      ? true
      : myPerms.permissions.includes(EXPORT_PERMISSION);
  const mfaOk = me?.mfa_satisfied ?? false;
  const blocked = !hasPerm || !mfaOk;
  const reason = !hasPerm
    ? intl.formatMessage({
        id: "evidence.export.needPerm",
        defaultMessage: "Requires the compliance.export permission.",
      })
    : !mfaOk
      ? intl.formatMessage({
          id: "evidence.export.needMfa",
          defaultMessage: "Requires step-up MFA — re-authenticate to export.",
        })
      : "";

  const doExport = async () => {
    try {
      const pack = await exportMut.mutateAsync({ framework });
      triggerDownload(pack.blob, pack.filename);
      toast.success(
        intl.formatMessage({
          id: "evidence.export.toast.title",
          defaultMessage: "Evidence pack exported",
        }),
        pack.digest
          ? intl.formatMessage(
              {
                id: "evidence.export.toast.digest",
                defaultMessage:
                  "Digest {digest}… — recorded on the audit chain.",
              },
              { digest: pack.digest.slice(0, 12) },
            )
          : intl.formatMessage({
              id: "evidence.export.toast.body",
              defaultMessage: "The export is recorded on the audit chain.",
            }),
      );
    } catch (e) {
      toast.error(
        intl.formatMessage({
          id: "evidence.export.toast.error",
          defaultMessage: "Could not export evidence pack",
        }),
        e instanceof Error
          ? e.message
          : intl.formatMessage({
              id: "evidence.export.toast.retry",
              defaultMessage: "Please try again.",
            }),
      );
    }
  };

  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
      {blocked && <HelpTooltip>{reason}</HelpTooltip>}
      <button
        className="btn btn--primary"
        disabled={blocked || exportMut.isPending}
        title={blocked ? reason : undefined}
        onClick={doExport}
      >
        {exportMut.isPending
          ? intl.formatMessage({
              id: "evidence.export.exporting",
              defaultMessage: "Exporting…",
            })
          : intl.formatMessage(
              {
                id: "evidence.export.label",
                defaultMessage: "Export {framework} pack",
              },
              { framework },
            )}
      </button>
    </span>
  );
}

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
