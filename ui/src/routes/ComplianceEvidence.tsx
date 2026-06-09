import { useState } from "react";
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
  const [framework, setFramework] = useState<Framework>("SOC 2");

  const coverageQ = useCoverage(framework);
  const evidenceQ = useEvidence({ limit: 50 });

  return (
    <>
      <PageHeader
        title="Compliance evidence"
        subtitle="Control coverage and tamper-evident evidence assembled as a side effect of normal access operations — every grant, revocation, policy promotion, review and certification is recorded on the workspace audit hash chain."
        actions={<ExportButton framework={framework} />}
      />

      <ChainStatus />

      <div className="pill-tabs" role="tablist" aria-label="Framework">
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
                label="Controls covered"
                value={`${cov.controls_covered} / ${cov.controls_total}`}
              />
              <Stat label="Evidence records" value={cov.evidence_total} />
              <Stat
                label="Coverage"
                value={`${cov.controls_total === 0 ? 0 : Math.round((cov.controls_covered / cov.controls_total) * 100)}%`}
              />
            </div>

            <Card
              title={`${cov.framework} control coverage`}
              subtitle="A control is covered when the chain holds at least one evidence record of a kind that demonstrates it."
            >
              {cov.controls.map((ctrl) => (
                <ControlMeter key={ctrl.id} control={ctrl} total={cov.evidence_total} />
              ))}
            </Card>
          </>
        )}
      </AsyncBoundary>

      <Card
        title="Evidence timeline"
        subtitle="Most recent control-relevant events on the audit chain."
      >
        <AsyncBoundary
          isLoading={evidenceQ.isLoading}
          error={evidenceQ.error}
          data={evidenceQ.data}
          onRetry={evidenceQ.refetch}
          isEmpty={(rows) => rows.length === 0}
          empty={
            <EmptyState
              title="No evidence yet"
              description="As access is granted, reviewed and certified, tamper-evident records will appear here."
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
  const chainQ = useChainVerification();
  if (chainQ.isLoading || !chainQ.data) return null;
  const v = chainQ.data;
  return (
    <Card className={v.ok ? "card--accent-ok" : "card--accent-danger"}>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <Badge tone={v.ok ? "ok" : "danger"} dot>
          {v.ok ? "Chain intact" : "Chain broken"}
        </Badge>
        <div>
          <div style={{ fontWeight: 600 }}>
            {v.ok
              ? `${v.length} evidence record${v.length === 1 ? "" : "s"} verified`
              : "Tamper detected on the audit hash chain"}
          </div>
          <div className="muted" style={{ fontSize: 12.5 }}>
            {v.ok
              ? "Every record's SHA-256 link was recomputed and matched."
              : v.reason
                ? `${v.reason}${v.broken_at_seq != null ? ` (sequence ${v.broken_at_seq})` : ""}`
                : "Recomputed hashes did not match stored links."}
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
  const pct = total === 0 ? 0 : Math.round((control.evidence_count / total) * 100);
  return (
    <div className="meter">
      <div className="meter__head">
        <span>
          <b style={{ marginRight: 6 }}>{control.id}</b>
          {control.title}{" "}
          {control.covered ? (
            <Badge tone="ok">Covered</Badge>
          ) : (
            <Badge tone="warn">No evidence</Badge>
          )}
        </span>
        <b>
          {control.evidence_count} record{control.evidence_count === 1 ? "" : "s"}
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
  return (
    <ul className="timeline">
      {records.map((r) => (
        <li className="timeline__item" key={r.id}>
          <span className="timeline__dot" />
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <Badge tone={r.kind === "other" ? "neutral" : "info"}>
              {titleCase(r.kind)}
            </Badge>
            <span style={{ fontWeight: 600 }}>{r.action}</span>
            <span className="muted" style={{ fontSize: 12 }}>
              #{r.chain_seq}
            </span>
          </div>
          <div className="muted" style={{ fontSize: 12.5, marginTop: 2 }}>
            {r.actor || "system"}
            {r.target_ref ? ` · ${r.target_ref}` : ""} · {formatDateTime(r.occurred_at)}
          </div>
        </li>
      ))}
    </ul>
  );
}

function ExportButton({ framework }: { framework: Framework }) {
  const toast = useToast();
  const { data: me } = useMe();
  const exportMut = useExportEvidencePack();

  const hasScope = me ? hasPermission(me.scopes, EXPORT_PERMISSION) : false;
  const mfaOk = me?.mfa_satisfied ?? false;
  const blocked = !hasScope || !mfaOk;
  const reason = !hasScope
    ? "Requires the compliance.export permission."
    : !mfaOk
      ? "Requires step-up MFA — re-authenticate to export."
      : "";

  const doExport = async () => {
    try {
      const pack = await exportMut.mutateAsync({ framework });
      triggerDownload(pack.blob, pack.filename);
      toast.success(
        "Evidence pack exported",
        pack.digest
          ? `Digest ${pack.digest.slice(0, 12)}… — recorded on the audit chain.`
          : "The export is recorded on the audit chain.",
      );
    } catch (e) {
      toast.error(
        "Could not export evidence pack",
        e instanceof Error ? e.message : "Please try again.",
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
        {exportMut.isPending ? "Exporting…" : `Export ${framework} pack`}
      </button>
    </span>
  );
}

// hasPermission mirrors the server-side middleware (RequirePermission): an
// exact scope, a prefix wildcard ("compliance.*"), or the global "*" grants it.
function hasPermission(scopes: string[] | undefined, permission: string): boolean {
  if (!scopes) return false;
  for (const scope of scopes) {
    if (scope === "*" || scope === permission) return true;
    if (scope.endsWith(".*")) {
      const prefix = scope.slice(0, -1); // keep the trailing dot
      // Mirror the server's strict-length guard (permission.go): a prefix
      // wildcard like "compliance.*" must match something AFTER the dot, so a
      // bare "compliance." never satisfies it. Keeps this client check a
      // faithful, non-divergent mirror of the authoritative server rule.
      if (permission.length > prefix.length && permission.startsWith(prefix)) return true;
    }
  }
  return false;
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
