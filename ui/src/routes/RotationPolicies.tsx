import { useMemo, useState } from "react";
import { useIntl } from "react-intl";
import { PageHeader, Card, Stat, Badge, StatusBadge } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { HelpTooltip } from "@/components/HelpTooltip";
import { LoadingState, ErrorState } from "@/components/ui";
import { RotationStatus } from "@/components/RotationStatus";
import {
  usePamTargets,
  useRotationPolicies,
  type PamTarget,
  type RotationPolicy,
} from "@/api/access";
import { formatRelative } from "@/lib/format";

// Protocols the rotation engine can genuinely rotate (real executors exist).
const ROTATABLE = new Set(["ssh", "postgres", "mysql"]);

interface Row {
  target: PamTarget;
  policy: RotationPolicy | null;
  rotatable: boolean;
}

function scheduleLabel(
  policy: RotationPolicy | null,
  intl: ReturnType<typeof useIntl>,
): string {
  if (!policy || !policy.enabled) {
    return intl.formatMessage({
      id: "rotation.list.manual",
      defaultMessage: "Manual only",
    });
  }
  const parts: string[] = [];
  if (policy.mode === "interval" && policy.interval_seconds > 0) {
    const days = policy.interval_seconds / 86400;
    parts.push(
      days >= 1 && Number.isInteger(days)
        ? intl.formatMessage(
            {
              id: "rotation.list.everyDays",
              defaultMessage: "Every {n, plural, one {# day} other {# days}}",
            },
            { n: days },
          )
        : intl.formatMessage(
            {
              id: "rotation.list.everyHours",
              defaultMessage: "Every {n, plural, one {# hour} other {# hours}}",
            },
            { n: Math.max(1, Math.round(policy.interval_seconds / 3600)) },
          ),
    );
  }
  if (policy.rotate_on_checkin) {
    parts.push(
      intl.formatMessage({
        id: "rotation.list.onCheckin",
        defaultMessage: "On check-in",
      }),
    );
  }
  return parts.length
    ? parts.join(" · ")
    : intl.formatMessage({
        id: "rotation.list.manual",
        defaultMessage: "Manual only",
      });
}

export function RotationPolicies() {
  const intl = useIntl();
  const targetsQ = usePamTargets();
  const policiesQ = useRotationPolicies();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const isLoading = targetsQ.isLoading || policiesQ.isLoading;
  const error = targetsQ.error || policiesQ.error;

  const rows = useMemo<Row[]>(() => {
    const targets = targetsQ.data ?? [];
    const byTarget = new Map<string, RotationPolicy>();
    for (const p of policiesQ.data ?? []) byTarget.set(p.target_id, p);
    return targets
      .map((target) => ({
        target,
        policy: byTarget.get(target.id) ?? null,
        rotatable: ROTATABLE.has(target.protocol),
      }))
      .sort((a, b) => {
        // Surface configured + failing policies first, then rotatable targets.
        const rank = (r: Row) =>
          r.policy?.last_status === "failed"
            ? 0
            : r.policy?.enabled
              ? 1
              : r.rotatable
                ? 2
                : 3;
        return rank(a) - rank(b) || a.target.name.localeCompare(b.target.name);
      });
  }, [targetsQ.data, policiesQ.data]);

  const stats = useMemo(() => {
    let rotating = 0;
    let dynamic = 0;
    let failing = 0;
    for (const r of rows) {
      if (
        r.policy?.enabled &&
        (r.policy.mode === "interval" || r.policy.rotate_on_checkin)
      ) {
        rotating += 1;
      }
      if (r.policy?.dynamic_enabled) dynamic += 1;
      if (r.policy?.last_status === "failed") failing += 1;
    }
    return { total: rows.length, rotating, dynamic, failing };
  }, [rows]);

  const selected = rows.find((r) => r.target.id === selectedId) ?? null;

  const columns: Column<Row>[] = useMemo(
    () => [
      {
        header: intl.formatMessage({
          id: "rotation.list.col.target",
          defaultMessage: "Target",
        }),
        cell: (r) => (
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <b>{r.target.name}</b>
            <span className="muted" style={{ fontSize: 12 }}>
              <code>{r.target.address}</code>
            </span>
          </div>
        ),
      },
      {
        header: intl.formatMessage({
          id: "rotation.list.col.protocol",
          defaultMessage: "Protocol",
        }),
        cell: (r) => (
          <Badge tone={r.rotatable ? "info" : "neutral"}>{r.target.protocol}</Badge>
        ),
      },
      {
        header: intl.formatMessage({
          id: "rotation.list.col.schedule",
          defaultMessage: "Schedule",
        }),
        cell: (r) => scheduleLabel(r.policy, intl),
      },
      {
        header: intl.formatMessage({
          id: "rotation.list.col.lastRotated",
          defaultMessage: "Last rotated",
        }),
        cell: (r) => (
          <span className="muted">{formatRelative(r.policy?.last_rotation_at)}</span>
        ),
      },
      {
        header: intl.formatMessage({
          id: "rotation.list.col.next",
          defaultMessage: "Next rotation",
        }),
        cell: (r) => (
          <span className="muted">
            {r.policy?.next_rotation_at
              ? formatRelative(r.policy.next_rotation_at)
              : "—"}
          </span>
        ),
      },
      {
        header: intl.formatMessage({
          id: "rotation.list.col.status",
          defaultMessage: "Status",
        }),
        cell: (r) =>
          r.policy?.last_status ? (
            <StatusBadge status={r.policy.last_status} />
          ) : r.policy?.enabled ? (
            <Badge tone="info">
              {intl.formatMessage({
                id: "rotation.list.scheduled",
                defaultMessage: "Scheduled",
              })}
            </Badge>
          ) : (
            <Badge tone="neutral">
              {intl.formatMessage({
                id: "rotation.list.notConfigured",
                defaultMessage: "Not configured",
              })}
            </Badge>
          ),
      },
    ],
    [intl],
  );

  return (
    <>
      <PageHeader
        title={intl.formatMessage({
          id: "rotation.page.title",
          defaultMessage: "Credential rotation",
        })}
        subtitle={intl.formatMessage({
          id: "rotation.page.subtitle",
          defaultMessage:
            "Automatically change privileged credentials on a schedule or after each use, and issue short-lived database credentials — so secrets never sit around long enough to be stolen.",
        })}
      />

      {isLoading ? (
        <LoadingState />
      ) : error ? (
        <ErrorState
          error={error}
          onRetry={() => {
            targetsQ.refetch();
            policiesQ.refetch();
          }}
        />
      ) : rows.length === 0 ? (
        <EmptyState
          title={intl.formatMessage({
            id: "rotation.page.emptyTitle",
            defaultMessage: "No PAM targets yet",
          })}
          description={intl.formatMessage({
            id: "rotation.page.emptyBody",
            defaultMessage:
              "Register an SSH, PostgreSQL or MySQL target first, then come back here to put its credential on an automatic rotation schedule.",
          })}
        />
      ) : (
        <>
          <div className="stat-grid" style={{ marginBottom: 16 }}>
            <Stat
              label={intl.formatMessage({
                id: "rotation.page.stat.targets",
                defaultMessage: "PAM targets",
              })}
              value={stats.total}
            />
            <Stat
              label={intl.formatMessage({
                id: "rotation.page.stat.rotating",
                defaultMessage: "Auto-rotating",
              })}
              value={stats.rotating}
            />
            <Stat
              label={intl.formatMessage({
                id: "rotation.page.stat.dynamic",
                defaultMessage: "Issuing ephemeral creds",
              })}
              value={stats.dynamic}
            />
            <Stat
              label={intl.formatMessage({
                id: "rotation.page.stat.failing",
                defaultMessage: "Last rotation failed",
              })}
              value={
                stats.failing > 0 ? (
                  <span style={{ color: "var(--danger, #c0392b)" }}>
                    {stats.failing}
                  </span>
                ) : (
                  stats.failing
                )
              }
            />
          </div>

          {selected ? (
            <Card
              title={intl.formatMessage(
                {
                  id: "rotation.panel.title",
                  defaultMessage: "Rotation — {name}",
                },
                { name: selected.target.name },
              )}
              actions={
                <button
                  className="btn btn--ghost btn--sm"
                  onClick={() => setSelectedId(null)}
                >
                  {intl.formatMessage({
                    id: "rotation.panel.back",
                    defaultMessage: "← All targets",
                  })}
                </button>
              }
            >
              <RotationStatus
                key={selected.target.id}
                targetId={selected.target.id}
                targetName={selected.target.name}
                protocol={selected.target.protocol}
              />
            </Card>
          ) : (
            <Card
              title={intl.formatMessage({
                id: "rotation.list.title",
                defaultMessage: "Targets",
              })}
              actions={
                <HelpTooltip
                  align="right"
                  title={intl.formatMessage({
                    id: "rotation.list.help.title",
                    defaultMessage: "How rotation works",
                  })}
                >
                  {intl.formatMessage({
                    id: "rotation.list.help.body",
                    defaultMessage:
                      "Pick a target to set how often its credential rotates, rotate it on demand, or turn on short-lived database credentials. ShieldNet rotates SSH, PostgreSQL and MySQL targets.",
                  })}
                </HelpTooltip>
              }
            >
              <DataTable
                columns={columns}
                rows={rows}
                rowKey={(r) => r.target.id}
                onRowClick={(r) => setSelectedId(r.target.id)}
              />
            </Card>
          )}
        </>
      )}
    </>
  );
}
