import { useMemo, useState } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import { useNavigate } from "@tanstack/react-router";
import {
  PageHeader,
  Card,
  Badge,
  StatusBadge,
  AsyncBoundary,
} from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { HelpTooltip } from "@/components/HelpTooltip";
import { useToast } from "@/components/Toast";
import { useMyPermissions } from "@/api/access";
import { formatDateTime, formatRelative } from "@/lib/format";
import {
  useRecordingSearch,
  useRetentionPolicy,
  useSetRetentionPolicy,
  type RecordingSummary,
  type RecordingSearchParams,
} from "./replay/api";
import { formatDurationMs } from "./replay/util";

const PAGE_SIZE = 20;
const PAM_ADMIN_PERMISSION = "pam.session.admin";

// SessionReplay is the search-across-sessions forensic surface: full-text query
// over the commands an operator executed, plus faceted filters (operator,
// protocol, target, time range), feeding into the in-browser replay player. It
// reads the light indexed projection so search stays cheap at 5k-tenant scale;
// the heavy transcript bytes are only fetched when a recording is opened.
export function SessionReplay() {
  const intl = useIntl();
  const navigate = useNavigate();

  // Draft filters (the form) vs. applied filters (what we actually query). The
  // split keeps typing from firing a request per keystroke; the query runs on
  // submit, on filter change, and on pagination.
  const [draft, setDraft] = useState({
    q: "",
    operator: "",
    protocol: "",
    target: "",
    from: "",
    to: "",
    includePruned: false,
  });
  const [applied, setApplied] = useState(draft);
  const [page, setPage] = useState(0);

  const params: RecordingSearchParams = useMemo(
    () => ({
      q: applied.q || undefined,
      operator: applied.operator || undefined,
      protocol: applied.protocol || undefined,
      target: applied.target || undefined,
      from: applied.from ? new Date(applied.from).toISOString() : undefined,
      to: applied.to ? new Date(applied.to).toISOString() : undefined,
      include_pruned: applied.includePruned || undefined,
      limit: PAGE_SIZE,
      offset: page * PAGE_SIZE,
    }),
    [applied, page],
  );

  const { data, isLoading, error, refetch } = useRecordingSearch(params, {
    placeholderData: (prev) => prev,
  });

  const apply = () => {
    setPage(0);
    setApplied(draft);
  };
  const reset = () => {
    const cleared = {
      q: "",
      operator: "",
      protocol: "",
      target: "",
      from: "",
      to: "",
      includePruned: false,
    };
    setDraft(cleared);
    setApplied(cleared);
    setPage(0);
  };

  const columns: Column<RecordingSummary>[] = [
    {
      header: intl.formatMessage({ id: "recordings.1", defaultMessage: "Operator" }),
      cell: (r) => (
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <b>{r.operator || "—"}</b>
          <span className="muted" style={{ fontSize: 12 }}>
            <Badge tone="info">{r.protocol || "—"}</Badge>
            {r.client_addr ? ` · ${r.client_addr}` : ""}
          </span>
        </div>
      ),
    },
    {
      header: intl.formatMessage({ id: "recordings.2", defaultMessage: "Target" }),
      cell: (r) => r.target_name || "—",
    },
    {
      header: intl.formatMessage({ id: "recordings.3", defaultMessage: "Started" }),
      cell: (r) => (
        <span className="muted" title={formatDateTime(r.started_at)}>
          {formatRelative(r.started_at)}
        </span>
      ),
    },
    {
      header: intl.formatMessage({ id: "recordings.4", defaultMessage: "Duration" }),
      cell: (r) => formatDurationMs(r.duration_ms),
    },
    {
      header: intl.formatMessage({ id: "recordings.5", defaultMessage: "Commands" }),
      cell: (r) => (
        <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
          {r.command_count}
          {r.deny_count > 0 && (
            <Badge tone="danger">
              <FormattedMessage id="recordings.19"
                defaultMessage="{n} denied"
                values={{ n: r.deny_count }}
              />
            </Badge>
          )}
        </span>
      ),
    },
    {
      header: intl.formatMessage({ id: "recordings.6", defaultMessage: "Integrity" }),
      cell: (r) =>
        r.blob_pruned ? (
          <Badge tone="neutral">
            <FormattedMessage id="recordings.20" defaultMessage="Tiered out" />
          </Badge>
        ) : !r.sha256 ? (
          <Badge tone="neutral">
            <FormattedMessage id="recordings.21" defaultMessage="Not attested" />
          </Badge>
        ) : r.sha256_verified ? (
          <Badge tone="ok" dot>
            <FormattedMessage id="recordings.22" defaultMessage="Verified" />
          </Badge>
        ) : (
          <Badge tone="warn">
            <FormattedMessage id="recordings.23" defaultMessage="Unverified" />
          </Badge>
        ),
    },
    {
      header: intl.formatMessage({ id: "recordings.7", defaultMessage: "State" }),
      cell: (r) => <StatusBadge status={r.state} />,
    },
  ];

  const total = data?.total ?? 0;
  const hasNext = (page + 1) * PAGE_SIZE < total;

  return (
    <>
      <PageHeader
        title={intl.formatMessage({ id: "recordings.8", defaultMessage: "Session recordings" })}
        subtitle={intl.formatMessage({ id: "recordings.9",
          defaultMessage:
            "Search every recorded privileged session by the commands that were run, then open the replay player to review it.",
        })}
        actions={<RetentionPolicyControl />}
      />

      <Card>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            apply();
          }}
          style={{ display: "flex", flexDirection: "column", gap: 12 }}
        >
          <label className="field">
            <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
              <FormattedMessage id="recordings.24" defaultMessage="Search commands" />
              <HelpTooltip>
                <FormattedMessage id="recordings.25" defaultMessage="Full-text search over the commands and queries executed during each session (e.g. a table name, a sudo command, a hostname). Powered by Postgres full-text search." />
              </HelpTooltip>
            </span>
            <input
              type="search"
              value={draft.q}
              placeholder={intl.formatMessage({ id: "recordings.10",
                defaultMessage: "e.g. DROP TABLE, sudo, SELECT * FROM users",
              })}
              onChange={(e) => setDraft({ ...draft, q: e.target.value })}
            />
          </label>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
              gap: 12,
            }}
          >
            <label className="field">
              <span>
                <FormattedMessage id="recordings.26" defaultMessage="Operator" />
              </span>
              <input
                value={draft.operator}
                onChange={(e) =>
                  setDraft({ ...draft, operator: e.target.value })
                }
              />
            </label>
            <label className="field">
              <span>
                <FormattedMessage id="recordings.27" defaultMessage="Protocol" />
              </span>
              <select
                value={draft.protocol}
                onChange={(e) =>
                  setDraft({ ...draft, protocol: e.target.value })
                }
              >
                <option value="">
                  {intl.formatMessage({ id: "recordings.11", defaultMessage: "Any" })}
                </option>
                <option value="ssh">SSH</option>
                <option value="postgres">PostgreSQL</option>
                <option value="mysql">MySQL</option>
              </select>
            </label>
            <label className="field">
              <span>
                <FormattedMessage id="recordings.28" defaultMessage="Target" />
              </span>
              <input
                value={draft.target}
                onChange={(e) => setDraft({ ...draft, target: e.target.value })}
              />
            </label>
            <label className="field">
              <span>
                <FormattedMessage id="recordings.29" defaultMessage="From" />
              </span>
              <input
                type="datetime-local"
                value={draft.from}
                onChange={(e) => setDraft({ ...draft, from: e.target.value })}
              />
            </label>
            <label className="field">
              <span>
                <FormattedMessage id="recordings.30" defaultMessage="To" />
              </span>
              <input
                type="datetime-local"
                value={draft.to}
                onChange={(e) => setDraft({ ...draft, to: e.target.value })}
              />
            </label>
          </div>

          <div
            style={{
              display: "flex",
              gap: 12,
              alignItems: "center",
              flexWrap: "wrap",
            }}
          >
            <label
              className="field"
              style={{ flexDirection: "row", alignItems: "center", gap: 8 }}
            >
              <input
                type="checkbox"
                checked={draft.includePruned}
                style={{ width: "auto" }}
                onChange={(e) =>
                  setDraft({ ...draft, includePruned: e.target.checked })
                }
              />
              <span>
                <FormattedMessage id="recordings.31" defaultMessage="Include tiered-out recordings" />
              </span>
            </label>
            <div style={{ flex: 1 }} />
            <button type="button" className="btn btn--ghost" onClick={reset}>
              <FormattedMessage id="recordings.32" defaultMessage="Reset" />
            </button>
            <button type="submit" className="btn btn--primary">
              <FormattedMessage id="recordings.33" defaultMessage="Search" />
            </button>
          </div>
        </form>
      </Card>

      <AsyncBoundary
        isLoading={isLoading}
        error={error}
        data={data}
        onRetry={refetch}
        isEmpty={(d) => d.recordings.length === 0}
        empty={
          <EmptyState
            title={intl.formatMessage({ id: "recordings.12",
              defaultMessage: "No recordings match",
            })}
            description={intl.formatMessage({ id: "recordings.13",
              defaultMessage:
                "Try a broader search, clear the filters, or widen the time range. Recordings appear here as privileged sessions are captured and indexed.",
            })}
          />
        }
      >
        {(d) => (
          <>
            <DataTable
              columns={columns}
              rows={d.recordings}
              rowKey={(r) => r.id}
              onRowClick={(r) =>
                navigate({
                  to: "/pam/recordings/$recordingId",
                  params: { recordingId: r.session_id },
                })
              }
            />
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginTop: 12,
              }}
            >
              <span className="muted" style={{ fontSize: 13 }}>
                <FormattedMessage id="recordings.34"
                  defaultMessage="{from}–{to} of {total}"
                  values={{
                    from: total === 0 ? 0 : page * PAGE_SIZE + 1,
                    to: page * PAGE_SIZE + d.recordings.length,
                    total,
                  }}
                />
              </span>
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  className="btn btn--ghost btn--sm"
                  disabled={page === 0}
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                >
                  <FormattedMessage id="recordings.35" defaultMessage="Previous" />
                </button>
                <button
                  className="btn btn--ghost btn--sm"
                  disabled={!hasNext}
                  onClick={() => setPage((p) => p + 1)}
                >
                  <FormattedMessage id="recordings.36" defaultMessage="Next" />
                </button>
              </div>
            </div>
          </>
        )}
      </AsyncBoundary>
    </>
  );
}

// RetentionPolicyControl reads and (for admins) edits the per-workspace
// recording retention window: how many days a recording's heavy blob is kept
// before the cost-aware sweep tiers it out. The audit record and searchable
// metadata always survive — only the replayable bytes are aged out — so the
// copy reassures a non-expert admin that forensic history is not lost.
function RetentionPolicyControl() {
  const intl = useIntl();
  const toast = useToast();
  const { data, isLoading } = useRetentionPolicy();
  const { data: myPerms } = useMyPermissions();
  const setMut = useSetRetentionPolicy();
  const [editing, setEditing] = useState(false);
  const [days, setDays] = useState<string>("");

  // undefined = still loading or RBAC tier not mounted → assume allowed; the
  // server still authorizes the PUT (pam.session.admin), so this only avoids a
  // false-negative disabled control.
  const canEdit =
    myPerms === undefined
      ? true
      : myPerms.permissions.includes(PAM_ADMIN_PERMISSION);

  if (isLoading || !data) {
    return (
      <Badge tone="neutral">
        <FormattedMessage id="recordings.37" defaultMessage="Retention…" />
      </Badge>
    );
  }

  const label =
    data.retention_days === 0
      ? intl.formatMessage({ id: "recordings.14", defaultMessage: "Retention: indefinite" })
      : intl.formatMessage(
          { id: "recordings.retentionDays", defaultMessage: "Retention: {days} days" },
          { days: data.retention_days },
        );

  if (!editing) {
    return (
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <Badge tone={data.is_default ? "neutral" : "info"}>{label}</Badge>
        <HelpTooltip align="right">
          <FormattedMessage id="recordings.38" defaultMessage="How long a recording's replayable bytes are kept before being tiered out to control storage cost. The searchable metadata, command timeline, and tamper-evident audit record are always preserved. Set to 0 to retain recordings indefinitely." />
        </HelpTooltip>
        {canEdit && (
          <button
            className="btn btn--ghost btn--sm"
            onClick={() => {
              setDays(String(data.retention_days));
              setEditing(true);
            }}
          >
            <FormattedMessage id="recordings.39" defaultMessage="Edit" />
          </button>
        )}
      </div>
    );
  }

  const save = async () => {
    const n = Number(days);
    if (!Number.isInteger(n) || n < 0) {
      toast.error(
        intl.formatMessage({ id: "recordings.15", defaultMessage: "Enter a whole number of days (0 = indefinite)." }),
      );
      return;
    }
    try {
      await setMut.mutateAsync(n);
      toast.success(intl.formatMessage({ id: "recordings.16", defaultMessage: "Retention policy updated" }));
      setEditing(false);
    } catch (err) {
      toast.error(
        intl.formatMessage({ id: "recordings.17", defaultMessage: "Could not update retention policy" }),
        err instanceof Error ? err.message : undefined,
      );
    }
  };

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <input
        type="number"
        min={0}
        value={days}
        onChange={(e) => setDays(e.target.value)}
        style={{ width: 90 }}
        aria-label={intl.formatMessage({ id: "recordings.18",
          defaultMessage: "Retention days (0 = indefinite)",
        })}
      />
      <button
        className="btn btn--primary btn--sm"
        disabled={setMut.isPending}
        onClick={save}
      >
        <FormattedMessage id="recordings.40" defaultMessage="Save" />
      </button>
      <button
        className="btn btn--ghost btn--sm"
        onClick={() => setEditing(false)}
      >
        <FormattedMessage id="recordings.41" defaultMessage="Cancel" />
      </button>
    </div>
  );
}
