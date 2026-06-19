import { useIntl } from "react-intl";
import { useLaneA5Scope } from "./lane-a5";
import {
  PageHeader,
  Card,
  Badge,
  Spinner,
  AsyncBoundary,
} from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { useToast } from "@/components/Toast";
import {
  useOrphans,
  useSetOrphanDisposition,
  type OrphanAccount,
  ApiError,
} from "@/api/access";
import { formatRelative, shortId } from "@/lib/format";

function dispositionTone(d: string) {
  switch (d) {
    case "pending":
      return "warn" as const;
    case "ignore":
      return "neutral" as const;
    case "disable":
      return "danger" as const;
    default:
      return "info" as const;
  }
}

function dispositionLabel(d: string, intl: ReturnType<typeof useIntl>): string {
  switch (d) {
    case "pending":
      return intl.formatMessage({
        id: "directory.disposition.pending",
        defaultMessage: "Needs review",
      });
    case "ignore":
      return intl.formatMessage({
        id: "directory.disposition.ignore",
        defaultMessage: "Ignored",
      });
    case "disable":
      return intl.formatMessage({
        id: "directory.disposition.disable",
        defaultMessage: "Disabled",
      });
    default:
      return d;
  }
}

// Per-row disposition controls. Lives in its own component so the
// useSetOrphanDisposition hook is scoped to a single orphan id.
function OrphanActions({ orphan }: { orphan: OrphanAccount }) {
  const intl = useIntl();
  const toast = useToast();
  const mut = useSetOrphanDisposition(orphan.id);

  const set = async (disposition: string) => {
    try {
      await mut.mutateAsync(disposition);
      toast.success(
        disposition === "disable"
          ? intl.formatMessage({
              id: "directory.toast.disabled",
              defaultMessage: "Account disabled at the connector",
            })
          : intl.formatMessage({
              id: "directory.toast.ignored",
              defaultMessage: "Marked to ignore",
            }),
      );
    } catch (err) {
      toast.error(
        intl.formatMessage({
          id: "directory.toast.error",
          defaultMessage: "Could not update disposition",
        }),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  if (mut.isPending) return <Spinner />;

  return (
    <div style={{ display: "inline-flex", gap: 6 }}>
      <button
        className="btn btn--sm btn--ghost"
        disabled={orphan.disposition === "ignore"}
        onClick={() => set("ignore")}
      >
        {intl.formatMessage({
          id: "directory.action.ignore",
          defaultMessage: "Ignore",
        })}
      </button>
      <button
        className="btn btn--sm btn--danger"
        disabled={orphan.disposition === "disable"}
        onClick={() => set("disable")}
      >
        {intl.formatMessage({
          id: "directory.action.disable",
          defaultMessage: "Disable",
        })}
      </button>
    </div>
  );
}

export function Directory() {
  useLaneA5Scope();
  const intl = useIntl();
  const { data, isLoading, error, refetch } = useOrphans();

  const columns: Column<OrphanAccount>[] = [
    {
      header: intl.formatMessage({
        id: "directory.col.account",
        defaultMessage: "Account",
      }),
      cell: (o) => (
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <b>{o.display_name || o.external_user_id}</b>
          <span className="muted" style={{ fontSize: 12 }}>
            <code>{o.external_user_id}</code>
          </span>
        </div>
      ),
    },
    {
      header: intl.formatMessage({
        id: "directory.col.connector",
        defaultMessage: "Connector",
      }),
      width: 140,
      cell: (o) => <code>{shortId(o.connector_id)}</code>,
    },
    {
      header: intl.formatMessage({
        id: "directory.col.disposition",
        defaultMessage: "Disposition",
      }),
      width: 130,
      cell: (o) => (
        <Badge tone={dispositionTone(o.disposition)}>
          {dispositionLabel(o.disposition, intl)}
        </Badge>
      ),
    },
    {
      header: intl.formatMessage({
        id: "directory.col.found",
        defaultMessage: "Found",
      }),
      width: 110,
      cell: (o) => <span className="muted">{formatRelative(o.created_at)}</span>,
    },
    {
      header: intl.formatMessage({
        id: "directory.col.action",
        defaultMessage: "Action",
      }),
      width: 180,
      cell: (o) => <OrphanActions orphan={o} />,
    },
  ];

  return (
    <>
      <PageHeader
        title={intl.formatMessage({
          id: "directory.title",
          defaultMessage: "Directory — orphan accounts",
        })}
        subtitle={intl.formatMessage({
          id: "directory.subtitle",
          defaultMessage:
            "Upstream connector accounts with no matching live grant. These are leaver-cleanup candidates: ignore known service accounts, or disable to deprovision at the connector.",
        })}
      />
      <Card
        title={intl.formatMessage({
          id: "directory.card.title",
          defaultMessage: "Orphans",
        })}
        subtitle={intl.formatMessage({
          id: "directory.card.subtitle",
          defaultMessage: "Detected by the reconciler against connected providers.",
        })}
      >
        <AsyncBoundary
          isLoading={isLoading}
          error={error}
          data={data}
          onRetry={refetch}
          isEmpty={(rows) => rows.length === 0}
          empty={
            <EmptyState
              title={intl.formatMessage({
                id: "directory.empty.title",
                defaultMessage: "No orphan accounts",
              })}
              description={intl.formatMessage({
                id: "directory.empty.body",
                defaultMessage:
                  "Every connected account maps to a live grant. Nothing to clean up.",
              })}
            />
          }
        >
          {(rows) => (
            <DataTable columns={columns} rows={rows} rowKey={(o) => o.id} />
          )}
        </AsyncBoundary>
      </Card>
    </>
  );
}
