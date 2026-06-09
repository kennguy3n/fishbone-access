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

// Per-row disposition controls. Lives in its own component so the
// useSetOrphanDisposition hook is scoped to a single orphan id.
function OrphanActions({ orphan }: { orphan: OrphanAccount }) {
  const toast = useToast();
  const mut = useSetOrphanDisposition(orphan.id);

  const set = async (disposition: string) => {
    try {
      await mut.mutateAsync(disposition);
      toast.success(
        disposition === "disable"
          ? "Account disabled at the connector"
          : "Marked to ignore",
      );
    } catch (err) {
      toast.error(
        "Could not update disposition",
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
        Ignore
      </button>
      <button
        className="btn btn--sm btn--danger"
        disabled={orphan.disposition === "disable"}
        onClick={() => set("disable")}
      >
        Disable
      </button>
    </div>
  );
}

export function Directory() {
  const { data, isLoading, error, refetch } = useOrphans();

  const columns: Column<OrphanAccount>[] = [
    {
      header: "Account",
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
      header: "Connector",
      width: 140,
      cell: (o) => <code>{shortId(o.connector_id)}</code>,
    },
    {
      header: "Disposition",
      width: 120,
      cell: (o) => (
        <Badge tone={dispositionTone(o.disposition)}>{o.disposition}</Badge>
      ),
    },
    {
      header: "Found",
      width: 110,
      cell: (o) => <span className="muted">{formatRelative(o.created_at)}</span>,
    },
    {
      header: "Action",
      width: 180,
      cell: (o) => <OrphanActions orphan={o} />,
    },
  ];

  return (
    <>
      <PageHeader
        title="Directory — orphan accounts"
        subtitle="Upstream connector accounts with no matching live grant. These are leaver-cleanup candidates: ignore known service accounts, or disable to deprovision at the connector."
      />
      <Card
        title="Orphans"
        subtitle="Detected by the reconciler against connected providers."
      >
        <AsyncBoundary
          isLoading={isLoading}
          error={error}
          data={data}
          onRetry={refetch}
          isEmpty={(rows) => rows.length === 0}
          empty={
            <EmptyState
              title="No orphan accounts"
              description="Every connected account maps to a live grant. Nothing to clean up."
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
