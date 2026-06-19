import { useNavigate } from "@tanstack/react-router";
import { useIntl } from "react-intl";
import { PageHeader, Badge, StatusBadge, AsyncBoundary } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { useWorkflows, type Workflow } from "@/api/workflows";
import { formatRelative, titleCase } from "@/lib/format";
import { RowActivate } from "@/routes/lane/RowActivate";

// Workflows: the no-code JML builder's catalog. Each row is a versioned
// Joiner/Mover/Leaver automation in the same draft → simulate → publish
// lifecycle as access policies — nothing the engine runs until it is published,
// and publishing is gated on a successful dry-run.
export function Workflows() {
  const navigate = useNavigate();
  const intl = useIntl();
  const { data, isLoading, error, refetch } = useWorkflows();

  const columns: Column<Workflow>[] = [
    {
      header: intl.formatMessage({ id: "jml.col.name", defaultMessage: "Name" }),
      cell: (w) => (
        <RowActivate
          label={intl.formatMessage(
            { id: "jml.workflow.open", defaultMessage: "Open workflow {name}" },
            { name: w.name },
          )}
          onActivate={() =>
            navigate({
              to: "/workflows/$workflowId",
              params: { workflowId: w.id },
            })
          }
        >
          <b>{w.name}</b>
          <span className="muted" style={{ fontSize: 12 }}>
            {titleCase(w.definition.kind)} ·{" "}
            {intl.formatMessage(
              {
                id: "jml.stepCount",
                defaultMessage: "{count, plural, one {# step} other {# steps}}",
              },
              { count: w.definition.steps.length },
            )}
            {w.definition.conditions?.length
              ? ` · ${intl.formatMessage(
                  {
                    id: "jml.conditionCount",
                    defaultMessage:
                      "{count, plural, one {# condition} other {# conditions}}",
                  },
                  { count: w.definition.conditions.length },
                )}`
              : ""}
          </span>
        </RowActivate>
      ),
    },
    {
      header: intl.formatMessage({ id: "jml.col.lane", defaultMessage: "Lane" }),
      width: 110,
      cell: (w) => (
        <Badge tone={w.definition.kind === "leaver" ? "danger" : "info"}>
          {titleCase(w.definition.kind)}
        </Badge>
      ),
    },
    {
      header: intl.formatMessage({
        id: "jml.col.trigger",
        defaultMessage: "Trigger",
      }),
      width: 150,
      cell: (w) => <span className="muted">{titleCase(w.trigger)}</span>,
    },
    {
      header: intl.formatMessage({
        id: "jml.col.state",
        defaultMessage: "State",
      }),
      width: 170,
      cell: (w) => (
        <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
          <StatusBadge status={w.state} />
          {w.state === "draft" &&
            (!w.draft_simulation || w.draft_simulation.status === "failed") && (
              <Badge tone="warn">
                {intl.formatMessage({
                  id: "jml.untested",
                  defaultMessage: "Untested",
                })}
              </Badge>
            )}
        </span>
      ),
    },
    {
      header: intl.formatMessage({
        id: "jml.col.updated",
        defaultMessage: "Updated",
      }),
      width: 130,
      cell: (w) => (
        <span className="muted">{formatRelative(w.updated_at)}</span>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title={intl.formatMessage({
          id: "nav.workflows",
          defaultMessage: "JML workflows",
        })}
        subtitle={intl.formatMessage({
          id: "jml.list.subtitle",
          defaultMessage:
            "Automate joiner, mover and leaver tasks. Nothing runs until a draft is simulated for a sample identity and published.",
        })}
        actions={
          <button
            className="btn btn--primary"
            onClick={() => navigate({ to: "/workflows/new" })}
          >
            {intl.formatMessage({
              id: "jml.new",
              defaultMessage: "New workflow",
            })}
          </button>
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
              id: "jml.empty.title",
              defaultMessage: "No workflows yet",
            })}
            description={intl.formatMessage({
              id: "jml.empty.desc",
              defaultMessage:
                "Build your first joiner, mover or leaver automation. Drafts are safe — nothing happens until you simulate and publish.",
            })}
            action={
              <button
                className="btn btn--primary btn--sm"
                onClick={() => navigate({ to: "/workflows/new" })}
              >
                {intl.formatMessage({
                  id: "jml.new",
                  defaultMessage: "New workflow",
                })}
              </button>
            }
          />
        }
      >
        {(rows) => (
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(w) => w.id}
            onRowClick={(w) =>
              navigate({
                to: "/workflows/$workflowId",
                params: { workflowId: w.id },
              })
            }
          />
        )}
      </AsyncBoundary>
    </>
  );
}
