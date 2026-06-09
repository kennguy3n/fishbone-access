import { useNavigate } from "@tanstack/react-router";
import { PageHeader, Badge, StatusBadge, AsyncBoundary } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { usePolicies, type Policy } from "@/api/access";
import { formatRelative } from "@/lib/format";

export function Policies() {
  const navigate = useNavigate();
  const { data, isLoading, error, refetch } = usePolicies();

  const columns: Column<Policy>[] = [
    {
      header: "Name",
      cell: (p) => (
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <b>{p.name}</b>
          <span className="muted" style={{ fontSize: 12 }}>
            {p.definition.action} · {p.definition.subjects.length} subject(s) →{" "}
            {p.definition.resources.length} resource(s)
            {p.definition.role ? ` · role ${p.definition.role}` : ""}
          </span>
        </div>
      ),
    },
    {
      header: "Decision",
      width: 110,
      cell: (p) => (
        <Badge tone={p.definition.action === "deny" ? "danger" : "ok"}>
          {p.definition.action === "deny" ? "Deny" : "Grant"}
        </Badge>
      ),
    },
    {
      header: "State",
      width: 170,
      cell: (p) => (
        <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
          <StatusBadge status={p.state} />
          {p.state === "draft" && !p.draft_impact && (
            <Badge tone="warn">Untested</Badge>
          )}
        </span>
      ),
    },
    {
      header: "Updated",
      width: 130,
      cell: (p) => <span className="muted">{formatRelative(p.updated_at)}</span>,
    },
  ];

  return (
    <>
      <PageHeader
        title="Access policies"
        subtitle="Who and which groups can reach which systems. Nothing is enforced until a draft is tested and promoted."
        actions={
          <button
            className="btn btn--primary"
            onClick={() => navigate({ to: "/policies/new" })}
          >
            New access policy
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
            illustration={undefined}
            title="No access policies yet"
            description="Create your first who → system rule. Drafts are safe — nothing reaches the data plane until you simulate and promote."
            action={
              <button
                className="btn btn--primary btn--sm"
                onClick={() => navigate({ to: "/policies/new" })}
              >
                New access policy
              </button>
            }
          />
        }
      >
        {(rows) => (
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(p) => p.id}
            onRowClick={(p) =>
              navigate({ to: "/policies/$policyId", params: { policyId: p.id } })
            }
          />
        )}
      </AsyncBoundary>
    </>
  );
}
