import { useNavigate } from "@tanstack/react-router";
import { useIntl } from "react-intl";
import { useLaneA5Scope } from "./lane-a5";
import { PageHeader, Badge, StatusBadge, AsyncBoundary } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { usePolicies, type Policy } from "@/api/access";
import { formatRelative } from "@/lib/format";

export function Policies() {
  useLaneA5Scope();
  const intl = useIntl();
  const navigate = useNavigate();
  const { data, isLoading, error, refetch } = usePolicies();

  const newLabel = intl.formatMessage({
    id: "policies.action.new",
    defaultMessage: "New access policy",
  });

  const columns: Column<Policy>[] = [
    {
      header: intl.formatMessage({
        id: "policies.col.name",
        defaultMessage: "Name",
      }),
      cell: (p) => (
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <b>{p.name}</b>
          <span className="muted" style={{ fontSize: 12 }}>
            {intl.formatMessage(
              {
                id: "policies.row.summary",
                defaultMessage:
                  "{action} · {subjects, plural, one {# subject} other {# subjects}} → {resources, plural, one {# resource} other {# resources}}",
              },
              {
                action:
                  p.definition.action === "deny"
                    ? intl.formatMessage({
                        id: "policies.decision.deny",
                        defaultMessage: "Deny",
                      })
                    : intl.formatMessage({
                        id: "policies.decision.grant",
                        defaultMessage: "Grant",
                      }),
                subjects: p.definition.subjects.length,
                resources: p.definition.resources.length,
              },
            )}
            {p.definition.role
              ? intl.formatMessage(
                  {
                    id: "policies.row.role",
                    defaultMessage: " · role {role}",
                  },
                  { role: p.definition.role },
                )
              : ""}
          </span>
        </div>
      ),
    },
    {
      header: intl.formatMessage({
        id: "policies.col.decision",
        defaultMessage: "Decision",
      }),
      width: 110,
      cell: (p) => (
        <Badge tone={p.definition.action === "deny" ? "danger" : "ok"}>
          {p.definition.action === "deny"
            ? intl.formatMessage({
                id: "policies.decision.deny",
                defaultMessage: "Deny",
              })
            : intl.formatMessage({
                id: "policies.decision.grant",
                defaultMessage: "Grant",
              })}
        </Badge>
      ),
    },
    {
      header: intl.formatMessage({
        id: "policies.col.state",
        defaultMessage: "State",
      }),
      width: 170,
      cell: (p) => (
        <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
          <StatusBadge status={p.state} />
          {p.state === "draft" && !p.draft_impact && (
            <Badge tone="warn">
              {intl.formatMessage({
                id: "policies.badge.untested",
                defaultMessage: "Untested",
              })}
            </Badge>
          )}
        </span>
      ),
    },
    {
      header: intl.formatMessage({
        id: "policies.col.updated",
        defaultMessage: "Updated",
      }),
      width: 130,
      cell: (p) => <span className="muted">{formatRelative(p.updated_at)}</span>,
    },
  ];

  return (
    <>
      <PageHeader
        title={intl.formatMessage({
          id: "policies.title",
          defaultMessage: "Access policies",
        })}
        subtitle={intl.formatMessage({
          id: "policies.subtitle",
          defaultMessage:
            "Who and which groups can reach which systems. Nothing is enforced until a draft is tested and promoted.",
        })}
        actions={
          <button
            className="btn btn--primary"
            onClick={() => navigate({ to: "/policies/new" })}
          >
            {newLabel}
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
            title={intl.formatMessage({
              id: "policies.empty.title",
              defaultMessage: "No access policies yet",
            })}
            description={intl.formatMessage({
              id: "policies.empty.body",
              defaultMessage:
                "Create your first who → system rule. Drafts are safe — nothing reaches the data plane until you simulate and promote.",
            })}
            action={
              <button
                className="btn btn--primary btn--sm"
                onClick={() => navigate({ to: "/policies/new" })}
              >
                {newLabel}
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
