import { useMemo } from "react";
import { Link } from "@tanstack/react-router";
import { PageHeader, Card, Stat, Badge, StatusBadge } from "@/components/ui";
import { EmptyState } from "@/components/EmptyState";
import {
  usePolicies,
  useAccessRequests,
  useOrphans,
  type Policy,
} from "@/api/access";
import { formatRelative } from "@/lib/format";

// The open-request states an operator still needs to action. Anything past
// these (provisioned/denied/cancelled) is terminal and isn't "pending work".
const OPEN_REQUEST_STATES = new Set(["requested", "approved"]);

export function Dashboard() {
  const policies = usePolicies();
  const requests = useAccessRequests();
  const orphans = useOrphans();

  const counts = useMemo(() => {
    const rows = policies.data ?? [];
    return {
      total: rows.length,
      drafts: rows.filter((p) => p.state === "draft").length,
      active: rows.filter((p) => p.state === "active").length,
      // Drafts that have never been simulated since their last edit can't be
      // promoted — surface them so the operator knows what's blocking rollout.
      untested: rows.filter((p) => p.state === "draft" && !p.draft_impact)
        .length,
    };
  }, [policies.data]);

  const openRequests = (requests.data ?? []).filter((r) =>
    OPEN_REQUEST_STATES.has(r.state),
  );
  const pendingOrphans = (orphans.data ?? []).filter(
    (o) => o.disposition === "pending",
  );

  const recentPolicies: Policy[] = useMemo(
    () =>
      [...(policies.data ?? [])]
        .sort((a, b) => b.updated_at.localeCompare(a.updated_at))
        .slice(0, 6),
    [policies.data],
  );

  return (
    <>
      <PageHeader
        title="Dashboard"
        subtitle="Who can reach what — and what still needs testing before rollout."
        actions={
          <Link className="btn btn--primary" to="/policies/new">
            New access policy
          </Link>
        }
      />

      <div className="grid grid--stats">
        <Stat label="Access policies" value={counts.total} />
        <Stat
          label="Active (live)"
          value={counts.active}
          delta={<span className="muted">enforced now</span>}
        />
        <Stat
          label="Drafts"
          value={counts.drafts}
          delta={
            counts.untested > 0 ? (
              <Badge tone="warn">{counts.untested} need testing</Badge>
            ) : (
              <span className="muted">all simulated</span>
            )
          }
        />
        <Stat label="Open access requests" value={openRequests.length} />
      </div>

      <div className="grid grid--2" style={{ marginTop: 16 }}>
        <Card
          title="Recently edited policies"
          subtitle="Drafts must be simulated since their last edit before they can go live."
          actions={
            <Link className="btn btn--sm" to="/policies">
              View all
            </Link>
          }
        >
          {recentPolicies.length === 0 ? (
            <EmptyState
              title="No access policies yet"
              description="Create your first who → system rule. Nothing is enforced until you test and promote it."
              action={
                <Link className="btn btn--primary btn--sm" to="/policies/new">
                  New access policy
                </Link>
              }
            />
          ) : (
            <ul className="list">
              {recentPolicies.map((p) => (
                <li key={p.id}>
                  <Link to="/policies/$policyId" params={{ policyId: p.id }}>
                    <div className="list__main">
                      <b>{p.name}</b>
                      <span className="muted">
                        {p.definition.action} · {p.definition.subjects.length}{" "}
                        subject(s) → {p.definition.resources.length} resource(s)
                      </span>
                    </div>
                    <div className="list__meta">
                      {p.state === "draft" && !p.draft_impact && (
                        <Badge tone="warn">Untested</Badge>
                      )}
                      <StatusBadge status={p.state} />
                      <span className="muted">
                        {formatRelative(p.updated_at)}
                      </span>
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card
          title="Needs attention"
          subtitle="Lifecycle items waiting on a decision."
        >
          <ul className="list">
            <li>
              <Link to="/requests">
                <div className="list__main">
                  <b>Open access requests</b>
                  <span className="muted">
                    Joiner / mover provisioning awaiting approval
                  </span>
                </div>
                <div className="list__meta">
                  <Badge tone={openRequests.length ? "warn" : "neutral"}>
                    {openRequests.length}
                  </Badge>
                </div>
              </Link>
            </li>
            <li>
              <Link to="/directory">
                <div className="list__main">
                  <b>Orphan accounts</b>
                  <span className="muted">
                    Upstream identities with no active grant (leaver cleanup)
                  </span>
                </div>
                <div className="list__meta">
                  <Badge tone={pendingOrphans.length ? "warn" : "neutral"}>
                    {pendingOrphans.length}
                  </Badge>
                </div>
              </Link>
            </li>
            <li>
              <Link to="/policies">
                <div className="list__main">
                  <b>Untested drafts</b>
                  <span className="muted">
                    Draft policies that must be simulated before rollout
                  </span>
                </div>
                <div className="list__meta">
                  <Badge tone={counts.untested ? "warn" : "neutral"}>
                    {counts.untested}
                  </Badge>
                </div>
              </Link>
            </li>
          </ul>
        </Card>
      </div>
    </>
  );
}
