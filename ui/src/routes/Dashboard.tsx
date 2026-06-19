import { useMemo } from "react";
import { Link } from "@tanstack/react-router";
import { useIntl } from "react-intl";
import { PageHeader, Card, Stat, Badge, StatusBadge } from "@/components/ui";
import { EmptyState, EmptyIllustration } from "@/components/EmptyState";
import { Icon } from "@/components/Icon";
import {
  usePolicies,
  useAccessRequests,
  useOrphans,
  useConnectors,
  useMe,
  type Policy,
} from "@/api/access";
import { formatRelative } from "@/lib/format";
import { useIsWorkspaceAdmin } from "@/lib/permissions";
import {
  useOnboardingProgress,
  type OnboardingProgress,
  type OnboardingUpdate,
} from "@/lib/onboarding-store";

// OnboardingNudge is the day-1 zero-state prompt. It only shows for workspace
// admins who haven't finished (or dismissed) the guided setup AND whose
// workspace still lacks a connected source or a policy — so once the workspace
// is genuinely set up, or for a plain operator, it never appears.
function OnboardingNudge() {
  const me = useMe();
  if (!me.data) return null;
  // key on tenant id so the progress store (keyed + lazily hydrated per tenant)
  // re-hydrates if the bound tenant ever changes, instead of outliving it.
  return (
    <OnboardingNudgeGate key={me.data.tenant_id} tenantId={me.data.tenant_id} />
  );
}

// Resolve admin status and dismissal *before* mounting the body that fires the
// workspace data queries, so a non-admin (or someone who already finished or
// dismissed the nudge) never pays for the connector/policy fetches.
function OnboardingNudgeGate({ tenantId }: { tenantId: string }) {
  const isAdmin = useIsWorkspaceAdmin();
  const [progress, update] = useOnboardingProgress(tenantId);
  if (!isAdmin || progress.finished || progress.nudgeDismissed) return null;
  return <OnboardingNudgeBody progress={progress} update={update} />;
}

function OnboardingNudgeBody({
  progress,
  update,
}: {
  progress: OnboardingProgress;
  update: OnboardingUpdate;
}) {
  const intl = useIntl();
  const connectors = useConnectors({});
  const policies = usePolicies();

  // Wait for both reads before deciding: otherwise an already-set-up workspace
  // would flash the "finish setup" banner for a frame (data undefined → looks
  // unconfigured) until the queries resolve and we hide it.
  if (connectors.isLoading || policies.isLoading) return null;
  const connected = (connectors.data ?? []).some((c) => c.connected);
  const hasPolicies = (policies.data?.length ?? 0) > 0;
  if (connected && hasPolicies) return null;

  const resuming =
    progress.completed.length > 0 || progress.lastStep !== "welcome";

  return (
    <div className="banner">
      <span className="banner__icon" aria-hidden>
        <Icon name="rocket" size={22} />
      </span>
      <div className="banner__body">
        <div className="banner__title">
          {resuming
            ? intl.formatMessage({
                id: "dashboard.nudge.title.resume",
                defaultMessage: "Pick up where you left off",
              })
            : intl.formatMessage({
                id: "dashboard.nudge.title.start",
                defaultMessage: "Welcome — let's get your workspace ready",
              })}
        </div>
        <div className="banner__sub">
          {intl.formatMessage({
            id: "dashboard.nudge.sub",
            defaultMessage:
              "A short, guided setup: connect where your team signs in, write your first access rule, and invite a teammate. It takes a few minutes, and your progress is saved as you go.",
          })}
        </div>
      </div>
      <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
        <Link className="btn btn--primary btn--sm" to="/onboarding">
          {resuming
            ? intl.formatMessage({
                id: "dashboard.nudge.resume",
                defaultMessage: "Resume setup",
              })
            : intl.formatMessage({
                id: "dashboard.nudge.start",
                defaultMessage: "Start setup",
              })}
        </Link>
        <button
          className="btn btn--ghost btn--sm"
          onClick={() => update({ nudgeDismissed: true })}
        >
          {intl.formatMessage({
            id: "dashboard.nudge.dismiss",
            defaultMessage: "Maybe later",
          })}
        </button>
      </div>
    </div>
  );
}

// The open-request states an operator still needs to action. Anything past
// these (provisioned/denied/cancelled) is terminal and isn't "pending work".
const OPEN_REQUEST_STATES = new Set(["requested", "approved"]);

export function Dashboard() {
  const intl = useIntl();
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

  const attentionTotal =
    openRequests.length + pendingOrphans.length + counts.untested;

  const recentPolicies: Policy[] = useMemo(
    () =>
      [...(policies.data ?? [])]
        .sort((a, b) => b.updated_at.localeCompare(a.updated_at))
        .slice(0, 6),
    [policies.data],
  );

  return (
    <>
      <OnboardingNudge />
      <PageHeader
        title={intl.formatMessage({
          id: "nav.dashboard",
          defaultMessage: "Dashboard",
        })}
        subtitle={intl.formatMessage({
          id: "dashboard.subtitle",
          defaultMessage:
            "Your starting point: what needs a decision today, and what you can act on right now.",
        })}
        actions={
          <Link className="btn btn--primary" to="/policies/new">
            {intl.formatMessage({
              id: "dashboard.newPolicy",
              defaultMessage: "New access policy",
            })}
          </Link>
        }
      />

      <div className="grid grid--stats">
        <Stat
          label={intl.formatMessage({
            id: "dashboard.stat.policies",
            defaultMessage: "Access policies",
          })}
          value={counts.total}
        />
        <Stat
          label={intl.formatMessage({
            id: "dashboard.stat.active",
            defaultMessage: "Live now",
          })}
          value={counts.active}
          delta={
            <span className="muted">
              {intl.formatMessage({
                id: "dashboard.stat.active.delta",
                defaultMessage: "enforced right now",
              })}
            </span>
          }
        />
        <Stat
          label={intl.formatMessage({
            id: "dashboard.stat.drafts",
            defaultMessage: "Drafts",
          })}
          value={counts.drafts}
          delta={
            counts.untested > 0 ? (
              <Badge tone="warn">
                {intl.formatMessage(
                  {
                    id: "dashboard.stat.drafts.needTesting",
                    defaultMessage:
                      "{count, plural, one {# needs testing} other {# need testing}}",
                  },
                  { count: counts.untested },
                )}
              </Badge>
            ) : (
              <span className="muted">
                {intl.formatMessage({
                  id: "dashboard.stat.drafts.allTested",
                  defaultMessage: "all tested",
                })}
              </span>
            )
          }
        />
        <Stat
          label={intl.formatMessage({
            id: "dashboard.stat.openRequests",
            defaultMessage: "Open access requests",
          })}
          value={openRequests.length}
        />
      </div>

      <div className="grid grid--2" style={{ marginTop: 16 }}>
        <Card
          title={intl.formatMessage({
            id: "dashboard.recent.title",
            defaultMessage: "Recently edited policies",
          })}
          subtitle={intl.formatMessage({
            id: "dashboard.recent.subtitle",
            defaultMessage:
              "A draft must be tested after its latest edit before it can go live.",
          })}
          actions={
            <Link className="btn btn--sm" to="/policies">
              {intl.formatMessage({
                id: "dashboard.viewAll",
                defaultMessage: "View all",
              })}
            </Link>
          }
        >
          {recentPolicies.length === 0 ? (
            <EmptyState
              illustration={<EmptyIllustration kind="policy" />}
              title={intl.formatMessage({
                id: "dashboard.recent.empty.title",
                defaultMessage: "No access policies yet",
              })}
              description={intl.formatMessage({
                id: "dashboard.recent.empty.desc",
                defaultMessage:
                  "Create your first rule for who can reach which system. Nothing is enforced until you test it and turn it on.",
              })}
              action={
                <Link className="btn btn--primary btn--sm" to="/policies/new">
                  {intl.formatMessage({
                    id: "dashboard.newPolicy",
                    defaultMessage: "New access policy",
                  })}
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
                        {intl.formatMessage(
                          {
                            id: "dashboard.recent.meta",
                            defaultMessage:
                              "{action} · {subjects, plural, one {# subject} other {# subjects}} → {resources, plural, one {# resource} other {# resources}}",
                          },
                          {
                            action: p.definition.action,
                            subjects: p.definition.subjects.length,
                            resources: p.definition.resources.length,
                          },
                        )}
                      </span>
                    </div>
                    <div className="list__meta">
                      {p.state === "draft" && !p.draft_impact && (
                        <Badge tone="warn">
                          {intl.formatMessage({
                            id: "dashboard.untested",
                            defaultMessage: "Untested",
                          })}
                        </Badge>
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
          title={intl.formatMessage({
            id: "dashboard.attention.title",
            defaultMessage: "Needs your attention",
          })}
          subtitle={intl.formatMessage({
            id: "dashboard.attention.subtitle",
            defaultMessage: "Items waiting on a decision from you.",
          })}
        >
          {attentionTotal === 0 ? (
            <EmptyState
              illustration={<EmptyIllustration kind="shield" />}
              title={intl.formatMessage({
                id: "dashboard.attention.clear.title",
                defaultMessage: "You're all caught up",
              })}
              description={intl.formatMessage({
                id: "dashboard.attention.clear.desc",
                defaultMessage:
                  "Nothing needs a decision right now. New requests and clean-up items will show up here when they arrive.",
              })}
            />
          ) : (
            <ul className="list">
              <li>
                <Link to="/requests">
                  <div className="list__main">
                    <b>
                      {intl.formatMessage({
                        id: "dashboard.attention.requests.title",
                        defaultMessage: "Open access requests",
                      })}
                    </b>
                    <span className="muted">
                      {intl.formatMessage({
                        id: "dashboard.attention.requests.desc",
                        defaultMessage:
                          "People waiting for access to be approved and set up",
                      })}
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
                    <b>
                      {intl.formatMessage({
                        id: "dashboard.attention.orphans.title",
                        defaultMessage: "Accounts to clean up",
                      })}
                    </b>
                    <span className="muted">
                      {intl.formatMessage({
                        id: "dashboard.attention.orphans.desc",
                        defaultMessage:
                          "Leftover accounts with no active access — usually people who have left",
                      })}
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
                    <b>
                      {intl.formatMessage({
                        id: "dashboard.attention.untested.title",
                        defaultMessage: "Untested drafts",
                      })}
                    </b>
                    <span className="muted">
                      {intl.formatMessage({
                        id: "dashboard.attention.untested.desc",
                        defaultMessage:
                          "Draft policies to test before they can go live",
                      })}
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
          )}
        </Card>
      </div>
    </>
  );
}
