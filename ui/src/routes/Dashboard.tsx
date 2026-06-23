import { useMemo } from "react";
import { Link } from "@tanstack/react-router";
import { useIntl } from "react-intl";
import { PageHeader, Card, Stat, Badge, StatusBadge } from "@/components/ui";
import { EmptyState, EmptyIllustration } from "@/components/EmptyState";
import { CircularScore } from "@/components/CircularScore";
import { Icon } from "@/components/Icon";
import { WhatsNewCard } from "@/components/WhatsNewCard";
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
import "./lane-a1.css";

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

// Shimmer for a card body while its underlying queries resolve. Without this,
// counts default to 0 from the `?? []` fallback on undefined data, so the
// "You're all caught up" / "No access policies yet" states would flash a false
// claim for a frame before the real data arrives.
function CardBodySkeleton({ lines = 3 }: { lines?: number }) {
  const intl = useIntl();
  return (
    <div
      aria-busy="true"
      aria-label={intl.formatMessage({
        id: "common.loading",
        defaultMessage: "Loading",
      })}
    >
      {Array.from({ length: lines }).map((_, i) => (
        <div
          key={i}
          className="skeleton skeleton--text"
          style={{ width: `${Math.max(40, 90 - i * 15)}%` }}
        />
      ))}
    </div>
  );
}

// Brand-voice failure state for a card whose query errored, so a failed load is
// never mistaken for an "all caught up" / empty result. Uses the design-system
// `.state--error` surface; copy stays plain-language with no raw error code,
// and `role="alert"` announces it to assistive tech.
function CardBodyError({ onRetry }: { onRetry: () => void }) {
  const intl = useIntl();
  return (
    <div className="state state--error" role="alert">
      <div className="state__icon" aria-hidden>
        <Icon name="alerts" size={22} />
      </div>
      <p style={{ fontWeight: 600 }}>
        {intl.formatMessage({
          id: "dashboard.loadError.title",
          defaultMessage: "We couldn't load this just now",
        })}
      </p>
      <p>
        {intl.formatMessage({
          id: "dashboard.loadError.desc",
          defaultMessage:
            "This is usually a brief network hiccup — nothing is lost. Check your connection and try again.",
        })}
      </p>
      <div style={{ marginTop: 12 }}>
        <button type="button" className="btn btn--sm" onClick={onRetry}>
          {intl.formatMessage({
            id: "common.tryAgain",
            defaultMessage: "Try again",
          })}
        </button>
      </div>
    </div>
  );
}

type HealthIssueTone = "ok" | "warn" | "danger";

interface HealthIssue {
  id: string;
  title: string;
  description: string;
  tone: HealthIssueTone;
  count: number;
  link: string;
  cta: string;
}

interface HealthData {
  score: number | null;
  issues: HealthIssue[];
  loading: boolean;
  error: unknown;
  retry: () => void;
}

function useHealthData(): HealthData {
  const intl = useIntl();
  const policies = usePolicies();
  const requests = useAccessRequests();
  const orphans = useOrphans();
  const connectors = useConnectors({});

  const counts = useMemo(() => {
    const rows = policies.data ?? [];
    return {
      total: rows.length,
      drafts: rows.filter((p) => p.state === "draft").length,
      active: rows.filter((p) => p.state === "active").length,
      untested: rows.filter((p) => p.state === "draft" && !p.draft_impact).length,
    };
  }, [policies.data]);

  const openRequests = (requests.data ?? []).filter((r) =>
    OPEN_REQUEST_STATES.has(r.state),
  );
  const pendingOrphans = (orphans.data ?? []).filter(
    (o) => o.disposition === "pending",
  );
  const connectedCount = (connectors.data ?? []).filter((c) => c.connected).length;

  const loading =
    policies.isLoading || requests.isLoading || orphans.isLoading || connectors.isLoading;
  const error =
    policies.error || requests.error || orphans.error || connectors.error;

  return useMemo(() => {
    if (loading || error) {
      return {
        score: null,
        issues: [],
        loading,
        error,
        retry: () => {
          void policies.refetch();
          void requests.refetch();
          void orphans.refetch();
          void connectors.refetch();
        },
      };
    }

    let score = 100;
    const issues: HealthIssue[] = [];

    const addIssue = (
      id: string,
      title: string,
      description: string,
      tone: HealthIssueTone,
      count: number,
      link: string,
      cta: string,
      deduction: number,
    ) => {
      score -= deduction;
      issues.push({ id, title, description, tone, count, link, cta });
    };

    if (counts.untested > 0) {
      addIssue(
        "untested",
        intl.formatMessage(
          {
            id: "dashboard.health.issue.untested.title",
            defaultMessage:
              "{count, plural, one {# untested draft} other {# untested drafts}}",
          },
          { count: counts.untested },
        ),
        intl.formatMessage({
          id: "dashboard.health.issue.untested.desc",
          defaultMessage: "Test and promote these drafts so they start protecting access.",
        }),
        "warn",
        counts.untested,
        "/policies",
        intl.formatMessage({
          id: "dashboard.health.issue.untested.cta",
          defaultMessage: "Review drafts",
        }),
        Math.min(30, counts.untested * 10),
      );
    }

    if (pendingOrphans.length > 0) {
      addIssue(
        "orphans",
        intl.formatMessage(
          {
            id: "dashboard.health.issue.orphans.title",
            defaultMessage:
              "{count, plural, one {# account to clean up} other {# accounts to clean up}}",
          },
          { count: pendingOrphans.length },
        ),
        intl.formatMessage({
          id: "dashboard.health.issue.orphans.desc",
          defaultMessage: "Leftover accounts with no active access — usually people who have left.",
        }),
        pendingOrphans.length > 3 ? "danger" : "warn",
        pendingOrphans.length,
        "/directory",
        intl.formatMessage({
          id: "dashboard.health.issue.orphans.cta",
          defaultMessage: "Review accounts",
        }),
        Math.min(20, pendingOrphans.length * 10),
      );
    }

    if (openRequests.length > 0) {
      addIssue(
        "requests",
        intl.formatMessage(
          {
            id: "dashboard.health.issue.requests.title",
            defaultMessage:
              "{count, plural, one {# open request} other {# open requests}}",
          },
          { count: openRequests.length },
        ),
        intl.formatMessage({
          id: "dashboard.health.issue.requests.desc",
          defaultMessage: "People waiting for access to be approved and set up.",
        }),
        "warn",
        openRequests.length,
        "/requests",
        intl.formatMessage({
          id: "dashboard.health.issue.requests.cta",
          defaultMessage: "Review requests",
        }),
        Math.min(15, openRequests.length * 5),
      );
    }

    if (counts.total === 0) {
      addIssue(
        "no-policies",
        intl.formatMessage({
          id: "dashboard.health.issue.noPolicies.title",
          defaultMessage: "No access policies yet",
        }),
        intl.formatMessage({
          id: "dashboard.health.issue.noPolicies.desc",
          defaultMessage: "Create your first rule so access is governed and enforced.",
        }),
        "danger",
        0,
        "/policies/new",
        intl.formatMessage({
          id: "dashboard.health.issue.noPolicies.cta",
          defaultMessage: "Create a policy",
        }),
        20,
      );
    }

    if (connectedCount === 0) {
      addIssue(
        "no-connectors",
        intl.formatMessage({
          id: "dashboard.health.issue.noConnectors.title",
          defaultMessage: "No connected source",
        }),
        intl.formatMessage({
          id: "dashboard.health.issue.noConnectors.desc",
          defaultMessage: "Connect where your team signs in so policies can target real people and apps.",
        }),
        "warn",
        0,
        "/connectors",
        intl.formatMessage({
          id: "dashboard.health.issue.noConnectors.cta",
          defaultMessage: "Connect a source",
        }),
        10,
      );
    }

    if (issues.length === 0) {
      issues.push({
        id: "healthy",
        title: intl.formatMessage({
          id: "dashboard.health.issue.healthy.title",
          defaultMessage: "Workspace looks healthy",
        }),
        description: intl.formatMessage({
          id: "dashboard.health.issue.healthy.desc",
          defaultMessage:
            "Policies are active, accounts are clean, and no requests are waiting on you.",
        }),
        tone: "ok",
        count: 0,
        link: "/policies",
        cta: intl.formatMessage({
          id: "dashboard.health.issue.healthy.cta",
          defaultMessage: "View policies",
        }),
      });
    }

    return {
      score: Math.max(0, score),
      issues: issues.slice(0, 3),
      loading: false,
      error: null,
      retry: () => {},
    };
  }, [
    loading,
    error,
    counts.untested,
    counts.total,
    pendingOrphans.length,
    openRequests.length,
    connectedCount,
    intl,
    policies,
    requests,
    orphans,
    connectors,
  ]);
}

function HealthScorecard({ data }: { data: HealthData }) {
  const intl = useIntl();
  const topIssue = data.issues[0];

  return (
    <div className="card health-card">
      <div className="health-card__body">
        {data.loading ? (
          <div className="health-card__skeleton">
            <div className="skeleton skeleton--circle" />
            <div className="health-card__skeleton-text">
              <div className="skeleton skeleton--title" />
              <div className="skeleton skeleton--text" />
              <div className="skeleton skeleton--text" style={{ width: "60%" }} />
            </div>
          </div>
        ) : data.error ? (
          <CardBodyError onRetry={data.retry} />
        ) : (
          <>
            <CircularScore
              value={data.score}
              size={140}
              caption={intl.formatMessage({
                id: "dashboard.health.scoreCaption",
                defaultMessage: "Health score",
              })}
            />
            <div className="health-card__info">
              <h2 className="health-card__title">
                {data.score === null
                  ? intl.formatMessage({
                      id: "dashboard.health.title.unavailable",
                      defaultMessage: "Health score unavailable",
                    })
                  : data.score >= 80
                    ? intl.formatMessage({
                        id: "dashboard.health.title.good",
                        defaultMessage: "Your workspace looks healthy",
                      })
                    : data.score >= 50
                      ? intl.formatMessage({
                          id: "dashboard.health.title.fair",
                          defaultMessage: "A few things need attention",
                        })
                      : intl.formatMessage({
                          id: "dashboard.health.title.poor",
                          defaultMessage: "Some issues need your attention",
                        })}
              </h2>
              <p className="health-card__desc">
                {data.score === null
                  ? intl.formatMessage({
                      id: "dashboard.health.desc.unavailable",
                      defaultMessage: "We couldn't calculate your health score right now.",
                    })
                  : intl.formatMessage({
                      id: "dashboard.health.desc",
                      defaultMessage:
                        "This score is based on your active policies, open requests, accounts to clean up, and connected sources.",
                    })}
              </p>
              <ul className="health-card__issues">
                {data.issues.map((issue) => (
                  <li key={issue.id} className={`health-card__issue health-card__issue--${issue.tone}`}>
                    <Icon
                      name={
                        issue.tone === "ok"
                          ? "compliance"
                          : issue.tone === "danger"
                            ? "alerts"
                            : "alerts"
                      }
                      size={16}
                    />
                    <span>{issue.title}</span>
                  </li>
                ))}
              </ul>
              {topIssue && (
                <Link className="btn btn--primary" to={topIssue.link}>
                  {topIssue.cta}
                </Link>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export function Dashboard() {
  const intl = useIntl();
  const health = useHealthData();
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

  // The attention card sums three independent reads; only trust a zero total
  // (the "all caught up" state) once every one of them has actually resolved.
  // If any errored, data is undefined → counts fall back to 0, which would
  // otherwise read as "all caught up" — surface the failure (with retry) first.
  const attentionLoading =
    policies.isLoading || requests.isLoading || orphans.isLoading;
  const attentionError =
    policies.isError || requests.isError || orphans.isError;
  const retryAttention = () => {
    void policies.refetch();
    void requests.refetch();
    void orphans.refetch();
  };

  const recentPolicies: Policy[] = useMemo(
    () =>
      [...(policies.data ?? [])]
        .sort((a, b) => b.updated_at.localeCompare(a.updated_at))
        .slice(0, 6),
    [policies.data],
  );

  return (
    <div className="lane-a1">
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

      <HealthScorecard data={health} />

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

      <div className="grid grid--3" style={{ marginTop: 16 }}>
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
          {policies.isLoading ? (
            <CardBodySkeleton />
          ) : policies.isError ? (
            <CardBodyError onRetry={() => void policies.refetch()} />
          ) : recentPolicies.length === 0 ? (
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
          {attentionLoading ? (
            <CardBodySkeleton />
          ) : attentionError ? (
            <CardBodyError onRetry={retryAttention} />
          ) : attentionTotal === 0 ? (
            <EmptyState
              illustration={<EmptyIllustration kind="shield" />}
              title={intl.formatMessage({
                id: "dashboard.attention.clear.title",
                defaultMessage: "You're all caught up",
              })}
              description={intl.formatMessage({
                id: "dashboard.attention.clear.desc",
                defaultMessage:
                  "Nothing needs a decision right now. Policies are active, accounts are clean, and no requests are waiting on you.",
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

        <WhatsNewCard />
      </div>
    </div>
  );
}
