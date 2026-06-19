import { useMemo, useState, type ReactNode } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useIntl, FormattedMessage } from "react-intl";
import { PageHeader, Card, Stat, StatusBadge, AsyncBoundary } from "@/components/ui";
import { EmptyState } from "@/components/EmptyState";
import { DataTable, type Column } from "@/components/DataTable";
import { HelpTooltip } from "@/components/HelpTooltip";
import { RiskPanel } from "@/components/RiskPanel";
import { useToast } from "@/components/Toast";
import {
  useMe,
  useAccessRequests,
  useCreateRequest,
  type AccessRequest,
  type CreateRequestResult,
  ApiError,
} from "@/api/access";
import { formatRelative, formatDateTime } from "@/lib/format";
import "./lane-a1.css";

// Rich-text tag for inline <code> samples inside localized help copy.
const code = (chunks: ReactNode) => <code>{chunks}</code>;

// Request states that mean the user can use the access right now: the grant has
// been provisioned (or activated) on the target.
const ACTIVE_STATES = new Set(["provisioned", "active"]);
// Closed/terminal states — neither usable nor in flight (no outgoing edges in
// the lifecycle FSM): the request was denied, cancelled, revoked, or expired.
const CLOSED_STATES = new Set(["denied", "cancelled", "revoked", "expired"]);
// "Waiting" is everything still in flight — requested, ai_reviewed, approved,
// provisioning, provision_failed — i.e. not yet usable and not closed. Deriving
// it by exclusion keeps the count correct as the request walks the FSM (e.g. a
// request parked in ai_reviewed by the AI risk gate still counts as waiting).
const isPending = (state: string) =>
  !ACTIVE_STATES.has(state) && !CLOSED_STATES.has(state);

export function SelfService() {
  const intl = useIntl();
  const me = useMe();
  const requests = useAccessRequests();

  // Scope the workspace-wide request list down to *this* person's requests —
  // the ones they raised, or that name them as the target. A plain operator's
  // self-service lens should only show their own access, never the whole
  // workspace's. (The server still authorizes the read; this is the user-facing
  // filter, not a security boundary.)
  const myRequests = useMemo(() => {
    const uid = me.data?.user_id;
    const rows = requests.data ?? [];
    // Fail safe for a page titled "Your access": if the caller's identity is
    // unknown (e.g. /me errored while the request list is still cached), show
    // nothing rather than the whole workspace's requests. The server still
    // authorizes the read — this is the user-facing scoping, not a security
    // boundary — but defaulting to "everything" would break the page's contract.
    if (!uid) return [];
    return rows.filter(
      (r) => r.requester_id === uid || r.target_user_id === uid,
    );
  }, [requests.data, me.data?.user_id]);

  const active = myRequests.filter((r) => ACTIVE_STATES.has(r.state));
  const pending = myRequests.filter((r) => isPending(r.state));

  return (
    <div className="lane-a1">
      <PageHeader
        title={intl.formatMessage({
          id: "nav.selfService",
          defaultMessage: "Your access",
        })}
        subtitle={intl.formatMessage({
          id: "selfservice.subtitle",
          defaultMessage:
            "Ask for what you need, follow where your requests are up to, and get plain-language help — no jargon required.",
        })}
      />

      <div className="grid grid--stats" style={{ marginBottom: 16 }}>
        <Stat
          label={intl.formatMessage({
            id: "selfservice.stat.active",
            defaultMessage: "Ready to use",
          })}
          value={active.length}
          delta={
            <span className="muted">
              {intl.formatMessage({
                id: "selfservice.stat.active.delta",
                defaultMessage: "things you can use now",
              })}
            </span>
          }
        />
        <Stat
          label={intl.formatMessage({
            id: "selfservice.stat.pending",
            defaultMessage: "Waiting on approval",
          })}
          value={pending.length}
          delta={
            <span className="muted">
              {intl.formatMessage({
                id: "selfservice.stat.pending.delta",
                defaultMessage: "requests in progress",
              })}
            </span>
          }
        />
      </div>

      <RequestAccessCard />

      <div className="grid grid--2" style={{ marginTop: 16 }}>
        <Card
          title={intl.formatMessage({
            id: "selfservice.active.title",
            defaultMessage: "What you can use now",
          })}
          subtitle={intl.formatMessage({
            id: "selfservice.active.subtitle",
            defaultMessage: "Access that's approved and ready to go.",
          })}
        >
          <AsyncBoundary
            isLoading={requests.isLoading}
            error={requests.error}
            data={active}
            onRetry={requests.refetch}
            isEmpty={(rows) => rows.length === 0}
            empty={
              <EmptyState
                icon="🔓"
                title={intl.formatMessage({
                  id: "selfservice.active.empty.title",
                  defaultMessage: "Nothing active yet",
                })}
                description={intl.formatMessage({
                  id: "selfservice.active.empty.desc",
                  defaultMessage:
                    "Once a request is approved and set up, it shows here. Use the form above to ask for what you need.",
                })}
              />
            }
          >
            {(rows) => (
              <ul className="list">
                {rows.map((r) => (
                  <li key={r.id}>
                    <Link to="/requests/$requestId" params={{ requestId: r.id }}>
                      <div className="list__main">
                        <b>{r.resource_ref}</b>
                        <span className="muted">
                          {r.role
                            ? intl.formatMessage(
                                {
                                  id: "selfservice.active.asRole",
                                  defaultMessage: "as {role}",
                                },
                                { role: r.role },
                              )
                            : intl.formatMessage({
                                id: "selfservice.active.access",
                                defaultMessage: "access",
                              })}{" "}
                          ·{" "}
                          {r.expires_at
                            ? intl.formatMessage(
                                {
                                  id: "selfservice.active.expires",
                                  defaultMessage: "expires {when}",
                                },
                                { when: formatRelative(r.expires_at) },
                              )
                            : intl.formatMessage({
                                id: "selfservice.active.noExpiry",
                                defaultMessage: "no expiry",
                              })}
                        </span>
                      </div>
                      <div className="list__meta">
                        <StatusBadge status={r.state} />
                      </div>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </AsyncBoundary>
        </Card>

        <HelpCard />
      </div>

      <Card
        title={intl.formatMessage({
          id: "selfservice.requests.title",
          defaultMessage: "Your requests",
        })}
        subtitle={intl.formatMessage({
          id: "selfservice.requests.subtitle",
          defaultMessage: "Everything you've asked for, and where it stands.",
        })}
        className="stack-mt"
      >
        <AsyncBoundary
          isLoading={requests.isLoading}
          error={requests.error}
          data={myRequests}
          onRetry={requests.refetch}
          isEmpty={(rows) => rows.length === 0}
          empty={
            <EmptyState
              icon="📝"
              title={intl.formatMessage({
                id: "selfservice.requests.empty.title",
                defaultMessage: "No requests yet",
              })}
              description={intl.formatMessage({
                id: "selfservice.requests.empty.desc",
                defaultMessage:
                  "Anything you ask for appears here so you can track approval and see when your access is ready.",
              })}
            />
          }
        >
          {(rows) => <MyRequestsTable rows={rows} />}
        </AsyncBoundary>
      </Card>
    </div>
  );
}

// RequestAccessCard is the plain-language "ask for access" form. It reuses the
// same POST /access-requests endpoint (and inline AI risk panel) as the
// operator console, but framed for an end user who just wants to get to a tool.
// Least-privilege default: the server requires a role on every request, but an
// end user shouldn't have to know access-level vocabulary to ask for something.
// When they leave "Level of access" blank we request read-only (viewer) — the
// safest grant — and power users can raise it under More options.
const DEFAULT_REQUEST_ROLE = "viewer";

function RequestAccessCard() {
  const intl = useIntl();
  const toast = useToast();
  const createMut = useCreateRequest();
  const [resource, setResource] = useState("");
  const [justification, setJustification] = useState("");
  const [role, setRole] = useState("");
  const [durationHours, setDurationHours] = useState("");
  const [result, setResult] = useState<CreateRequestResult | null>(null);

  const valid = resource.trim().length > 0 && justification.trim().length > 0;

  const submit = async () => {
    if (!valid) return;
    const hours = Number(durationHours);
    try {
      const res = await createMut.mutateAsync({
        resource_ref: resource.trim(),
        justification: justification.trim(),
        role: role.trim() || DEFAULT_REQUEST_ROLE,
        ...(durationHours.trim() && Number.isFinite(hours) && hours > 0
          ? { duration_hours: hours }
          : {}),
      });
      setResult(res);
      toast.success(
        intl.formatMessage({
          id: "selfservice.toast.submitted.title",
          defaultMessage: "Request submitted",
        }),
        res.workflow.approved
          ? intl.formatMessage({
              id: "selfservice.toast.submitted.approved",
              defaultMessage: "Approved automatically — setting up your access now.",
            })
          : intl.formatMessage({
              id: "selfservice.toast.submitted.review",
              defaultMessage:
                "Sent for review. You'll see the status update here.",
            }),
      );
      setResource("");
      setJustification("");
      setRole("");
      setDurationHours("");
    } catch (err) {
      toast.error(
        intl.formatMessage({
          id: "selfservice.toast.failed",
          defaultMessage: "We couldn't submit your request",
        }),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  return (
    <Card
      title={intl.formatMessage({
        id: "selfservice.request.title",
        defaultMessage: "Request access",
      })}
      subtitle={intl.formatMessage({
        id: "selfservice.request.subtitle",
        defaultMessage:
          "Tell us what you need and why. We'll send it to the right approver automatically — no need to know who that is.",
      })}
    >
      <label className="field">
        <span className="field__label">
          {intl.formatMessage({
            id: "selfservice.request.what.label",
            defaultMessage: "What do you need access to?",
          })}{" "}
          <HelpTooltip
            title={intl.formatMessage({
              id: "selfservice.request.what.helpTitle",
              defaultMessage: "What to enter",
            })}
          >
            <FormattedMessage
              id="selfservice.request.what.help"
              defaultMessage="The name of the app, server, or system — for example <code>app:salesforce</code> or <code>host:db-prod</code>. If you're not sure of the exact name, use one the person who sent you here would recognise."
              values={{ code }}
            />
          </HelpTooltip>
        </span>
        <input
          value={resource}
          placeholder={intl.formatMessage({
            id: "selfservice.request.what.placeholder",
            defaultMessage: "e.g. app:salesforce",
          })}
          onChange={(e) => setResource(e.target.value)}
        />
      </label>

      <label className="field">
        <span className="field__label">
          {intl.formatMessage({
            id: "selfservice.request.why.label",
            defaultMessage: "Why do you need it?",
          })}{" "}
          <HelpTooltip
            title={intl.formatMessage({
              id: "selfservice.request.why.helpTitle",
              defaultMessage: "Why this helps",
            })}
          >
            {intl.formatMessage({
              id: "selfservice.request.why.help",
              defaultMessage:
                "A short reason helps approvers say yes quickly — e.g. \"Closing the Q3 deals in Salesforce.\" It's also kept for the audit record.",
            })}
          </HelpTooltip>
        </span>
        <textarea
          value={justification}
          placeholder={intl.formatMessage({
            id: "selfservice.request.why.placeholder",
            defaultMessage: "e.g. Need to update customer records for my accounts",
          })}
          rows={2}
          onChange={(e) => setJustification(e.target.value)}
        />
      </label>

      <details className="disclosure">
        <summary>
          {intl.formatMessage({
            id: "selfservice.request.more",
            defaultMessage: "More options",
          })}
        </summary>
        <div className="field-row" style={{ marginTop: 10 }}>
          <label className="field">
            <span className="field__label">
              {intl.formatMessage({
                id: "selfservice.request.level.label",
                defaultMessage: "Level of access (optional)",
              })}{" "}
              <HelpTooltip
                title={intl.formatMessage({
                  id: "selfservice.request.level.helpTitle",
                  defaultMessage: "Access level",
                })}
              >
                <FormattedMessage
                  id="selfservice.request.level.help"
                  defaultMessage="The role you need on the target, like <code>viewer</code> or <code>editor</code>. Leave it blank and we'll request read-only (<code>viewer</code>) access — the safest default. Only ask for more if you know you need it."
                  values={{ code }}
                />
              </HelpTooltip>
            </span>
            <input
              value={role}
              placeholder="viewer"
              onChange={(e) => setRole(e.target.value)}
            />
          </label>
          <label className="field">
            <span className="field__label">
              {intl.formatMessage({
                id: "selfservice.request.duration.label",
                defaultMessage: "For how long? (hours, optional)",
              })}{" "}
              <HelpTooltip
                title={intl.formatMessage({
                  id: "selfservice.request.duration.helpTitle",
                  defaultMessage: "Time-limited access",
                })}
              >
                {intl.formatMessage({
                  id: "selfservice.request.duration.help",
                  defaultMessage:
                    "Access is given for a limited time and then removed automatically, which keeps everyone safer. Leave this blank to use your workspace's default.",
                })}
              </HelpTooltip>
            </span>
            <input
              value={durationHours}
              placeholder="e.g. 8"
              inputMode="numeric"
              onChange={(e) => setDurationHours(e.target.value)}
            />
          </label>
        </div>
      </details>

      {createMut.isError && (
        <p className="form-error" role="alert">
          {createMut.error.message}
        </p>
      )}

      <button
        className="btn btn--primary"
        disabled={!valid || createMut.isPending}
        onClick={submit}
        style={{ marginTop: 4 }}
      >
        {createMut.isPending
          ? intl.formatMessage({
              id: "selfservice.request.submitting",
              defaultMessage: "Submitting…",
            })
          : intl.formatMessage({
              id: "selfservice.request.submit",
              defaultMessage: "Request access",
            })}
      </button>

      {result && (
        <div className="callout callout--info" role="status" style={{ marginTop: 14 }}>
          <b>
            {intl.formatMessage({
              id: "selfservice.request.received",
              defaultMessage: "Request received.",
            })}
          </b>{" "}
          {result.workflow.approved
            ? intl.formatMessage({
                id: "selfservice.request.received.approved",
                defaultMessage:
                  "It was approved automatically and your access is being set up.",
              })
            : intl.formatMessage({
                id: "selfservice.request.received.review",
                defaultMessage:
                  "It's been sent for review — you'll see it update under \u201CYour requests\u201D below.",
              })}
          <div style={{ marginTop: 10 }}>
            <RiskPanel verdict={result.risk} />
          </div>
          <div style={{ marginTop: 10 }}>
            <Link
              className="btn btn--sm"
              to="/requests/$requestId"
              params={{ requestId: result.request.id }}
            >
              {intl.formatMessage({
                id: "selfservice.request.view",
                defaultMessage: "View request",
              })}
            </Link>
          </div>
        </div>
      )}
    </Card>
  );
}

function MyRequestsTable({ rows }: { rows: AccessRequest[] }) {
  const intl = useIntl();
  const navigate = useNavigate();
  const sorted = [...rows].sort((a, b) =>
    b.created_at.localeCompare(a.created_at),
  );
  const columns: Column<AccessRequest>[] = [
    {
      header: intl.formatMessage({
        id: "selfservice.col.what",
        defaultMessage: "What",
      }),
      cell: (r) => <b>{r.resource_ref}</b>,
    },
    {
      header: intl.formatMessage({
        id: "selfservice.col.level",
        defaultMessage: "Level",
      }),
      cell: (r) => r.role || <span className="muted">—</span>,
    },
    {
      header: intl.formatMessage({
        id: "selfservice.col.status",
        defaultMessage: "Status",
      }),
      cell: (r) => <StatusBadge status={r.state} />,
    },
    {
      header: intl.formatMessage({
        id: "selfservice.col.requested",
        defaultMessage: "Requested",
      }),
      cell: (r) => <span className="muted">{formatRelative(r.created_at)}</span>,
    },
    {
      header: intl.formatMessage({
        id: "selfservice.col.expires",
        defaultMessage: "Expires",
      }),
      cell: (r) =>
        r.expires_at ? (
          formatDateTime(r.expires_at)
        ) : (
          <span className="muted">—</span>
        ),
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={sorted}
      rowKey={(r) => r.id}
      onRowClick={(r) =>
        navigate({ to: "/requests/$requestId", params: { requestId: r.id } })
      }
    />
  );
}

function HelpCard() {
  const intl = useIntl();
  return (
    <Card
      title={intl.formatMessage({
        id: "selfservice.help.title",
        defaultMessage: "Help & FAQ",
      })}
      subtitle={intl.formatMessage({
        id: "selfservice.help.subtitle",
        defaultMessage: "Quick answers in plain language.",
      })}
    >
      <details className="disclosure">
        <summary>
          {intl.formatMessage({
            id: "selfservice.help.jit.q",
            defaultMessage: "What is \u201Cjust-in-time\u201D access?",
          })}
        </summary>
        <p className="muted">
          {intl.formatMessage({
            id: "selfservice.help.jit.a",
            defaultMessage:
              "Instead of having access to everything all the time, you ask for it only when you need it. It's granted for a limited window and then removed automatically — which keeps everyone safer.",
          })}
        </p>
      </details>
      <details className="disclosure">
        <summary>
          {intl.formatMessage({
            id: "selfservice.help.time.q",
            defaultMessage: "How long does approval take?",
          })}
        </summary>
        <p className="muted">
          {intl.formatMessage({
            id: "selfservice.help.time.a",
            defaultMessage:
              "Low-risk requests can be approved automatically and are ready in moments. Others go to a reviewer; you'll see the status change here as soon as they decide.",
          })}
        </p>
      </details>
      <details className="disclosure">
        <summary>
          {intl.formatMessage({
            id: "selfservice.help.name.q",
            defaultMessage: "I don't know the exact name of what I need.",
          })}
        </summary>
        <p className="muted">
          {intl.formatMessage({
            id: "selfservice.help.name.a",
            defaultMessage:
              "Enter the closest name you know (like the app's name) and add a clear reason. If it's not quite right, an approver can help — or ask the colleague who pointed you here.",
          })}
        </p>
      </details>
      <details className="disclosure">
        <summary>
          {intl.formatMessage({
            id: "selfservice.help.expired.q",
            defaultMessage: "My access expired — what do I do?",
          })}
        </summary>
        <p className="muted">
          {intl.formatMessage({
            id: "selfservice.help.expired.a",
            defaultMessage:
              "That's normal for time-limited access. Just request it again using the form above; if you use it often, mention that in your reason.",
          })}
        </p>
      </details>
    </Card>
  );
}
