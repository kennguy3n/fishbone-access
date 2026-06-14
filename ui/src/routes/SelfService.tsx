import { useMemo, useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
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
    <>
      <PageHeader
        title="Your access"
        subtitle="Request access to what you need, track your requests, and find help — in plain language."
      />

      <div className="grid grid--stats" style={{ marginBottom: 16 }}>
        <Stat
          label="Active access"
          value={active.length}
          delta={<span className="muted">things you can use now</span>}
        />
        <Stat
          label="Waiting on approval"
          value={pending.length}
          delta={<span className="muted">requests in progress</span>}
        />
      </div>

      <RequestAccessCard />

      <div className="grid grid--2" style={{ marginTop: 16 }}>
        <Card
          title="What you can access now"
          subtitle="Access that's been approved and is currently active."
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
                title="No active access yet"
                description="When a request is approved and set up, it shows here. Use the form above to ask for what you need."
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
                          {r.role ? `as ${r.role}` : "access"} ·{" "}
                          {r.expires_at
                            ? `expires ${formatRelative(r.expires_at)}`
                            : "no expiry"}
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
        title="Your requests"
        subtitle="Everything you've asked for, and where it stands."
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
              title="You haven't requested anything yet"
              description="Requests you make appear here so you can track approval and see when access is ready."
            />
          }
        >
          {(rows) => <MyRequestsTable rows={rows} />}
        </AsyncBoundary>
      </Card>
    </>
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
        "Request submitted",
        res.workflow.approved
          ? "Auto-approved — setting up your access now."
          : "Sent for review. You'll see the status update here.",
      );
      setResource("");
      setJustification("");
      setRole("");
      setDurationHours("");
    } catch (err) {
      toast.error(
        "Could not submit request",
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  return (
    <Card
      title="Request access"
      subtitle="Tell us what you need and why. We'll route it for approval automatically — no need to know who to ask."
    >
      <label className="field">
        <span className="field__label">
          What do you need access to?{" "}
          <HelpTooltip title="What to enter">
            The name of the app, server, or system — for example{" "}
            <code>app:salesforce</code> or <code>host:db-prod</code>. If you're
            not sure of the exact name, ask the person who sent you here, or use
            a name they'd recognise.
          </HelpTooltip>
        </span>
        <input
          value={resource}
          placeholder="e.g. app:salesforce"
          onChange={(e) => setResource(e.target.value)}
        />
      </label>

      <label className="field">
        <span className="field__label">
          Why do you need it?{" "}
          <HelpTooltip title="Why this helps">
            A short reason helps approvers say yes quickly — e.g. "Closing the
            Q3 deals in Salesforce." It's also kept for the audit record.
          </HelpTooltip>
        </span>
        <textarea
          value={justification}
          placeholder="e.g. Need to update customer records for my accounts"
          rows={2}
          onChange={(e) => setJustification(e.target.value)}
        />
      </label>

      <details className="disclosure">
        <summary>More options</summary>
        <div className="field-row" style={{ marginTop: 10 }}>
          <label className="field">
            <span className="field__label">
              Level of access (optional){" "}
              <HelpTooltip title="Access level">
                The role you need on the target, like <code>viewer</code> or{" "}
                <code>editor</code>. Leave blank and we'll request read-only{" "}
                (<code>viewer</code>) access — the safest default. Ask for more
                here only if you know you need it.
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
              For how long? (hours, optional){" "}
              <HelpTooltip title="Time-limited access">
                Access is just-in-time: it's granted for a limited time and then
                automatically removed. Leave blank to use your workspace's
                default.
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
        {createMut.isPending ? "Submitting…" : "Request access"}
      </button>

      {result && (
        <div className="callout callout--info" role="status" style={{ marginTop: 14 }}>
          <b>Request received.</b>{" "}
          {result.workflow.approved
            ? "It was auto-approved and your access is being set up."
            : "It's been sent for review — you'll see it update under “Your requests” below."}
          <div style={{ marginTop: 10 }}>
            <RiskPanel verdict={result.risk} />
          </div>
          <div style={{ marginTop: 10 }}>
            <Link
              className="btn btn--sm"
              to="/requests/$requestId"
              params={{ requestId: result.request.id }}
            >
              View request
            </Link>
          </div>
        </div>
      )}
    </Card>
  );
}

function MyRequestsTable({ rows }: { rows: AccessRequest[] }) {
  const navigate = useNavigate();
  const sorted = [...rows].sort((a, b) =>
    b.created_at.localeCompare(a.created_at),
  );
  const columns: Column<AccessRequest>[] = [
    {
      header: "What",
      cell: (r) => <b>{r.resource_ref}</b>,
    },
    {
      header: "Level",
      cell: (r) => r.role || <span className="muted">—</span>,
    },
    {
      header: "Status",
      cell: (r) => <StatusBadge status={r.state} />,
    },
    {
      header: "Requested",
      cell: (r) => <span className="muted">{formatRelative(r.created_at)}</span>,
    },
    {
      header: "Expires",
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
  return (
    <Card
      title="Help & FAQ"
      subtitle="Quick answers in plain language."
    >
      <details className="disclosure">
        <summary>What is “just-in-time” access?</summary>
        <p className="muted">
          Instead of having standing access to everything all the time, you
          request access only when you need it. It's granted for a limited
          window and then removed automatically — which keeps everyone safer.
        </p>
      </details>
      <details className="disclosure">
        <summary>How long does approval take?</summary>
        <p className="muted">
          Low-risk requests can be approved automatically and are ready in
          moments. Others go to a reviewer; you'll see the status change here as
          soon as they decide.
        </p>
      </details>
      <details className="disclosure">
        <summary>I don't know the exact name of what I need.</summary>
        <p className="muted">
          Enter the closest name you know (like the app's name) and add a clear
          reason. If it's not quite right, an approver can help — or ask the
          colleague who pointed you here.
        </p>
      </details>
      <details className="disclosure">
        <summary>My access expired — what do I do?</summary>
        <p className="muted">
          That's normal for time-limited access. Just request it again using
          the form above; if you use it often, mention that in your reason.
        </p>
      </details>
    </Card>
  );
}
