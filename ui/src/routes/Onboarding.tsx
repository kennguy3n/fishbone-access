import { useMemo, useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { PageHeader, Card, Badge, LoadingState } from "@/components/ui";
import { EmptyIllustration } from "@/components/EmptyState";
import { HelpTooltip } from "@/components/HelpTooltip";
import { Icon } from "@/components/Icon";
import { useToast } from "@/components/Toast";
import {
  useMe,
  useConnectors,
  usePolicies,
  useCreatePolicy,
  useRbacRoles,
  useRbacMembers,
  useAssignRbacMember,
  type ConnectorCatalogueEntry,
  ApiError,
} from "@/api/access";
import { useHasPermission, Perm } from "@/lib/permissions";
import {
  ONBOARDING_STEPS,
  useOnboardingProgress,
  withCompleted,
  type OnboardingProgress,
  type OnboardingStepId,
} from "@/lib/onboarding-store";
import { titleCase } from "@/lib/format";

// Human labels for the stepper. Kept here (not in the store) so the store stays
// presentation-free.
const STEP_LABELS: Record<OnboardingStepId, string> = {
  welcome: "Welcome",
  connect: "Connect a source",
  policy: "First access rule",
  invite: "Invite a teammate",
  done: "All set",
};

export function Onboarding() {
  const me = useMe();
  // Resolve the bound tenant before mounting the wizard so the progress store
  // keys on the real tenant id from its first render (the persistence hook
  // initializes lazily and won't re-key afterwards).
  if (me.isLoading) return <LoadingState label="Preparing your setup…" />;
  return <OnboardingWizard tenantId={me.data?.tenant_id ?? ""} />;
}

function OnboardingWizard({ tenantId }: { tenantId: string }) {
  const navigate = useNavigate();
  const [progress, update] = useOnboardingProgress(tenantId);

  const stepIndex = Math.max(0, ONBOARDING_STEPS.indexOf(progress.lastStep));
  const step = ONBOARDING_STEPS[stepIndex];

  const goto = (next: OnboardingStepId) => update({ lastStep: next });
  const advance = () => {
    const next = ONBOARDING_STEPS[Math.min(stepIndex + 1, ONBOARDING_STEPS.length - 1)];
    update({ lastStep: next, completed: withCompleted(progress.completed, step) });
  };
  const back = () => {
    if (stepIndex === 0) return;
    goto(ONBOARDING_STEPS[stepIndex - 1]);
  };

  return (
    <>
      <PageHeader
        title="Get started"
        subtitle="A short, guided setup. You can leave and pick up where you left off — your progress on this browser is saved as you go."
        actions={
          <Link className="btn btn--ghost btn--sm" to="/">
            Skip for now
          </Link>
        }
      />

      <div className="onboard">
        <Stepper current={stepIndex} completed={progress.completed} />

        {step === "welcome" && (
          <WelcomeStep
            tenantId={tenantId}
            workspaceName={progress.workspaceName}
            onName={(workspaceName) => update({ workspaceName })}
            onNext={advance}
          />
        )}
        {step === "connect" && (
          <ConnectStep onBack={back} onNext={advance} />
        )}
        {step === "policy" && <PolicyStep onBack={back} onNext={advance} />}
        {step === "invite" && <InviteStep onBack={back} onNext={advance} />}
        {step === "done" && (
          <DoneStep
            progress={progress}
            onBack={back}
            onFinish={() => {
              update({
                finished: true,
                completed: withCompleted(progress.completed, "done"),
              });
              navigate({ to: "/" });
            }}
          />
        )}
      </div>
    </>
  );
}

function Stepper({
  current,
  completed,
}: {
  current: number;
  completed: OnboardingStepId[];
}) {
  return (
    <ol className="stepper" aria-label="Setup progress">
      {ONBOARDING_STEPS.map((id, i) => {
        const isActive = i === current;
        const isDone = i < current || completed.includes(id);
        const cls = `stepper__step${isActive ? " stepper__step--active" : ""}${
          isDone && !isActive ? " stepper__step--done" : ""
        }`;
        return (
          <li className={cls} key={id} aria-current={isActive ? "step" : undefined}>
            <span className="stepper__dot" aria-hidden>
              {isDone && !isActive ? "✓" : i + 1}
            </span>
            <span className="stepper__name">{STEP_LABELS[id]}</span>
            {i < ONBOARDING_STEPS.length - 1 && (
              <span className="stepper__bar" aria-hidden />
            )}
          </li>
        );
      })}
    </ol>
  );
}

// --- Step 1: Welcome ------------------------------------------------------

function WelcomeStep({
  tenantId,
  workspaceName,
  onName,
  onNext,
}: {
  tenantId: string;
  workspaceName: string;
  onName: (name: string) => void;
  onNext: () => void;
}) {
  return (
    <Card
      title="Welcome to ShieldNet Access"
      subtitle="In a few minutes you'll connect where your team logs in, write your first access rule, and invite a colleague. No prior security experience needed."
    >
      <div className="overview-anim" aria-hidden>
        <span className="overview-anim__node">Your people</span>
        <span className="overview-anim__flow" />
        <span className="overview-anim__node overview-anim__node--sng">
          ShieldNet Access
        </span>
        <span className="overview-anim__flow" />
        <span className="overview-anim__node">Your apps &amp; servers</span>
      </div>
      <p className="muted" style={{ maxWidth: "62ch" }}>
        ShieldNet sits between your people and the apps, servers, and databases
        they need. It grants access just-in-time — only when someone needs it,
        only for as long as they need it — and records every grant for you.
      </p>

      <label className="field" style={{ marginTop: 8 }}>
        <span className="field__label">
          What should we call this workspace?{" "}
          <HelpTooltip title="Workspace name">
            A friendly label just for you, shown in this console on this browser.
            It doesn't change anything on the server or how access works.
          </HelpTooltip>
        </span>
        <input
          value={workspaceName}
          placeholder="e.g. Acme Corp"
          onChange={(e) => onName(e.target.value)}
        />
      </label>

      <dl className="kv" style={{ marginTop: 4 }}>
        <div>
          <dt>
            Bound tenant{" "}
            <HelpTooltip title="Tenant">
              The isolated workspace your sign-in maps to. Everything you create
              here stays inside this tenant and is never visible to others.
            </HelpTooltip>
          </dt>
          <dd>
            <code>{tenantId || "—"}</code>
          </dd>
        </div>
      </dl>

      <div className="onboard__actions">
        <button className="btn btn--primary" onClick={onNext}>
          Let's go
        </button>
      </div>
    </Card>
  );
}

// --- Step 2: Connect a source --------------------------------------------

// Recommend the most-adopted, fully-supported connectors first (T1/T2), and
// surface identity sources ahead of apps — connecting where your team logs in
// is the natural day-1 first move. Capped so the SME isn't shown the full
// catalogue here; the full gallery is one click away.
function recommendConnectors(
  entries: ConnectorCatalogueEntry[],
): ConnectorCatalogueEntry[] {
  const rank = (e: ConnectorCatalogueEntry) => {
    const identity = /identity|directory|idp|sso/i.test(e.category) ? 0 : 1;
    const tier = e.tier === "T1" ? 0 : e.tier === "T2" ? 1 : 2;
    return identity * 10 + tier;
  };
  return [...entries].sort((a, b) => rank(a) - rank(b)).slice(0, 6);
}

function ConnectStep({
  onBack,
  onNext,
}: {
  onBack: () => void;
  onNext: () => void;
}) {
  const navigate = useNavigate();
  const { data, isLoading } = useConnectors({});
  const entries = useMemo(() => data ?? [], [data]);
  const connectedCount = entries.filter((e) => e.connected).length;
  const recommended = useMemo(() => recommendConnectors(entries), [entries]);
  const [selected, setSelected] = useState<string>("");
  const selectedEntry = entries.find((e) => e.provider === selected);

  return (
    <Card
      title="Connect where your team logs in"
      subtitle="Link an identity source (like Google Workspace, Okta, or Microsoft Entra) or an app. ShieldNet uses it to know who your people are — it never stores their passwords."
    >
      {connectedCount > 0 && (
        <div className="callout callout--ok" role="status">
          {connectedCount === 1
            ? "1 source connected. You can connect more, or continue."
            : `${connectedCount} sources connected. You can connect more, or continue.`}
        </div>
      )}

      <div className="explainer">
        <p className="muted" style={{ maxWidth: "64ch" }}>
          To connect a source you'll usually paste one credential from it:
        </p>
        <ul className="explainer__list">
          <li>
            an{" "}
            <b>OAuth client</b>{" "}
            <HelpTooltip title="OAuth client">
              A small "app registration" you create inside your provider (e.g.
              Google or Microsoft). It produces a <i>client ID</i> and{" "}
              <i>client secret</i> that let ShieldNet read your users on your
              behalf — without ever seeing anyone's password. You'll usually
              find it under "APIs &amp; Services", "App registrations", or
              "Developer" settings.
            </HelpTooltip>
            , or
          </li>
          <li>
            an{" "}
            <b>API token</b>{" "}
            <HelpTooltip title="API token">
              A long secret string the provider generates for you (sometimes
              called an "API key" or "service token"). Copy it once when you
              create it and paste it into the guided setup — the provider often
              won't show it again, so keep it handy.
            </HelpTooltip>
            .
          </li>
        </ul>
        <p className="muted" style={{ maxWidth: "64ch" }}>
          Don't have one yet? Pick your provider below — the guided setup walks
          you through exactly where to find it, step by step.
        </p>
      </div>

      {isLoading ? (
        <LoadingState label="Loading connectors…" />
      ) : recommended.length === 0 ? (
        <p className="muted">No connectors are available in this deployment.</p>
      ) : (
        <div className="choice-grid" role="radiogroup" aria-label="Recommended connectors">
          {recommended.map((e) => {
            const isSel = e.provider === selected;
            return (
              <button
                key={e.provider}
                type="button"
                role="radio"
                aria-checked={isSel}
                className={`choice${isSel ? " choice--selected" : ""}`}
                onClick={() => setSelected(e.provider)}
              >
                <div className="choice__name">
                  {e.display_name}
                  {e.connected && (
                    <Badge tone="ok" dot>
                      Connected
                    </Badge>
                  )}
                </div>
                <div className="choice__desc">
                  {titleCase(e.category)} · {e.tier}
                </div>
              </button>
            );
          })}
        </div>
      )}

      {selectedEntry && (
        <div className="callout callout--info" role="status" style={{ marginTop: 12 }}>
          <b>{selectedEntry.display_name}</b> — the guided setup explains the
          exact scopes to grant and the common mistakes to avoid, then verifies
          the connection before anything syncs.
          <div style={{ marginTop: 10 }}>
            <button
              className="btn btn--primary btn--sm"
              onClick={() =>
                navigate({
                  to: "/connectors/$provider/setup",
                  params: { provider: selectedEntry.provider },
                })
              }
            >
              Open guided setup for {selectedEntry.display_name}
            </button>
          </div>
        </div>
      )}

      <p className="muted" style={{ fontSize: 12, marginTop: 12 }}>
        Looking for a different provider?{" "}
        <Link to="/connectors">Browse all connectors</Link>.
      </p>

      <div className="onboard__actions">
        <button className="btn btn--ghost" onClick={onBack}>
          Back
        </button>
        <button className="btn btn--primary" onClick={onNext}>
          {connectedCount > 0 ? "Continue" : "Skip for now"}
        </button>
      </div>
    </Card>
  );
}

// --- Step 3: First access rule -------------------------------------------

function PolicyStep({
  onBack,
  onNext,
}: {
  onBack: () => void;
  onNext: () => void;
}) {
  const toast = useToast();
  const policies = usePolicies();
  const createMut = useCreatePolicy();
  const [subjects, setSubjects] = useState("");
  const [resources, setResources] = useState("");
  const [role, setRole] = useState("");
  const [createdName, setCreatedName] = useState<string | null>(null);

  const policyCount = policies.data?.length ?? 0;
  const subjectList = subjects.split(",").map((s) => s.trim()).filter(Boolean);
  const resourceList = resources.split(",").map((s) => s.trim()).filter(Boolean);
  const valid = subjectList.length > 0 && resourceList.length > 0;

  const submit = async () => {
    if (!valid) return;
    const name = `Allow ${subjectList[0]}${
      subjectList.length > 1 ? ` +${subjectList.length - 1}` : ""
    } → ${resourceList[0]}`;
    try {
      await createMut.mutateAsync({
        name,
        definition: {
          action: "grant",
          subjects: subjectList,
          resources: resourceList,
          ...(role.trim() ? { role: role.trim() } : {}),
        },
      });
      setCreatedName(name);
      toast.success("Draft access rule created", "Test and promote it to go live.");
    } catch (err) {
      toast.error(
        "Could not create the rule",
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  return (
    <Card
      title="Write your first access rule"
      subtitle="A rule says who can reach what. Nothing is enforced until you test it and turn it on — so it's safe to create one now."
    >
      {policyCount > 0 && createdName === null && (
        <div className="callout callout--ok" role="status">
          You already have {policyCount} access{" "}
          {policyCount === 1 ? "rule" : "rules"}. You can add another, or
          continue.
        </div>
      )}

      {createdName ? (
        <div className="callout callout--ok" role="status">
          <b>Created.</b> Your draft rule "{createdName}" is saved. Next, open it
          to <Link to="/policies">test and promote it</Link> — that's when it
          starts protecting access.
        </div>
      ) : (
        <>
          <label className="field">
            <span className="field__label">
              Who should get access?{" "}
              <HelpTooltip title="Who">
                A group or person from your connected source — for example a
                group name like <code>group:engineering</code> or a single user.
                Separate multiple with commas.
              </HelpTooltip>
            </span>
            <input
              value={subjects}
              placeholder="group:engineering, alice@acme.com"
              onChange={(e) => setSubjects(e.target.value)}
            />
          </label>

          <label className="field">
            <span className="field__label">
              What can they reach?{" "}
              <HelpTooltip title="What">
                The app, server, or database this rule covers — for example{" "}
                <code>app:salesforce</code> or <code>host:10.0.0.0/24</code>.
                Separate multiple with commas.
              </HelpTooltip>
            </span>
            <input
              value={resources}
              placeholder="app:salesforce, host:db-prod"
              onChange={(e) => setResources(e.target.value)}
            />
          </label>

          <details className="disclosure">
            <summary>Advanced options</summary>
            <label className="field" style={{ marginTop: 10 }}>
              <span className="field__label">
                Role (optional){" "}
                <HelpTooltip title="Role">
                  The level of access this rule grants on the target, such as{" "}
                  <code>viewer</code> or <code>admin</code>. Leave blank if your
                  target doesn't use roles.
                </HelpTooltip>
              </span>
              <input
                value={role}
                placeholder="viewer"
                onChange={(e) => setRole(e.target.value)}
              />
            </label>
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
            {createMut.isPending ? "Creating…" : "Create draft rule"}
          </button>
        </>
      )}

      <div className="onboard__actions">
        <button className="btn btn--ghost" onClick={onBack}>
          Back
        </button>
        <button className="btn btn--primary" onClick={onNext}>
          {createdName || policyCount > 0 ? "Continue" : "Skip for now"}
        </button>
      </div>
    </Card>
  );
}

// --- Step 4: Invite a teammate -------------------------------------------

function InviteStep({
  onBack,
  onNext,
}: {
  onBack: () => void;
  onNext: () => void;
}) {
  const toast = useToast();
  const canManage = useHasPermission(Perm.RbacManage);
  const roles = useRbacRoles({ enabled: canManage });
  const members = useRbacMembers({ enabled: canManage });
  const assignMut = useAssignRbacMember();
  const [userId, setUserId] = useState("");
  const [role, setRole] = useState("");
  const [invited, setInvited] = useState<string | null>(null);

  // Default the role select to the first non-owner role once the catalogue
  // loads (a teammate rarely needs to be made an owner on day one).
  const roleOptions = roles.data?.roles ?? [];
  const effectiveRole =
    role || roleOptions.find((r) => r.role !== "owner")?.role || roleOptions[0]?.role || "";

  const memberCount = members.data?.length ?? 0;

  const submit = async () => {
    const uid = userId.trim();
    if (!uid || !effectiveRole) return;
    try {
      await assignMut.mutateAsync({ userId: uid, role: effectiveRole });
      setInvited(uid);
      toast.success("Teammate added", `Assigned the ${effectiveRole} role.`);
      setUserId("");
    } catch (err) {
      toast.error(
        "Could not add teammate",
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  if (!canManage) {
    return (
      <Card
        title="Invite a teammate"
        subtitle="Bring a colleague into this workspace."
      >
        <div className="callout callout--info" role="status">
          Inviting teammates needs the member-management permission, which your
          current role doesn't have. Ask your workspace owner to add people, or
          continue — you can always do this later.
        </div>
        <div className="onboard__actions">
          <button className="btn btn--ghost" onClick={onBack}>
            Back
          </button>
          <button className="btn btn--primary" onClick={onNext}>
            Continue
          </button>
        </div>
      </Card>
    );
  }

  return (
    <Card
      title="Invite a teammate"
      subtitle="Give a colleague the right level of access to this workspace. They sign in with your identity provider — you just assign their role here."
    >
      {memberCount > 0 && (
        <div className="callout callout--ok" role="status">
          {memberCount} {memberCount === 1 ? "member" : "members"} in this
          workspace.
        </div>
      )}

      {invited && (
        <div className="callout callout--ok" role="status">
          <b>{invited}</b> now has access. Add another, or continue.
        </div>
      )}

      <label className="field">
        <span className="field__label">
          Teammate's user ID{" "}
          <HelpTooltip title="User ID">
            The person's unique ID from your identity provider (the same system
            you connected earlier). It's not an email invite — the teammate must
            already exist in your identity provider; here you grant them a role
            in this workspace.
          </HelpTooltip>
        </span>
        <input
          value={userId}
          placeholder="e.g. iam-core user id"
          onChange={(e) => setUserId(e.target.value)}
        />
      </label>

      <label className="field">
        <span className="field__label">
          Their role{" "}
          <HelpTooltip title="Roles">
            <b>Operator</b>: an everyday user who requests access. <b>Admin</b>:
            manages connectors, rules, and members. <b>Auditor</b>: read-only
            for compliance. Pick the least access that lets them do their job.
          </HelpTooltip>
        </span>
        <select
          value={effectiveRole}
          onChange={(e) => setRole(e.target.value)}
          disabled={roles.isLoading || roleOptions.length === 0}
        >
          {roleOptions.map((r) => (
            <option key={r.role} value={r.role}>
              {titleCase(r.role)}
            </option>
          ))}
        </select>
      </label>

      {assignMut.isError && (
        <p className="form-error" role="alert">
          {assignMut.error.message}
        </p>
      )}

      <button
        className="btn btn--primary"
        disabled={!userId.trim() || !effectiveRole || assignMut.isPending}
        onClick={submit}
        style={{ marginTop: 4 }}
      >
        {assignMut.isPending ? "Adding…" : "Add teammate"}
      </button>

      <div className="onboard__actions">
        <button className="btn btn--ghost" onClick={onBack}>
          Back
        </button>
        <button className="btn btn--primary" onClick={onNext}>
          {invited || memberCount > 1 ? "Continue" : "Skip for now"}
        </button>
      </div>
    </Card>
  );
}

// --- Step 5: All set ------------------------------------------------------

function DoneStep({
  progress,
  onBack,
  onFinish,
}: {
  progress: OnboardingProgress;
  onBack: () => void;
  onFinish: () => void;
}) {
  // Reflect real, server-side state — not just which steps were clicked — so
  // the summary is honest about what actually exists.
  const connectors = useConnectors({});
  const policies = usePolicies();
  const canManage = useHasPermission(Perm.RbacManage);
  const members = useRbacMembers({ enabled: canManage });

  const connectedCount = (connectors.data ?? []).filter((c) => c.connected).length;
  const policyCount = policies.data?.length ?? 0;
  const memberCount = members.data?.length ?? 0;

  const items: { done: boolean; label: string }[] = [
    {
      done: connectedCount > 0,
      label:
        connectedCount > 0
          ? `Connected ${connectedCount} source${connectedCount === 1 ? "" : "s"}`
          : "Connect a source (you can do this any time)",
    },
    {
      done: policyCount > 0,
      label:
        policyCount > 0
          ? `Created ${policyCount} access rule${policyCount === 1 ? "" : "s"}`
          : "Write your first access rule",
    },
    {
      done: memberCount > 1,
      label:
        memberCount > 1
          ? `${memberCount} people in the workspace`
          : "Invite a teammate",
    },
  ];

  const hello = progress.workspaceName ? ` for ${progress.workspaceName}` : "";

  return (
    <Card
      title={`You're set up${hello}`}
      subtitle="Here's where things stand and what to do next."
    >
      <div className="done-summary">
        <div className="state__illustration" aria-hidden style={{ margin: "0 auto" }}>
          <EmptyIllustration kind="shield" />
        </div>
        <ul className="check-list">
          {items.map((it) => (
            <li key={it.label} className={it.done ? "check-list__item--done" : ""}>
              <span className="check-list__mark" aria-hidden>
                {it.done ? "✓" : "○"}
              </span>
              {it.label}
            </li>
          ))}
        </ul>
      </div>

      <h4 style={{ margin: "18px 0 6px" }}>What's next</h4>
      <ul className="done-links">
        <li>
          <Link to="/policies">Test &amp; promote your access rules</Link> — turn
          a draft into live protection.
        </li>
        <li>
          <Link to="/connectors">Connect more sources</Link> — add the apps and
          servers your team uses.
        </li>
        <li>
          <Link to="/requests">Review access requests</Link> — approve or deny
          what your team asks for.
        </li>
        <li>
          <Link to="/self-service">Self-service portal</Link> — what your team
          sees when they need access.
        </li>
      </ul>

      <div className="onboard__actions">
        <button className="btn btn--ghost" onClick={onBack}>
          Back
        </button>
        <button className="btn btn--primary" onClick={onFinish}>
          <Icon name="rocket" size={15} /> Go to dashboard
        </button>
      </div>
    </Card>
  );
}
