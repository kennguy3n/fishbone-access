import { useMemo, useState, type ReactNode } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useIntl, FormattedMessage } from "react-intl";
import { PageHeader, Card, Badge, LoadingState } from "@/components/ui";
import { EmptyIllustration } from "@/components/EmptyState";
import { HelpTooltip } from "@/components/HelpTooltip";
import { Icon } from "@/components/Icon";
import { useToast } from "@/components/Toast";
import {
  useMe,
  useMyPermissions,
  useConnectors,
  usePolicies,
  useCreatePolicy,
  useRbacRoles,
  useRbacMembers,
  useAssignRbacMember,
  type ConnectorCatalogueEntry,
  ApiError,
} from "@/api/access";
import { useHasPermission, isWorkspaceAdmin, Perm } from "@/lib/permissions";
import {
  ONBOARDING_STEPS,
  useOnboardingProgress,
  withCompleted,
  type OnboardingProgress,
  type OnboardingStepId,
} from "@/lib/onboarding-store";
import { titleCase } from "@/lib/format";
import "./lane-a1.css";

// Rich-text tags for inline emphasis inside localized copy.
const code = (chunks: ReactNode) => <code>{chunks}</code>;
const b = (chunks: ReactNode) => <b>{chunks}</b>;
const i = (chunks: ReactNode) => <i>{chunks}</i>;

// Message ids for the stepper labels. Kept here (not in the store) so the store
// stays presentation-free.
const STEP_LABELS: Record<OnboardingStepId, { id: string; defaultMessage: string }> =
  {
    welcome: { id: "onboarding.step.welcome", defaultMessage: "Welcome" },
    connect: { id: "onboarding.step.connect", defaultMessage: "Connect a source" },
    policy: { id: "onboarding.step.policy", defaultMessage: "First access rule" },
    invite: { id: "onboarding.step.invite", defaultMessage: "Invite a teammate" },
    done: { id: "onboarding.step.done", defaultMessage: "All set" },
  };

export function Onboarding() {
  const intl = useIntl();
  const me = useMe();
  const perms = useMyPermissions();
  // Resolve the bound tenant before mounting the wizard so the progress store
  // keys on the real tenant id from its first render (the persistence hook
  // initializes lazily and won't re-key afterwards).
  if (me.isLoading || perms.isLoading)
    return (
      <LoadingState
        label={intl.formatMessage({
          id: "onboarding.preparing",
          defaultMessage: "Preparing your setup…",
        })}
      />
    );
  // The wizard drives admin-only mutations and its nav entry is admin-only, but
  // a non-admin reaching /onboarding directly would otherwise see a wizard that
  // 403s on submit. Once permissions resolve and the caller isn't an admin,
  // send them to their self-service portal instead. (Permissions absent = an
  // unenforced RBAC tier → fail-open to the wizard, matching the server.)
  if (perms.data && !isWorkspaceAdmin(perms.data.permissions))
    return <SetupNotAvailable />;
  // key on tenant id so a (hypothetical) tenant change remounts the wizard and
  // its progress store re-hydrates for the new tenant — the store keys its
  // localStorage on tenant id and hydrates lazily, so it must never outlive the
  // tenant it was mounted for.
  const tenantId = me.data?.tenant_id ?? "";
  return <OnboardingWizard key={tenantId} tenantId={tenantId} />;
}

// Shown when a non-admin lands on /onboarding directly: day-1 setup is an admin
// task, so point them at the surface that is theirs rather than a wizard the
// server will reject.
function SetupNotAvailable() {
  const intl = useIntl();
  return (
    <div className="lane-a1">
      <PageHeader
        title={intl.formatMessage({
          id: "onboarding.title",
          defaultMessage: "Get started",
        })}
        subtitle={intl.formatMessage({
          id: "onboarding.notAvailable.subtitle",
          defaultMessage: "Guided setup is handled by a workspace admin.",
        })}
      />
      <Card
        title={intl.formatMessage({
          id: "onboarding.notAvailable.title",
          defaultMessage: "Setup is handled by an admin",
        })}
        subtitle={intl.formatMessage({
          id: "onboarding.notAvailable.cardSubtitle",
          defaultMessage: "Your role doesn't include workspace setup.",
        })}
      >
        <div className="callout callout--info" role="status">
          {intl.formatMessage({
            id: "onboarding.notAvailable.body",
            defaultMessage:
              "Connecting identity sources, writing access rules, and inviting people are admin tasks. You can request the access you need from your self-service area — no setup required.",
          })}
        </div>
        <div className="onboard__actions">
          <Link className="btn btn--primary" to="/self-service">
            {intl.formatMessage({
              id: "onboarding.notAvailable.cta",
              defaultMessage: "Go to your access",
            })}
          </Link>
        </div>
      </Card>
    </div>
  );
}

function OnboardingWizard({ tenantId }: { tenantId: string }) {
  const intl = useIntl();
  const navigate = useNavigate();
  const [progress, update] = useOnboardingProgress(tenantId);

  const stepIndex = Math.max(0, ONBOARDING_STEPS.indexOf(progress.lastStep));
  const step = ONBOARDING_STEPS[stepIndex];

  // Derive the next step + completed list from the latest state inside the
  // updater so rapid advances can't clobber each other's `completed` entries.
  const advance = () =>
    update((prev) => {
      const idx = Math.max(0, ONBOARDING_STEPS.indexOf(prev.lastStep));
      const next =
        ONBOARDING_STEPS[Math.min(idx + 1, ONBOARDING_STEPS.length - 1)];
      return {
        lastStep: next,
        completed: withCompleted(prev.completed, ONBOARDING_STEPS[idx]),
      };
    });
  // Derive the previous step from the latest state inside the updater (matching
  // advance()) so the two stay symmetric and back() can't act on a stale index.
  const back = () =>
    update((prev) => {
      const idx = Math.max(0, ONBOARDING_STEPS.indexOf(prev.lastStep));
      return { lastStep: ONBOARDING_STEPS[Math.max(idx - 1, 0)] };
    });

  return (
    <div className="lane-a1">
      <PageHeader
        title={intl.formatMessage({
          id: "onboarding.title",
          defaultMessage: "Get started",
        })}
        subtitle={intl.formatMessage({
          id: "onboarding.subtitle",
          defaultMessage:
            "A short, guided setup. You can leave and pick up where you left off — your progress on this browser is saved as you go.",
        })}
        actions={
          <Link className="btn btn--ghost btn--sm" to="/">
            {intl.formatMessage({
              id: "onboarding.skip",
              defaultMessage: "Skip for now",
            })}
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
        {step === "connect" && <ConnectStep onBack={back} onNext={advance} />}
        {step === "policy" && <PolicyStep onBack={back} onNext={advance} />}
        {step === "invite" && <InviteStep onBack={back} onNext={advance} />}
        {step === "done" && (
          <DoneStep
            progress={progress}
            onBack={back}
            onFinish={() => {
              update((prev) => ({
                finished: true,
                completed: withCompleted(prev.completed, "done"),
              }));
              navigate({ to: "/" });
            }}
          />
        )}
      </div>
    </div>
  );
}

function Stepper({
  current,
  completed,
}: {
  current: number;
  completed: OnboardingStepId[];
}) {
  const intl = useIntl();
  return (
    <ol
      className="stepper"
      aria-label={intl.formatMessage({
        id: "onboarding.stepper.label",
        defaultMessage: "Setup progress",
      })}
    >
      {ONBOARDING_STEPS.map((id, idx) => {
        const isActive = idx === current;
        const isDone = idx < current || completed.includes(id);
        const cls = `stepper__step${isActive ? " stepper__step--active" : ""}${
          isDone && !isActive ? " stepper__step--done" : ""
        }`;
        return (
          <li
            className={cls}
            key={id}
            aria-current={isActive ? "step" : undefined}
          >
            <span className="stepper__dot" aria-hidden>
              {isDone && !isActive ? "✓" : idx + 1}
            </span>
            <span className="stepper__name">
              {intl.formatMessage(STEP_LABELS[id])}
            </span>
            {idx < ONBOARDING_STEPS.length - 1 && (
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
  const intl = useIntl();
  return (
    <Card
      title={intl.formatMessage({
        id: "onboarding.welcome.title",
        defaultMessage: "Welcome to ShieldNet Access",
      })}
      subtitle={intl.formatMessage({
        id: "onboarding.welcome.subtitle",
        defaultMessage:
          "In a few minutes you'll connect where your team signs in, write your first access rule, and invite a colleague. No prior security experience needed.",
      })}
    >
      <div className="overview-anim" aria-hidden>
        <span className="overview-anim__node">
          {intl.formatMessage({
            id: "onboarding.welcome.diagram.people",
            defaultMessage: "Your people",
          })}
        </span>
        <span className="overview-anim__flow" />
        <span className="overview-anim__node overview-anim__node--sng">
          ShieldNet Access
        </span>
        <span className="overview-anim__flow" />
        <span className="overview-anim__node">
          {intl.formatMessage({
            id: "onboarding.welcome.diagram.apps",
            defaultMessage: "Your apps & servers",
          })}
        </span>
      </div>
      <p className="muted" style={{ maxWidth: "62ch" }}>
        {intl.formatMessage({
          id: "onboarding.welcome.body",
          defaultMessage:
            "ShieldNet sits between your people and the apps, servers, and databases they need. It grants access just-in-time — only when someone needs it, and only for as long as they need it — and keeps a record of every grant for you.",
        })}
      </p>

      <label className="field" style={{ marginTop: 8 }}>
        <span className="field__label">
          {intl.formatMessage({
            id: "onboarding.welcome.name.label",
            defaultMessage: "What should we call this workspace?",
          })}{" "}
          <HelpTooltip
            title={intl.formatMessage({
              id: "onboarding.welcome.name.helpTitle",
              defaultMessage: "Workspace name",
            })}
          >
            {intl.formatMessage({
              id: "onboarding.welcome.name.help",
              defaultMessage:
                "A friendly label just for you, shown in this console on this browser. It doesn't change anything on the server or how access works.",
            })}
          </HelpTooltip>
        </span>
        <input
          value={workspaceName}
          placeholder={intl.formatMessage({
            id: "onboarding.welcome.name.placeholder",
            defaultMessage: "e.g. Acme Corp",
          })}
          onChange={(e) => onName(e.target.value)}
        />
      </label>

      <dl className="kv" style={{ marginTop: 4 }}>
        <div>
          <dt>
            {intl.formatMessage({
              id: "onboarding.welcome.tenant.label",
              defaultMessage: "Your workspace ID",
            })}{" "}
            <HelpTooltip
              title={intl.formatMessage({
                id: "onboarding.welcome.tenant.helpTitle",
                defaultMessage: "Workspace ID",
              })}
            >
              {intl.formatMessage({
                id: "onboarding.welcome.tenant.help",
                defaultMessage:
                  "The private space your sign-in maps to. Everything you create here stays inside it and is never visible to anyone else.",
              })}
            </HelpTooltip>
          </dt>
          <dd>
            <code>{tenantId || "—"}</code>
          </dd>
        </div>
      </dl>

      <div className="onboard__actions">
        <button className="btn btn--primary" onClick={onNext}>
          {intl.formatMessage({
            id: "onboarding.welcome.cta",
            defaultMessage: "Let's go",
          })}
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
  return [...entries].sort((a, b2) => rank(a) - rank(b2)).slice(0, 6);
}

function ConnectStep({
  onBack,
  onNext,
}: {
  onBack: () => void;
  onNext: () => void;
}) {
  const intl = useIntl();
  const navigate = useNavigate();
  const { data, isLoading } = useConnectors({});
  const entries = useMemo(() => data ?? [], [data]);
  const connectedCount = entries.filter((e) => e.connected).length;
  const recommended = useMemo(() => recommendConnectors(entries), [entries]);
  const [selected, setSelected] = useState<string>("");
  const selectedEntry = entries.find((e) => e.provider === selected);

  return (
    <Card
      title={intl.formatMessage({
        id: "onboarding.connect.title",
        defaultMessage: "Connect where your team signs in",
      })}
      subtitle={intl.formatMessage({
        id: "onboarding.connect.subtitle",
        defaultMessage:
          "Link an identity source (like Google Workspace, Okta, or Microsoft Entra) or an app. ShieldNet uses it to know who your people are — it never stores their passwords.",
      })}
    >
      {connectedCount > 0 && (
        <div className="callout callout--ok" role="status">
          {intl.formatMessage(
            {
              id: "onboarding.connect.connectedCount",
              defaultMessage:
                "{count, plural, one {# source connected. You can connect more, or continue.} other {# sources connected. You can connect more, or continue.}}",
            },
            { count: connectedCount },
          )}
        </div>
      )}

      <div className="explainer">
        <p className="muted" style={{ maxWidth: "64ch" }}>
          {intl.formatMessage({
            id: "onboarding.connect.explainer.intro",
            defaultMessage:
              "To connect a source you'll usually paste one credential from it:",
          })}
        </p>
        <ul className="explainer__list">
          <li>
            <FormattedMessage
              id="onboarding.connect.explainer.oauth"
              defaultMessage="an <b>app connection</b>, or"
              values={{ b }}
            />{" "}
            <HelpTooltip
              title={intl.formatMessage({
                id: "onboarding.connect.oauth.helpTitle",
                defaultMessage: "App connection (OAuth client)",
              })}
            >
              <FormattedMessage
                id="onboarding.connect.oauth.help"
                defaultMessage="A small ‘app registration’ you create inside your provider (e.g. Google or Microsoft). It produces a <i>client ID</i> and <i>client secret</i> that let ShieldNet read your users on your behalf — without ever seeing anyone's password. You'll usually find it under ‘APIs & Services’, ‘App registrations’, or ‘Developer’ settings."
                values={{ i }}
              />
            </HelpTooltip>
          </li>
          <li>
            <FormattedMessage
              id="onboarding.connect.explainer.token"
              defaultMessage="an <b>API token</b>."
              values={{ b }}
            />{" "}
            <HelpTooltip
              title={intl.formatMessage({
                id: "onboarding.connect.token.helpTitle",
                defaultMessage: "API token",
              })}
            >
              {intl.formatMessage({
                id: "onboarding.connect.token.help",
                defaultMessage:
                  "A long secret string the provider generates for you (sometimes called an ‘API key’ or ‘service token’). Copy it once when you create it and paste it into the guided setup — the provider often won't show it again, so keep it handy.",
              })}
            </HelpTooltip>
          </li>
        </ul>
        <p className="muted" style={{ maxWidth: "64ch" }}>
          {intl.formatMessage({
            id: "onboarding.connect.explainer.outro",
            defaultMessage:
              "Don't have one yet? Pick your provider below — the guided setup walks you through exactly where to find it, step by step.",
          })}
        </p>
      </div>

      {isLoading ? (
        <LoadingState
          label={intl.formatMessage({
            id: "onboarding.connect.loading",
            defaultMessage: "Loading providers…",
          })}
        />
      ) : recommended.length === 0 ? (
        <p className="muted">
          {intl.formatMessage({
            id: "onboarding.connect.none",
            defaultMessage: "No providers are available in this deployment.",
          })}
        </p>
      ) : (
        <div
          className="choice-grid"
          role="radiogroup"
          aria-label={intl.formatMessage({
            id: "onboarding.connect.recommended",
            defaultMessage: "Recommended providers",
          })}
        >
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
                      {intl.formatMessage({
                        id: "onboarding.connect.connected",
                        defaultMessage: "Connected",
                      })}
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
        <div
          className="callout callout--info"
          role="status"
          style={{ marginTop: 12 }}
        >
          {intl.formatMessage(
            {
              id: "onboarding.connect.selectedHint",
              defaultMessage:
                "<b>{name}</b> — the guided setup explains exactly what to allow and the common mistakes to avoid, then checks the connection before anything syncs.",
            },
            { name: selectedEntry.display_name, b },
          )}
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
              {intl.formatMessage(
                {
                  id: "onboarding.connect.openGuided",
                  defaultMessage: "Open guided setup for {name}",
                },
                { name: selectedEntry.display_name },
              )}
            </button>
          </div>
        </div>
      )}

      <p className="muted" style={{ fontSize: 12, marginTop: 12 }}>
        <FormattedMessage
          id="onboarding.connect.browseAll"
          defaultMessage="Looking for a different provider? <a>Browse all connectors</a>."
          values={{
            a: (chunks) => <Link to="/connectors">{chunks}</Link>,
          }}
        />
      </p>

      <div className="onboard__actions">
        <button className="btn btn--ghost" onClick={onBack}>
          {intl.formatMessage({
            id: "onboarding.back",
            defaultMessage: "Back",
          })}
        </button>
        <button className="btn btn--primary" onClick={onNext}>
          {connectedCount > 0
            ? intl.formatMessage({
                id: "onboarding.continue",
                defaultMessage: "Continue",
              })
            : intl.formatMessage({
                id: "onboarding.skip",
                defaultMessage: "Skip for now",
              })}
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
  const intl = useIntl();
  const toast = useToast();
  const policies = usePolicies();
  const createMut = useCreatePolicy();
  const [subjects, setSubjects] = useState("");
  const [resources, setResources] = useState("");
  const [role, setRole] = useState("");
  const [createdName, setCreatedName] = useState<string | null>(null);

  const policyCount = policies.data?.length ?? 0;
  const subjectList = subjects.split(",").map((s) => s.trim()).filter(Boolean);
  const resourceList = resources
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
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
      toast.success(
        intl.formatMessage({
          id: "onboarding.policy.toast.title",
          defaultMessage: "Draft access rule created",
        }),
        intl.formatMessage({
          id: "onboarding.policy.toast.body",
          defaultMessage: "Test it, then turn it on to go live.",
        }),
      );
    } catch (err) {
      toast.error(
        intl.formatMessage({
          id: "onboarding.policy.toast.error",
          defaultMessage: "We couldn't create the rule",
        }),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  return (
    <Card
      title={intl.formatMessage({
        id: "onboarding.policy.title",
        defaultMessage: "Write your first access rule",
      })}
      subtitle={intl.formatMessage({
        id: "onboarding.policy.subtitle",
        defaultMessage:
          "A rule says who can reach what. Nothing is enforced until you test it and turn it on — so it's safe to create one now.",
      })}
    >
      {policyCount > 0 && createdName === null && (
        <div className="callout callout--ok" role="status">
          {intl.formatMessage(
            {
              id: "onboarding.policy.existing",
              defaultMessage:
                "{count, plural, one {You already have # access rule. You can add another, or continue.} other {You already have # access rules. You can add another, or continue.}}",
            },
            { count: policyCount },
          )}
        </div>
      )}

      {createdName ? (
        <div className="callout callout--ok" role="status">
          <FormattedMessage
            id="onboarding.policy.created"
            defaultMessage="<b>Created.</b> Your draft rule “{name}” is saved. Next, open it to <a>test and turn it on</a> — that's when it starts protecting access."
            values={{
              name: createdName,
              b,
              a: (chunks) => <Link to="/policies">{chunks}</Link>,
            }}
          />
        </div>
      ) : (
        <>
          <label className="field">
            <span className="field__label">
              {intl.formatMessage({
                id: "onboarding.policy.who.label",
                defaultMessage: "Who should get access?",
              })}{" "}
              <HelpTooltip
                title={intl.formatMessage({
                  id: "onboarding.policy.who.helpTitle",
                  defaultMessage: "Who",
                })}
              >
                <FormattedMessage
                  id="onboarding.policy.who.help"
                  defaultMessage="A group or person from your connected source — for example a group name like <code>group:engineering</code> or a single user. Separate multiple with commas."
                  values={{ code }}
                />
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
              {intl.formatMessage({
                id: "onboarding.policy.what.label",
                defaultMessage: "What can they reach?",
              })}{" "}
              <HelpTooltip
                title={intl.formatMessage({
                  id: "onboarding.policy.what.helpTitle",
                  defaultMessage: "What",
                })}
              >
                <FormattedMessage
                  id="onboarding.policy.what.help"
                  defaultMessage="The app, server, or database this rule covers — for example <code>app:salesforce</code> or <code>host:10.0.0.0/24</code>. Separate multiple with commas."
                  values={{ code }}
                />
              </HelpTooltip>
            </span>
            <input
              value={resources}
              placeholder="app:salesforce, host:db-prod"
              onChange={(e) => setResources(e.target.value)}
            />
          </label>

          <details className="disclosure">
            <summary>
              {intl.formatMessage({
                id: "onboarding.policy.advanced",
                defaultMessage: "Advanced options",
              })}
            </summary>
            <label className="field" style={{ marginTop: 10 }}>
              <span className="field__label">
                {intl.formatMessage({
                  id: "onboarding.policy.role.label",
                  defaultMessage: "Level of access (optional)",
                })}{" "}
                <HelpTooltip
                  title={intl.formatMessage({
                    id: "onboarding.policy.role.helpTitle",
                    defaultMessage: "Access level",
                  })}
                >
                  <FormattedMessage
                    id="onboarding.policy.role.help"
                    defaultMessage="The level of access this rule grants on the target, such as <code>viewer</code> or <code>admin</code>. Leave blank if your target doesn't use levels."
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
                  id: "onboarding.policy.creating",
                  defaultMessage: "Creating…",
                })
              : intl.formatMessage({
                  id: "onboarding.policy.create",
                  defaultMessage: "Create draft rule",
                })}
          </button>
        </>
      )}

      <div className="onboard__actions">
        <button className="btn btn--ghost" onClick={onBack}>
          {intl.formatMessage({ id: "onboarding.back", defaultMessage: "Back" })}
        </button>
        <button className="btn btn--primary" onClick={onNext}>
          {createdName || policyCount > 0
            ? intl.formatMessage({
                id: "onboarding.continue",
                defaultMessage: "Continue",
              })
            : intl.formatMessage({
                id: "onboarding.skip",
                defaultMessage: "Skip for now",
              })}
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
  const intl = useIntl();
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
    role ||
    roleOptions.find((r) => r.role !== "owner")?.role ||
    roleOptions[0]?.role ||
    "";

  const memberCount = members.data?.length ?? 0;

  const submit = async () => {
    const uid = userId.trim();
    if (!uid || !effectiveRole) return;
    try {
      await assignMut.mutateAsync({ userId: uid, role: effectiveRole });
      setInvited(uid);
      toast.success(
        intl.formatMessage({
          id: "onboarding.invite.toast.title",
          defaultMessage: "Teammate added",
        }),
        intl.formatMessage(
          {
            id: "onboarding.invite.toast.body",
            defaultMessage: "Given the {role} role.",
          },
          { role: effectiveRole },
        ),
      );
      setUserId("");
    } catch (err) {
      toast.error(
        intl.formatMessage({
          id: "onboarding.invite.toast.error",
          defaultMessage: "We couldn't add your teammate",
        }),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  if (!canManage) {
    return (
      <Card
        title={intl.formatMessage({
          id: "onboarding.invite.title",
          defaultMessage: "Invite a teammate",
        })}
        subtitle={intl.formatMessage({
          id: "onboarding.invite.subtitle.short",
          defaultMessage: "Bring a colleague into this workspace.",
        })}
      >
        <div className="callout callout--info" role="status">
          {intl.formatMessage({
            id: "onboarding.invite.noPermission",
            defaultMessage:
              "Inviting teammates needs permission to manage members, which your current role doesn't have. Ask your workspace owner to add people, or continue — you can always do this later.",
          })}
        </div>
        <div className="onboard__actions">
          <button className="btn btn--ghost" onClick={onBack}>
            {intl.formatMessage({
              id: "onboarding.back",
              defaultMessage: "Back",
            })}
          </button>
          <button className="btn btn--primary" onClick={onNext}>
            {intl.formatMessage({
              id: "onboarding.continue",
              defaultMessage: "Continue",
            })}
          </button>
        </div>
      </Card>
    );
  }

  return (
    <Card
      title={intl.formatMessage({
        id: "onboarding.invite.title",
        defaultMessage: "Invite a teammate",
      })}
      subtitle={intl.formatMessage({
        id: "onboarding.invite.subtitle",
        defaultMessage:
          "Give a colleague the right level of access to this workspace. They sign in with your identity provider — you just choose their role here.",
      })}
    >
      {memberCount > 0 && (
        <div className="callout callout--ok" role="status">
          {intl.formatMessage(
            {
              id: "onboarding.invite.memberCount",
              defaultMessage:
                "{count, plural, one {# person in this workspace.} other {# people in this workspace.}}",
            },
            { count: memberCount },
          )}
        </div>
      )}

      {invited && (
        <div className="callout callout--ok" role="status">
          <FormattedMessage
            id="onboarding.invite.added"
            defaultMessage="<b>{user}</b> now has access. Add another, or continue."
            values={{ user: invited, b }}
          />
        </div>
      )}

      <label className="field">
        <span className="field__label">
          {intl.formatMessage({
            id: "onboarding.invite.user.label",
            defaultMessage: "Teammate's user ID",
          })}{" "}
          <HelpTooltip
            title={intl.formatMessage({
              id: "onboarding.invite.user.helpTitle",
              defaultMessage: "User ID",
            })}
          >
            {intl.formatMessage({
              id: "onboarding.invite.user.help",
              defaultMessage:
                "The person's unique ID from your identity provider (the same system you connected earlier). This isn't an email invite — the teammate must already exist in your identity provider; here you give them a role in this workspace.",
            })}
          </HelpTooltip>
        </span>
        <input
          value={userId}
          placeholder={intl.formatMessage({
            id: "onboarding.invite.user.placeholder",
            defaultMessage: "Paste their user ID",
          })}
          onChange={(e) => setUserId(e.target.value)}
        />
      </label>

      <label className="field">
        <span className="field__label">
          {intl.formatMessage({
            id: "onboarding.invite.role.label",
            defaultMessage: "Their role",
          })}{" "}
          <HelpTooltip
            title={intl.formatMessage({
              id: "onboarding.invite.role.helpTitle",
              defaultMessage: "Roles",
            })}
          >
            <FormattedMessage
              id="onboarding.invite.role.help"
              defaultMessage="<b>Operator</b>: an everyday user who requests access. <b>Admin</b>: manages connectors, rules, and members. <b>Auditor</b>: read-only for compliance. Pick the least access that lets them do their job."
              values={{ b }}
            />
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
        {assignMut.isPending
          ? intl.formatMessage({
              id: "onboarding.invite.adding",
              defaultMessage: "Adding…",
            })
          : intl.formatMessage({
              id: "onboarding.invite.add",
              defaultMessage: "Add teammate",
            })}
      </button>

      <div className="onboard__actions">
        <button className="btn btn--ghost" onClick={onBack}>
          {intl.formatMessage({ id: "onboarding.back", defaultMessage: "Back" })}
        </button>
        <button className="btn btn--primary" onClick={onNext}>
          {invited || memberCount > 1
            ? intl.formatMessage({
                id: "onboarding.continue",
                defaultMessage: "Continue",
              })
            : intl.formatMessage({
                id: "onboarding.skip",
                defaultMessage: "Skip for now",
              })}
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
  const intl = useIntl();
  // Reflect real, server-side state — not just which steps were clicked — so
  // the summary is honest about what actually exists.
  const connectors = useConnectors({});
  const policies = usePolicies();
  const canManage = useHasPermission(Perm.RbacManage);
  const members = useRbacMembers({ enabled: canManage });

  const connectedCount = (connectors.data ?? []).filter(
    (c) => c.connected,
  ).length;
  const policyCount = policies.data?.length ?? 0;
  const memberCount = members.data?.length ?? 0;

  const items: { done: boolean; label: string }[] = [
    {
      done: connectedCount > 0,
      label:
        connectedCount > 0
          ? intl.formatMessage(
              {
                id: "onboarding.done.connected",
                defaultMessage:
                  "{count, plural, one {Connected # source} other {Connected # sources}}",
              },
              { count: connectedCount },
            )
          : intl.formatMessage({
              id: "onboarding.done.connectTodo",
              defaultMessage: "Connect a source (you can do this any time)",
            }),
    },
    {
      done: policyCount > 0,
      label:
        policyCount > 0
          ? intl.formatMessage(
              {
                id: "onboarding.done.policies",
                defaultMessage:
                  "{count, plural, one {Created # access rule} other {Created # access rules}}",
              },
              { count: policyCount },
            )
          : intl.formatMessage({
              id: "onboarding.done.policyTodo",
              defaultMessage: "Write your first access rule",
            }),
    },
  ];
  // Only summarize membership when this admin can actually manage it — the
  // member count query is gated on the same permission, so for an admin without
  // it the count would always read 0 and falsely show "Invite a teammate" as
  // unfinished. InviteStep already steers those admins to their owner.
  if (canManage) {
    items.push({
      done: memberCount > 1,
      label:
        memberCount > 1
          ? intl.formatMessage(
              {
                id: "onboarding.done.members",
                defaultMessage: "{count} people in the workspace",
              },
              { count: memberCount },
            )
          : intl.formatMessage({
              id: "onboarding.done.inviteTodo",
              defaultMessage: "Invite a teammate",
            }),
    });
  }

  return (
    <Card
      title={
        progress.workspaceName
          ? intl.formatMessage(
              {
                id: "onboarding.done.titleNamed",
                defaultMessage: "You're set up for {name}",
              },
              { name: progress.workspaceName },
            )
          : intl.formatMessage({
              id: "onboarding.done.title",
              defaultMessage: "You're all set",
            })
      }
      subtitle={intl.formatMessage({
        id: "onboarding.done.subtitle",
        defaultMessage: "Here's where things stand and what to do next.",
      })}
    >
      <div className="done-summary">
        <div
          className="state__illustration"
          aria-hidden
          style={{ margin: "0 auto" }}
        >
          <EmptyIllustration kind="shield" />
        </div>
        <ul className="check-list">
          {items.map((it) => (
            <li
              key={it.label}
              className={it.done ? "check-list__item--done" : ""}
            >
              <span className="check-list__mark" aria-hidden>
                {it.done ? "✓" : "○"}
              </span>
              {it.label}
            </li>
          ))}
        </ul>
      </div>

      <h4 style={{ margin: "18px 0 6px" }}>
        {intl.formatMessage({
          id: "onboarding.done.whatsNext",
          defaultMessage: "What's next",
        })}
      </h4>
      <ul className="done-links">
        <li>
          <FormattedMessage
            id="onboarding.done.link.policies"
            defaultMessage="<a>Test & turn on your access rules</a> — turn a draft into live protection."
            values={{ a: (chunks) => <Link to="/policies">{chunks}</Link> }}
          />
        </li>
        <li>
          <FormattedMessage
            id="onboarding.done.link.connectors"
            defaultMessage="<a>Connect more sources</a> — add the apps and servers your team uses."
            values={{ a: (chunks) => <Link to="/connectors">{chunks}</Link> }}
          />
        </li>
        <li>
          <FormattedMessage
            id="onboarding.done.link.requests"
            defaultMessage="<a>Review access requests</a> — approve or decline what your team asks for."
            values={{ a: (chunks) => <Link to="/requests">{chunks}</Link> }}
          />
        </li>
        <li>
          <FormattedMessage
            id="onboarding.done.link.selfService"
            defaultMessage="<a>Self-service area</a> — what your team sees when they need access."
            values={{ a: (chunks) => <Link to="/self-service">{chunks}</Link> }}
          />
        </li>
      </ul>

      <div className="onboard__actions">
        <button className="btn btn--ghost" onClick={onBack}>
          {intl.formatMessage({ id: "onboarding.back", defaultMessage: "Back" })}
        </button>
        <button className="btn btn--primary" onClick={onFinish}>
          <Icon name="rocket" size={15} />{" "}
          {intl.formatMessage({
            id: "onboarding.done.cta",
            defaultMessage: "Go to dashboard",
          })}
        </button>
      </div>
    </Card>
  );
}
