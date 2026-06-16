import { useEffect, useState } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import { Card, Badge, AsyncBoundary } from "@/components/ui";
import { HelpTooltip } from "@/components/HelpTooltip";
import { useToast } from "@/components/Toast";
import { ApiError, useAgents } from "@/api/access";
import {
  useAutoOnboardingPolicy,
  useSaveAutoOnboardingPolicy,
  type AutoOnboardRule,
  type PolicyView,
  type SavePolicyInput,
} from "@/api/discovery";

const PROTOCOL_OPTIONS = ["ssh", "rdp", "postgres", "mysql", "mssql"];

interface Draft {
  enabled: boolean;
  create_targets: boolean;
  default_agent_id: string;
  rules: AutoOnboardRule[];
  credential_username: string;
  credential_password: string;
  has_credential: boolean;
}

function toDraft(p: PolicyView): Draft {
  return {
    enabled: p.enabled,
    create_targets: p.create_targets,
    default_agent_id: p.default_agent_id ?? "",
    rules: p.rules ?? [],
    credential_username: p.credential_username ?? "",
    credential_password: "",
    has_credential: p.has_credential,
  };
}

/**
 * Auto-onboarding policy editor. Opt-in, OFF by default. Explains in plain
 * English exactly what it will and will not do: matching assets become managed
 * targets on each sweep, but standing access is never granted — leases stay
 * required (the require-lease boundary is pinned server-side).
 */
export function AutoOnboardingPolicyEditor() {
  const policyQ = useAutoOnboardingPolicy();
  return (
    <AsyncBoundary
      isLoading={policyQ.isLoading}
      error={policyQ.error}
      data={policyQ.data}
      onRetry={policyQ.refetch}
    >
      {(policy) => <PolicyForm policy={policy} />}
    </AsyncBoundary>
  );
}

function PolicyForm({ policy }: { policy: PolicyView }) {
  const intl = useIntl();
  const toast = useToast();
  const agentsQ = useAgents();
  const saveMut = useSaveAutoOnboardingPolicy();
  const [draft, setDraft] = useState<Draft>(() => toDraft(policy));

  // Re-seed when a save returns a fresh server view (e.g. updated_at).
  useEffect(() => {
    setDraft(toDraft(policy));
  }, [policy]);

  const agents = agentsQ.data ?? [];

  const addRule = () =>
    setDraft((d) => ({
      ...d,
      rules: [...d.rules, { name: "", protocols: [], cidrs: [] }],
    }));

  const updateRule = (i: number, patch: Partial<AutoOnboardRule>) =>
    setDraft((d) => ({
      ...d,
      rules: d.rules.map((r, idx) => (idx === i ? { ...r, ...patch } : r)),
    }));

  const removeRule = (i: number) =>
    setDraft((d) => ({ ...d, rules: d.rules.filter((_, idx) => idx !== i) }));

  const save = async () => {
    const body: SavePolicyInput = {
      enabled: draft.enabled,
      create_targets: draft.create_targets,
      default_agent_id: draft.default_agent_id || undefined,
      rules: draft.rules
        .map((r) => ({
          ...r,
          name: r.name.trim(),
          // Drop empty array fields so the rule stays compact.
          protocols: r.protocols?.filter(Boolean),
          cidrs: r.cidrs?.map((c) => c.trim()).filter(Boolean),
        }))
        .filter((r) => r.name),
    };
    // Only send a credential when the operator typed a new password; an empty
    // password with a username present clears the sealed credential.
    if (draft.credential_password.trim() || draft.credential_username.trim()) {
      body.credential = {
        username: draft.credential_username.trim(),
        password: draft.credential_password,
      };
    }
    try {
      await saveMut.mutateAsync(body);
      toast.success(
        intl.formatMessage({
          id: "discovery.policy.saved",
          defaultMessage: "Auto-onboarding policy saved",
        }),
      );
    } catch (err) {
      toast.error(
        intl.formatMessage({
          id: "discovery.policy.error",
          defaultMessage: "Could not save policy",
        }),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <Card
        title={intl.formatMessage({
          id: "discovery.policy.title",
          defaultMessage: "Auto-onboarding policy",
        })}
        subtitle={intl.formatMessage({
          id: "discovery.policy.subtitle",
          defaultMessage:
            "Automatically promote matching discovered assets to managed targets on each scheduled sweep.",
        })}
        actions={
          draft.enabled ? (
            <Badge tone="ok" dot>
              <FormattedMessage
                id="discovery.policy.on"
                defaultMessage="Enabled"
              />
            </Badge>
          ) : (
            <Badge tone="neutral">
              <FormattedMessage
                id="discovery.policy.off"
                defaultMessage="Disabled"
              />
            </Badge>
          )
        }
      >
        <div
          className="callout callout--info"
          style={{ marginBottom: 16 }}
          role="note"
        >
          <FormattedMessage
            id="discovery.policy.boundary"
            defaultMessage="Auto-onboarding only ever creates the managed target/record. It never grants standing privileged access — every session still flows through the normal request → approve → time-boxed lease path, recorded on the audit chain."
          />
        </div>

        <label
          className="field"
          style={{ flexDirection: "row", alignItems: "center", gap: 8 }}
        >
          <input
            type="checkbox"
            checked={draft.enabled}
            style={{ width: "auto" }}
            onChange={(e) =>
              setDraft({ ...draft, enabled: e.target.checked })
            }
          />
          <span>
            <FormattedMessage
              id="discovery.policy.enable"
              defaultMessage="Enable auto-onboarding for this workspace"
            />
          </span>
        </label>

        <label
          className="field"
          style={{ flexDirection: "row", alignItems: "center", gap: 8 }}
        >
          <input
            type="checkbox"
            checked={draft.create_targets}
            style={{ width: "auto" }}
            onChange={(e) =>
              setDraft({ ...draft, create_targets: e.target.checked })
            }
          />
          <span>
            <FormattedMessage
              id="discovery.policy.createTargets"
              defaultMessage="Create PAM targets for matches (off = flag only, no targets created)"
            />{" "}
            <HelpTooltip>
              <FormattedMessage
                id="discovery.policy.createTargets.help"
                defaultMessage="When off, matching assets are flagged as policy-matched for review but no target is created automatically — a safe way to preview what the policy would onboard."
              />
            </HelpTooltip>
          </span>
        </label>

        <div className="field-row">
          <label className="field">
            <span>
              <FormattedMessage
                id="discovery.policy.defaultAgent"
                defaultMessage="Default agent for auto-created targets"
              />
            </span>
            <select
              value={draft.default_agent_id}
              onChange={(e) =>
                setDraft({ ...draft, default_agent_id: e.target.value })
              }
            >
              <option value="">
                {intl.formatMessage({
                  id: "discovery.policy.agent.none",
                  defaultMessage: "None (direct)",
                })}
              </option>
              {agents.map((a) => (
                <option key={a.agent.id} value={a.agent.id}>
                  {a.agent.name}
                </option>
              ))}
            </select>
          </label>
        </div>
      </Card>

      <Card
        title={intl.formatMessage({
          id: "discovery.policy.credential.title",
          defaultMessage: "Onboarding credential",
        })}
        subtitle={intl.formatMessage({
          id: "discovery.policy.credential.subtitle",
          defaultMessage:
            "Sealed (AES-256-GCM) and attached to targets the policy creates. Leave blank to keep flagging without a credential.",
        })}
      >
        {draft.has_credential && (
          <p className="muted" style={{ fontSize: 12, marginTop: 0 }}>
            <FormattedMessage
              id="discovery.policy.credential.exists"
              defaultMessage="A sealed credential is already configured. Enter a new password to replace it."
            />
          </p>
        )}
        <div className="field-row">
          <label className="field">
            <span>
              <FormattedMessage
                id="discovery.policy.credential.username"
                defaultMessage="Username"
              />
            </span>
            <input
              value={draft.credential_username}
              onChange={(e) =>
                setDraft({ ...draft, credential_username: e.target.value })
              }
              placeholder="svc-onboard"
            />
          </label>
          <label className="field">
            <span>
              <FormattedMessage
                id="discovery.policy.credential.password"
                defaultMessage="Password / key"
              />
            </span>
            <input
              type="password"
              value={draft.credential_password}
              onChange={(e) =>
                setDraft({ ...draft, credential_password: e.target.value })
              }
              placeholder={
                draft.has_credential ? "••••••••" : intl.formatMessage({
                  id: "discovery.policy.credential.placeholder",
                  defaultMessage: "Set a credential",
                })
              }
            />
          </label>
        </div>
      </Card>

      <Card
        title={intl.formatMessage({
          id: "discovery.policy.rules.title",
          defaultMessage: "Match rules",
        })}
        subtitle={intl.formatMessage({
          id: "discovery.policy.rules.subtitle",
          defaultMessage:
            "An asset is auto-onboarded when it matches any rule. A rule matches when all of its set conditions hold.",
        })}
        actions={
          <button className="btn btn--sm" onClick={addRule}>
            <FormattedMessage
              id="discovery.policy.rules.add"
              defaultMessage="Add rule"
            />
          </button>
        }
      >
        {draft.rules.length === 0 ? (
          <p className="muted">
            <FormattedMessage
              id="discovery.policy.rules.empty"
              defaultMessage="No rules yet. Add a rule such as “SSH hosts in 10.0.0.0/24”."
            />
          </p>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            {draft.rules.map((rule, i) => (
              <div
                key={i}
                style={{
                  border: "1px solid var(--border-soft)",
                  borderRadius: 8,
                  padding: 14,
                  display: "flex",
                  flexDirection: "column",
                  gap: 10,
                }}
              >
                <div className="field-row">
                  <label className="field">
                    <span>
                      <FormattedMessage
                        id="discovery.policy.rule.name"
                        defaultMessage="Rule name"
                      />
                    </span>
                    <input
                      value={rule.name}
                      onChange={(e) =>
                        updateRule(i, { name: e.target.value })
                      }
                      placeholder="SSH in office subnet"
                    />
                  </label>
                  <label className="field">
                    <span>
                      <FormattedMessage
                        id="discovery.policy.rule.cidrs"
                        defaultMessage="CIDRs (comma-separated)"
                      />
                    </span>
                    <input
                      value={(rule.cidrs ?? []).join(", ")}
                      onChange={(e) =>
                        updateRule(i, {
                          cidrs: e.target.value.split(","),
                        })
                      }
                      placeholder="10.0.0.0/24"
                    />
                  </label>
                </div>
                <div>
                  <span
                    className="muted"
                    style={{ fontSize: 12, display: "block", marginBottom: 6 }}
                  >
                    <FormattedMessage
                      id="discovery.policy.rule.protocols"
                      defaultMessage="Protocols (none = any)"
                    />
                  </span>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    {PROTOCOL_OPTIONS.map((p) => {
                      const on = (rule.protocols ?? []).includes(p);
                      return (
                        <button
                          key={p}
                          type="button"
                          className={`btn btn--sm${on ? " btn--primary" : " btn--ghost"}`}
                          aria-pressed={on}
                          onClick={() =>
                            updateRule(i, {
                              protocols: on
                                ? (rule.protocols ?? []).filter(
                                    (x) => x !== p,
                                  )
                                : [...(rule.protocols ?? []), p],
                            })
                          }
                        >
                          {p}
                        </button>
                      );
                    })}
                  </div>
                </div>
                <div style={{ display: "flex", justifyContent: "flex-end" }}>
                  <button
                    className="btn btn--sm btn--ghost"
                    onClick={() => removeRule(i)}
                  >
                    <FormattedMessage
                      id="discovery.policy.rule.remove"
                      defaultMessage="Remove rule"
                    />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
        <button
          className="btn btn--primary"
          disabled={saveMut.isPending}
          onClick={save}
        >
          <FormattedMessage
            id="discovery.policy.save"
            defaultMessage="Save policy"
          />
        </button>
      </div>
    </div>
  );
}
