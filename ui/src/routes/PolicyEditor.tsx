import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useIntl, type IntlShape } from "react-intl";
import { useLaneA5Scope } from "./lane-a5";
import { PageHeader, Card, Badge, StatusBadge, Spinner } from "@/components/ui";
import { Modal } from "@/components/Modal";
import { HelpTooltip } from "@/components/HelpTooltip";
import { useToast } from "@/components/Toast";
import {
  usePolicy,
  useCreatePolicy,
  useUpdatePolicy,
  useSimulatePolicy,
  usePromotePolicy,
  useArchivePolicy,
  type Policy,
  type PolicyAction,
  type PolicyConflict,
  type PolicyDefinition,
  type PromoteInput,
  type SimulationResult,
  ApiError,
} from "@/api/access";
import { formatDateTime } from "@/lib/format";

// The promote route's middleware chain is RequirePermission -> RequireMFA ->
// RequireStepUpMFA -> handler, so THREE distinct auth failures can come back and
// must be told apart by their exact server messages, not a loose /step-up mfa/
// match (which collides across all three and caused an infinite TOTP prompt):
//   - RequireStepUpMFA, missing header  -> 400 "step-up MFA assertion required"
//   - RequireStepUpMFA, wrong/replayed  -> 403 "step-up MFA verification failed"
//   - RequireMFA, JWT lacks the claim   -> 403 "step-up MFA required"
// Only the first two are answered with the TOTP modal; the third means the
// session itself needs MFA re-authentication, so prompting for a code would loop
// forever (the header never satisfies the JWT-claim gate). Anchored phrases keep
// each predicate disjoint.
const isStepUpRequired = (err: ApiError) =>
  err.status === 400 && /step-up mfa assertion required/i.test(err.message);
const isStepUpFailed = (err: ApiError) =>
  err.status === 403 && /step-up mfa verification failed/i.test(err.message);
const isSessionMfaRequired = (err: ApiError) =>
  err.status === 403 && /^step-up mfa required$/i.test(err.message.trim());

// Subject/resource entry prefixes the operator can pick from. The backend
// treats these as opaque refs (cartesian product of subjects × resources); the
// prefixes are a usability affordance so SME admins build "team:… → app:…"
// rules without memorizing a syntax.
const SUBJECT_HINTS = ["user:", "team:", "contractor:", "group:", "role:"];
const RESOURCE_HINTS = ["app:", "host:", "service:", "db:", "*"];

interface DraftForm {
  name: string;
  action: PolicyAction;
  role: string;
  subjects: string[];
  resources: string[];
}

const emptyForm: DraftForm = {
  name: "",
  action: "grant",
  role: "",
  subjects: [],
  resources: [],
};

function formFromPolicy(p: Policy): DraftForm {
  return {
    name: p.name,
    action: p.definition.action,
    role: p.definition.role ?? "",
    subjects: [...p.definition.subjects],
    resources: [...p.definition.resources],
  };
}

function toDefinition(f: DraftForm): PolicyDefinition {
  return {
    action: f.action,
    subjects: f.subjects,
    resources: f.resources,
    ...(f.role.trim() ? { role: f.role.trim() } : {}),
  };
}

/** Tag-style multi-value entry: type a value, Enter/comma to commit, × to remove. */
function ChipInput({
  label,
  values,
  onChange,
  placeholder,
  hints,
  disabled,
  invalidHint,
}: {
  label: string;
  values: string[];
  onChange: (next: string[]) => void;
  placeholder: string;
  hints: string[];
  disabled?: boolean;
  invalidHint?: string;
}) {
  const intl = useIntl();
  const [draft, setDraft] = useState("");
  const listId = useMemo(
    () => `hints-${label.replace(/\s+/g, "-").toLowerCase()}`,
    [label],
  );

  const commit = (raw: string) => {
    const v = raw.trim().replace(/,$/, "").trim();
    if (!v) return;
    if (!values.includes(v)) onChange([...values, v]);
    setDraft("");
  };

  return (
    <label className="field">
      <span>{label}</span>
      <div className={`chip-input${disabled ? " is-disabled" : ""}`}>
        {values.map((v) => (
          <span className="chip" key={v}>
            {v}
            {!disabled && (
              <button
                type="button"
                className="chip__remove"
                aria-label={intl.formatMessage(
                  { id: "policyEditor.chip.remove", defaultMessage: "Remove {v}" },
                  { v },
                )}
                onClick={() => onChange(values.filter((x) => x !== v))}
              >
                ✕
              </button>
            )}
          </span>
        ))}
        {!disabled && (
          <input
            value={draft}
            list={listId}
            placeholder={values.length === 0 ? placeholder : ""}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === ",") {
                e.preventDefault();
                commit(draft);
              } else if (
                e.key === "Backspace" &&
                draft === "" &&
                values.length
              ) {
                onChange(values.slice(0, -1));
              }
            }}
            onBlur={() => commit(draft)}
          />
        )}
        <datalist id={listId}>
          {hints.map((h) => (
            <option key={h} value={h} />
          ))}
        </datalist>
      </div>
      {invalidHint && <span className="field__error">{invalidHint}</span>}
    </label>
  );
}

function ConflictTable({ conflicts }: { conflicts: PolicyConflict[] }) {
  const intl = useIntl();
  return (
    <table className="data">
      <thead>
        <tr>
          <th>
            {intl.formatMessage({
              id: "policyEditor.conflict.col.type",
              defaultMessage: "Type",
            })}
          </th>
          <th>
            {intl.formatMessage({
              id: "policyEditor.conflict.col.subject",
              defaultMessage: "Subject",
            })}
          </th>
          <th>
            {intl.formatMessage({
              id: "policyEditor.conflict.col.resource",
              defaultMessage: "Resource",
            })}
          </th>
          <th>
            {intl.formatMessage({
              id: "policyEditor.conflict.col.policy",
              defaultMessage: "Conflicting policy",
            })}
          </th>
        </tr>
      </thead>
      <tbody>
        {conflicts.map((c, i) => (
          <tr key={`${c.other_policy_id}-${c.subject}-${c.resource}-${i}`}>
            <td>
              <Badge tone={c.kind === "grant_vs_deny" ? "danger" : "warn"}>
                {c.kind === "grant_vs_deny"
                  ? intl.formatMessage({
                      id: "policyEditor.conflict.kind.grantVsDeny",
                      defaultMessage: "Grant vs deny",
                    })
                  : intl.formatMessage({
                      id: "policyEditor.conflict.kind.redundant",
                      defaultMessage: "Redundant",
                    })}
              </Badge>
            </td>
            <td>
              <code>{c.subject}</code>
            </td>
            <td>
              <code>{c.resource}</code>
            </td>
            <td>
              {c.other_policy_name}{" "}
              <span className="muted">({c.other_policy_state})</span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function PolicyEditor() {
  useLaneA5Scope();
  const intl = useIntl();
  const params = useParams({ strict: false }) as { policyId?: string };
  const policyId = params.policyId;
  const isNew = !policyId;
  const navigate = useNavigate();
  const toast = useToast();

  const policyQuery = usePolicy(policyId);
  const policy = policyQuery.data;
  const isDraft = isNew || policy?.state === "draft";

  const [form, setForm] = useState<DraftForm>(emptyForm);
  // Baseline = the last-persisted definition+name. Used for dirty detection so
  // we know whether the stored draft matches what's on screen (Simulate/Promote
  // act on the *stored* draft, so edits must be saved first).
  const baselineRef = useRef<string>(JSON.stringify(emptyForm));
  const [sim, setSim] = useState<SimulationResult | null>(null);
  const [overrideOpen, setOverrideOpen] = useState(false);
  const [overrideReason, setOverrideReason] = useState("");
  // Step-up MFA prompt: the promote route is gated by RequireStepUpMFA, so a
  // promotion with no fresh assertion returns 400 and we collect a TOTP code
  // here. pendingPromote remembers the conflict-override context so the retry
  // carries the same force/reason as the original attempt.
  const [mfaOpen, setMfaOpen] = useState(false);
  const [mfaCode, setMfaCode] = useState("");
  const [mfaError, setMfaError] = useState<string | null>(null);
  const [pendingPromote, setPendingPromote] = useState<{
    force: boolean;
    reason?: string;
  }>({ force: false });

  // Hydrate the form from the loaded policy once (and whenever the server's
  // version changes, e.g. after a save), but only when the user hasn't got
  // unsaved edits in flight that we'd clobber.
  const loadedVersionRef = useRef<string | null>(null);
  useEffect(() => {
    if (!policy) return;
    const stamp = `${policy.id}@${policy.version}:${policy.updated_at}`;
    if (loadedVersionRef.current === stamp) return;
    loadedVersionRef.current = stamp;
    const next = formFromPolicy(policy);
    setForm(next);
    baselineRef.current = JSON.stringify(next);
    // A fresh load/refetch reflects the server's draft_impact, so drop any
    // stale local simulation snapshot that no longer matches.
    setSim(null);
  }, [policy]);

  const dirty = JSON.stringify(form) !== baselineRef.current;
  const valid =
    form.name.trim().length > 0 &&
    form.subjects.length > 0 &&
    form.resources.length > 0;

  // "Tested since last edit": the server stamps draft_impact on a successful
  // Simulate and clears it on any edit. That flag — not the local sim snapshot
  // — is the source of truth the Promote gate (and the backend) rely on.
  const simulatedSinceEdit = isNew ? false : !!policy?.draft_impact && !dirty;
  const hardConflicts = (sim?.conflicts ?? []).filter(
    (c) => c.kind === "grant_vs_deny",
  );
  const canPromote = isDraft && simulatedSinceEdit && !dirty;

  const createMut = useCreatePolicy();
  const updateMut = useUpdatePolicy(policyId ?? "");
  const simulateMut = useSimulatePolicy(policyId ?? "");
  const promoteMut = usePromotePolicy(policyId ?? "");
  const archiveMut = useArchivePolicy(policyId ?? "");

  const save = async () => {
    if (!valid) return;
    const body = { name: form.name.trim(), definition: toDefinition(form) };
    try {
      if (isNew) {
        const created = await createMut.mutateAsync(body);
        toast.success(
          intl.formatMessage({
            id: "policyEditor.toast.created",
            defaultMessage: "Draft created",
          }),
          intl.formatMessage({
            id: "policyEditor.toast.createdBody",
            defaultMessage: "Now simulate it before rolling out.",
          }),
        );
        navigate({
          to: "/policies/$policyId",
          params: { policyId: created.id },
        });
      } else {
        await updateMut.mutateAsync(body);
        baselineRef.current = JSON.stringify(form);
        setSim(null);
        toast.info(
          intl.formatMessage({
            id: "policyEditor.toast.saved",
            defaultMessage: "Draft saved",
          }),
          intl.formatMessage({
            id: "policyEditor.toast.savedBody",
            defaultMessage:
              "Editing cleared the previous test — simulate again before rollout.",
          }),
        );
      }
    } catch (err) {
      toast.error(
        intl.formatMessage({
          id: "policyEditor.toast.saveError",
          defaultMessage: "Could not save draft",
        }),
        errMessage(err, intl),
      );
    }
  };

  const simulate = async () => {
    if (!policyId) return;
    try {
      const result = await simulateMut.mutateAsync();
      setSim(result);
      const hard = result.conflicts.filter(
        (c) => c.kind === "grant_vs_deny",
      ).length;
      if (hard > 0) {
        toast.info(
          intl.formatMessage({
            id: "policyEditor.toast.simComplete",
            defaultMessage: "Simulation complete",
          }),
          intl.formatMessage(
            {
              id: "policyEditor.toast.simConflicts",
              defaultMessage:
                "{n, plural, one {# grant-vs-deny conflict} other {# grant-vs-deny conflicts}} found — resolve or override to promote.",
            },
            { n: hard },
          ),
        );
      } else {
        toast.success(
          intl.formatMessage({
            id: "policyEditor.toast.simComplete",
            defaultMessage: "Simulation complete",
          }),
          intl.formatMessage({
            id: "policyEditor.toast.simClean",
            defaultMessage:
              "No blocking conflicts. This draft is ready to promote.",
          }),
        );
      }
    } catch (err) {
      toast.error(
        intl.formatMessage({
          id: "policyEditor.toast.simError",
          defaultMessage: "Simulation failed",
        }),
        errMessage(err, intl),
      );
    }
  };

  const promote = async (
    force = false,
    reason?: string,
    mfaAssertion?: string,
  ) => {
    if (!policyId) return;
    try {
      const input: PromoteInput = {};
      if (force) {
        input.force = true;
        input.reason = reason;
      }
      if (mfaAssertion) input.mfaAssertion = mfaAssertion;
      await promoteMut.mutateAsync(
        Object.keys(input).length > 0 ? input : undefined,
      );
      toast.success(
        intl.formatMessage({
          id: "policyEditor.toast.promoted",
          defaultMessage: "Policy promoted",
        }),
        force
          ? intl.formatMessage({
              id: "policyEditor.toast.promotedForce",
              defaultMessage: "Promoted with an audited conflict override.",
            })
          : intl.formatMessage({
              id: "policyEditor.toast.promotedLive",
              defaultMessage: "This policy is now live.",
            }),
      );
      setOverrideOpen(false);
      setOverrideReason("");
      setMfaOpen(false);
      setMfaCode("");
      setMfaError(null);
      navigate({ to: "/policies/$policyId", params: { policyId } });
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        // Server blocked on unresolved grant-vs-deny conflicts. Surface them
        // (the response carries the offending pairs) and open the audited
        // override path rather than silently failing.
        if (err.conflicts?.length) {
          setSim((prev) =>
            prev
              ? { ...prev, conflicts: err.conflicts as PolicyConflict[] }
              : { impact: zeroImpact(), conflicts: err.conflicts! },
          );
        }
        // A 409 can arrive on the retry *after* a successful step-up (a
        // concurrent promotion introduced new conflicts), so the MFA modal may
        // still be open. Close it before opening the override modal so the two
        // never stack — the mirror of the step-up handler below, which closes
        // the override modal before opening MFA.
        setMfaOpen(false);
        setMfaCode("");
        setMfaError(null);
        setOverrideOpen(true);
        return;
      }
      if (err instanceof ApiError && isStepUpRequired(err)) {
        // The high-risk promote needs a fresh step-up assertion. Remember the
        // (force, reason) context so the modal's retry matches this attempt,
        // then prompt for the TOTP code. Close the conflict-override modal first
        // so the MFA modal does not stack on top of it (the override reason is
        // already captured in pendingPromote).
        setPendingPromote({ force, reason });
        setMfaError(null);
        setMfaCode("");
        setOverrideOpen(false);
        setMfaOpen(true);
        return;
      }
      if (err instanceof ApiError && isStepUpFailed(err)) {
        // Wrong or replayed code: keep the prompt open for another attempt and
        // surface why the last one was rejected.
        setPendingPromote({ force, reason });
        setMfaError(err.message);
        setMfaCode("");
        setOverrideOpen(false);
        setMfaOpen(true);
        return;
      }
      if (err instanceof ApiError && isSessionMfaRequired(err)) {
        // The session's own MFA claim is unsatisfied (not a step-up failure).
        // A TOTP code cannot satisfy the JWT-claim gate, so close any prompt and
        // tell the operator to re-authenticate rather than looping the modal.
        setMfaOpen(false);
        setOverrideOpen(false);
        toast.error(
          intl.formatMessage({
            id: "policyEditor.toast.sessionMfa",
            defaultMessage: "Session needs MFA",
          }),
          intl.formatMessage({
            id: "policyEditor.toast.sessionMfaBody",
            defaultMessage:
              "Your session is not MFA-verified. Sign out and sign back in with MFA, then retry the promotion.",
          }),
        );
        return;
      }
      toast.error(
        intl.formatMessage({
          id: "policyEditor.toast.promoteError",
          defaultMessage: "Could not promote",
        }),
        errMessage(err, intl),
      );
    }
  };

  const submitMfa = () => {
    const code = mfaCode.trim();
    if (!code) return;
    void promote(pendingPromote.force, pendingPromote.reason, code);
  };

  const archive = async () => {
    if (!policyId) return;
    try {
      await archiveMut.mutateAsync();
      toast.success(
        intl.formatMessage({
          id: "policyEditor.toast.archived",
          defaultMessage: "Policy archived",
        }),
      );
      navigate({ to: "/policies" });
    } catch (err) {
      toast.error(
        intl.formatMessage({
          id: "policyEditor.toast.archiveError",
          defaultMessage: "Could not archive",
        }),
        errMessage(err, intl),
      );
    }
  };

  if (policyId && policyQuery.isLoading) {
    return (
      <div className="state">
        <Spinner />
        <p style={{ marginTop: 12 }}>
          {intl.formatMessage({
            id: "policyEditor.loading",
            defaultMessage: "Loading policy…",
          })}
        </p>
      </div>
    );
  }
  if (policyId && policyQuery.error) {
    return (
      <PageHeader
        title={intl.formatMessage({
          id: "policyEditor.notFound.title",
          defaultMessage: "Policy not found",
        })}
        subtitle={errMessage(policyQuery.error, intl)}
        actions={
          <button className="btn" onClick={() => navigate({ to: "/policies" })}>
            {intl.formatMessage({
              id: "policyEditor.notFound.back",
              defaultMessage: "Back to policies",
            })}
          </button>
        }
      />
    );
  }

  const readOnly = !isDraft;
  const impact = sim?.impact ?? policy?.draft_impact ?? null;

  return (
    <>
      <PageHeader
        title={
          isNew
            ? intl.formatMessage({
                id: "policyEditor.title.new",
                defaultMessage: "New access policy",
              })
            : form.name ||
              intl.formatMessage({
                id: "policyEditor.title.fallback",
                defaultMessage: "Access policy",
              })
        }
        subtitle={intl.formatMessage({
          id: "policyEditor.subtitle",
          defaultMessage:
            "Define who and which groups can reach which systems. Drafts never touch the data plane until you simulate and promote.",
        })}
        actions={
          <span style={{ display: "inline-flex", gap: 8, alignItems: "center" }}>
            {policy && <StatusBadge status={policy.state} />}
            <button className="btn" onClick={() => navigate({ to: "/policies" })}>
              {intl.formatMessage({
                id: "policyEditor.back",
                defaultMessage: "Back",
              })}
            </button>
          </span>
        }
      />

      {readOnly && (
        <div className="notice notice--info" style={{ marginBottom: 16 }}>
          {intl.formatMessage(
            {
              id: "policyEditor.readOnly",
              defaultMessage:
                "This policy is <b>{state}</b> and is read-only. To change live access, create a new draft — the original stays enforced until the new one is tested and promoted.",
            },
            {
              state: policy?.state ?? "",
              b: (chunks) => <b>{chunks}</b>,
            },
          )}
        </div>
      )}

      <div className="grid grid--2">
        <Card
          title={intl.formatMessage({
            id: "policyEditor.rule.title",
            defaultMessage: "Rule",
          })}
          subtitle={intl.formatMessage({
            id: "policyEditor.rule.subtitle",
            defaultMessage:
              "A policy grants or denies a set of subjects access to a set of resources. Deny always wins on conflict.",
          })}
        >
          <label className="field">
            <span>
              {intl.formatMessage({
                id: "policyEditor.field.name",
                defaultMessage: "Policy name",
              })}
            </span>
            <input
              value={form.name}
              disabled={readOnly}
              placeholder={intl.formatMessage({
                id: "policyEditor.field.namePlaceholder",
                defaultMessage: "e.g. Engineering → production apps",
              })}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
          </label>

          <div className="field">
            <span>
              {intl.formatMessage({
                id: "policyEditor.field.decision",
                defaultMessage: "Decision",
              })}{" "}
              <HelpTooltip>
                {intl.formatMessage({
                  id: "policyEditor.field.decisionHelp",
                  defaultMessage:
                    "Grant opens access; Deny blocks it. When a subject/resource pair is matched by both a grant and a deny, deny wins.",
                })}
              </HelpTooltip>
            </span>
            <div
              className="segmented"
              role="radiogroup"
              aria-label={intl.formatMessage({
                id: "policyEditor.field.decision",
                defaultMessage: "Decision",
              })}
            >
              <button
                type="button"
                role="radio"
                aria-checked={form.action === "grant"}
                disabled={readOnly}
                className={`segmented__option${form.action === "grant" ? " active" : ""}`}
                onClick={() => setForm({ ...form, action: "grant" })}
              >
                {intl.formatMessage({
                  id: "policyEditor.decision.grant",
                  defaultMessage: "Grant",
                })}
              </button>
              <button
                type="button"
                role="radio"
                aria-checked={form.action === "deny"}
                disabled={readOnly}
                className={`segmented__option${form.action === "deny" ? " active" : ""}`}
                onClick={() => setForm({ ...form, action: "deny" })}
              >
                {intl.formatMessage({
                  id: "policyEditor.decision.deny",
                  defaultMessage: "Deny",
                })}
              </button>
            </div>
          </div>

          <ChipInput
            label={intl.formatMessage({
              id: "policyEditor.field.subjects",
              defaultMessage: "Who / which groups",
            })}
            values={form.subjects}
            disabled={readOnly}
            onChange={(subjects) => setForm({ ...form, subjects })}
            placeholder={intl.formatMessage({
              id: "policyEditor.field.subjectsPlaceholder",
              defaultMessage: "user:ada@corp, team:engineering, contractor:acme…",
            })}
            hints={SUBJECT_HINTS}
            invalidHint={
              !readOnly && form.subjects.length === 0
                ? intl.formatMessage({
                    id: "policyEditor.field.subjectsError",
                    defaultMessage:
                      "Add at least one subject (a user, team, group or contractor).",
                  })
                : undefined
            }
          />

          <ChipInput
            label={intl.formatMessage({
              id: "policyEditor.field.resources",
              defaultMessage: "Which systems / resources",
            })}
            values={form.resources}
            disabled={readOnly}
            onChange={(resources) => setForm({ ...form, resources })}
            placeholder={intl.formatMessage({
              id: "policyEditor.field.resourcesPlaceholder",
              defaultMessage: "app:salesforce, host:10.0.0.0/24, *…",
            })}
            hints={RESOURCE_HINTS}
            invalidHint={
              !readOnly && form.resources.length === 0
                ? intl.formatMessage({
                    id: "policyEditor.field.resourcesError",
                    defaultMessage:
                      "Add at least one resource. Use * for all resources (with care).",
                  })
                : undefined
            }
          />

          <label className="field">
            <span>
              {intl.formatMessage({
                id: "policyEditor.field.role",
                defaultMessage: "Role",
              })}{" "}
              <span className="muted">
                {intl.formatMessage({
                  id: "policyEditor.field.optional",
                  defaultMessage: "(optional)",
                })}
              </span>
            </span>
            <input
              value={form.role}
              disabled={readOnly}
              placeholder={intl.formatMessage({
                id: "policyEditor.field.rolePlaceholder",
                defaultMessage: "e.g. viewer, admin",
              })}
              onChange={(e) => setForm({ ...form, role: e.target.value })}
            />
          </label>

          {form.resources.includes("*") && !readOnly && (
            <div className="notice notice--warn">
              {intl.formatMessage(
                {
                  id: "policyEditor.wildcardWarn",
                  defaultMessage:
                    "This rule targets <b>all resources</b> (<code>*</code>). Simulate carefully before rollout.",
                },
                {
                  b: (chunks) => <b>{chunks}</b>,
                  code: (chunks) => <code>{chunks}</code>,
                },
              )}
            </div>
          )}

          {!readOnly && (
            <div className="field-row" style={{ marginTop: 4 }}>
              <button
                className="btn btn--primary"
                onClick={save}
                disabled={!valid || createMut.isPending || updateMut.isPending}
              >
                {createMut.isPending || updateMut.isPending ? (
                  <Spinner />
                ) : isNew ? (
                  intl.formatMessage({
                    id: "policyEditor.action.createDraft",
                    defaultMessage: "Create draft",
                  })
                ) : (
                  intl.formatMessage({
                    id: "policyEditor.action.saveDraft",
                    defaultMessage: "Save draft",
                  })
                )}
              </button>
              {readOnlyArchiveHidden(isNew) && (
                <button
                  className="btn btn--ghost"
                  onClick={archive}
                  disabled={archiveMut.isPending}
                >
                  {intl.formatMessage({
                    id: "policyEditor.action.archive",
                    defaultMessage: "Archive",
                  })}
                </button>
              )}
            </div>
          )}
        </Card>

        <Card
          title={intl.formatMessage({
            id: "policyEditor.test.title",
            defaultMessage: "Test before rollout",
          })}
          subtitle={intl.formatMessage({
            id: "policyEditor.test.subtitle",
            defaultMessage:
              "Simulate computes the real impact and any conflicts against live policies. A draft can't go live until it's been simulated since its last edit.",
          })}
        >
          {isNew ? (
            <div className="notice notice--info">
              {intl.formatMessage({
                id: "policyEditor.test.newHint",
                defaultMessage:
                  "Create the draft first, then simulate it here. Nothing is enforced until you promote.",
              })}
            </div>
          ) : (
            <>
              <div className="rollout-steps">
                <div className={`rollout-step${!dirty ? " done" : ""}`}>
                  <span className="rollout-step__num">1</span>
                  <div>
                    <b>
                      {intl.formatMessage({
                        id: "policyEditor.step.save",
                        defaultMessage: "Save the draft",
                      })}
                    </b>
                    <p className="muted">
                      {dirty
                        ? intl.formatMessage({
                            id: "policyEditor.step.saveDirty",
                            defaultMessage:
                              "You have unsaved edits. Save them before testing.",
                          })
                        : intl.formatMessage({
                            id: "policyEditor.step.saveDone",
                            defaultMessage: "Draft saved.",
                          })}
                    </p>
                  </div>
                </div>
                <div
                  className={`rollout-step${simulatedSinceEdit ? " done" : ""}`}
                >
                  <span className="rollout-step__num">2</span>
                  <div>
                    <b>
                      {intl.formatMessage({
                        id: "policyEditor.step.simulate",
                        defaultMessage: "Simulate",
                      })}
                    </b>
                    <p className="muted">
                      {simulatedSinceEdit
                        ? intl.formatMessage({
                            id: "policyEditor.step.simulateDone",
                            defaultMessage:
                              "Tested against current live policies.",
                          })
                        : intl.formatMessage({
                            id: "policyEditor.step.simulateTodo",
                            defaultMessage:
                              "Required before rollout — computes impact + conflicts.",
                          })}
                    </p>
                  </div>
                </div>
                <div className="rollout-step">
                  <span className="rollout-step__num">3</span>
                  <div>
                    <b>
                      {intl.formatMessage({
                        id: "policyEditor.step.promote",
                        defaultMessage: "Promote",
                      })}
                    </b>
                    <p className="muted">
                      {intl.formatMessage({
                        id: "policyEditor.step.promoteHint",
                        defaultMessage:
                          "Flips the policy live. Blocked on grant-vs-deny conflicts unless you override with a reason (audited).",
                      })}
                    </p>
                  </div>
                </div>
              </div>

              {readOnly ? (
                <dl className="kv" style={{ marginTop: 12 }}>
                  <dt>
                    {intl.formatMessage({
                      id: "policyEditor.promotedAt",
                      defaultMessage: "Promoted",
                    })}
                  </dt>
                  <dd>{formatDateTime(policy?.promoted_at)}</dd>
                </dl>
              ) : (
                <div className="field-row" style={{ marginTop: 12 }}>
                  <button
                    className="btn"
                    onClick={simulate}
                    disabled={dirty || simulateMut.isPending}
                    title={
                      dirty
                        ? intl.formatMessage({
                            id: "policyEditor.simulate.dirtyTitle",
                            defaultMessage: "Save your edits before simulating.",
                          })
                        : undefined
                    }
                  >
                    {simulateMut.isPending ? (
                      <Spinner />
                    ) : (
                      intl.formatMessage({
                        id: "policyEditor.step.simulate",
                        defaultMessage: "Simulate",
                      })
                    )}
                  </button>
                  <button
                    className="btn btn--primary"
                    onClick={() => {
                      if (hardConflicts.length > 0) setOverrideOpen(true);
                      else promote();
                    }}
                    disabled={!canPromote || promoteMut.isPending}
                    title={
                      !simulatedSinceEdit
                        ? intl.formatMessage({
                            id: "policyEditor.promote.needSim",
                            defaultMessage: "Simulate this draft before promoting.",
                          })
                        : undefined
                    }
                  >
                    {promoteMut.isPending ? (
                      <Spinner />
                    ) : (
                      intl.formatMessage({
                        id: "policyEditor.action.promote",
                        defaultMessage: "Promote to live",
                      })
                    )}
                  </button>
                </div>
              )}

              {!canPromote && !readOnly && (
                <p className="muted" style={{ marginTop: 8, fontSize: 12 }}>
                  {dirty
                    ? intl.formatMessage({
                        id: "policyEditor.promote.hintDirty",
                        defaultMessage:
                          "Save your edits, then simulate, to enable promotion.",
                      })
                    : !simulatedSinceEdit
                      ? intl.formatMessage({
                          id: "policyEditor.promote.hintSim",
                          defaultMessage:
                            "Simulate this draft to enable promotion.",
                        })
                      : ""}
                </p>
              )}
            </>
          )}

          {impact && (
            <div style={{ marginTop: 16 }}>
              <h4 style={{ margin: "0 0 8px" }}>
                {intl.formatMessage({
                  id: "policyEditor.impact.title",
                  defaultMessage: "Impact",
                })}
              </h4>
              <div className="grid grid--stats">
                <ImpactStat
                  label={intl.formatMessage({
                    id: "policyEditor.impact.subjects",
                    defaultMessage: "Subjects",
                  })}
                  value={impact.subject_count}
                />
                <ImpactStat
                  label={intl.formatMessage({
                    id: "policyEditor.impact.resources",
                    defaultMessage: "Resources",
                  })}
                  value={impact.resource_count}
                />
                <ImpactStat
                  label={intl.formatMessage({
                    id: "policyEditor.impact.pairs",
                    defaultMessage: "Pairs",
                  })}
                  value={impact.pair_count}
                />
                <ImpactStat
                  label={intl.formatMessage({
                    id: "policyEditor.impact.newGrants",
                    defaultMessage: "New grants",
                  })}
                  value={impact.new_grant_pairs}
                />
              </div>
              {impact.wildcard_resource && (
                <p className="muted" style={{ marginTop: 8, fontSize: 12 }}>
                  {intl.formatMessage({
                    id: "policyEditor.impact.wildcard",
                    defaultMessage: "Includes a wildcard resource",
                  })}{" "}
                  ·{" "}
                  {impact.redundant_pairs > 0
                    ? intl.formatMessage(
                        {
                          id: "policyEditor.impact.redundant",
                          defaultMessage:
                            "{n, plural, one {# redundant pair} other {# redundant pairs}}",
                        },
                        { n: impact.redundant_pairs },
                      )
                    : intl.formatMessage({
                        id: "policyEditor.impact.noRedundancy",
                        defaultMessage: "no redundancy",
                      })}
                </p>
              )}
            </div>
          )}

          {sim && sim.conflicts.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <h4 style={{ margin: "0 0 8px" }}>
                {intl.formatMessage({
                  id: "policyEditor.conflicts.title",
                  defaultMessage: "Conflicts",
                })}{" "}
                {hardConflicts.length > 0 ? (
                  <Badge tone="danger">
                    {intl.formatMessage(
                      {
                        id: "policyEditor.conflicts.blocking",
                        defaultMessage: "{n} blocking",
                      },
                      { n: hardConflicts.length },
                    )}
                  </Badge>
                ) : (
                  <Badge tone="warn">
                    {intl.formatMessage({
                      id: "policyEditor.conflicts.advisory",
                      defaultMessage: "advisory only",
                    })}
                  </Badge>
                )}
              </h4>
              <ConflictTable conflicts={sim.conflicts} />
            </div>
          )}
        </Card>
      </div>

      {overrideOpen && (
        <Modal
          title={intl.formatMessage({
            id: "policyEditor.override.title",
            defaultMessage: "Override conflicts and promote",
          })}
          onClose={() => setOverrideOpen(false)}
          footer={
            <>
              <button
                className="btn btn--ghost"
                onClick={() => setOverrideOpen(false)}
              >
                {intl.formatMessage({
                  id: "policyEditor.override.cancel",
                  defaultMessage: "Cancel",
                })}
              </button>
              <button
                className="btn btn--danger"
                disabled={!overrideReason.trim() || promoteMut.isPending}
                onClick={() => promote(true, overrideReason.trim())}
              >
                {promoteMut.isPending ? (
                  <Spinner />
                ) : (
                  intl.formatMessage({
                    id: "policyEditor.override.confirm",
                    defaultMessage: "Override and promote",
                  })
                )}
              </button>
            </>
          }
        >
          <p>
            {intl.formatMessage(
              {
                id: "policyEditor.override.body",
                defaultMessage:
                  "This draft has <b>{n}</b> grant-vs-deny conflict(s). Promoting anyway requires a written reason, which is recorded in the tamper-evident audit log.",
              },
              {
                n:
                  hardConflicts.length ||
                  intl.formatMessage({
                    id: "policyEditor.override.unresolved",
                    defaultMessage: "unresolved",
                  }),
                b: (chunks) => <b>{chunks}</b>,
              },
            )}
          </p>
          {hardConflicts.length > 0 && (
            <div style={{ margin: "12px 0" }}>
              <ConflictTable conflicts={hardConflicts} />
            </div>
          )}
          <label className="field">
            <span>
              {intl.formatMessage({
                id: "policyEditor.override.reasonLabel",
                defaultMessage: "Reason for override (required)",
              })}
            </span>
            <textarea
              rows={3}
              value={overrideReason}
              placeholder={intl.formatMessage({
                id: "policyEditor.override.reasonPlaceholder",
                defaultMessage:
                  "e.g. Break-glass access approved by CISO under ticket SEC-1421.",
              })}
              onChange={(e) => setOverrideReason(e.target.value)}
            />
          </label>
        </Modal>
      )}

      {mfaOpen && (
        <Modal
          title={intl.formatMessage({
            id: "policyEditor.mfa.title",
            defaultMessage: "Confirm with step-up MFA",
          })}
          onClose={() => setMfaOpen(false)}
          footer={
            <>
              <button
                className="btn btn--ghost"
                onClick={() => setMfaOpen(false)}
              >
                {intl.formatMessage({
                  id: "policyEditor.mfa.cancel",
                  defaultMessage: "Cancel",
                })}
              </button>
              <button
                className="btn btn--primary"
                disabled={mfaCode.trim().length < 6 || promoteMut.isPending}
                onClick={submitMfa}
              >
                {promoteMut.isPending ? (
                  <Spinner />
                ) : (
                  intl.formatMessage({
                    id: "policyEditor.mfa.confirm",
                    defaultMessage: "Verify and promote",
                  })
                )}
              </button>
            </>
          }
        >
          <p>
            {intl.formatMessage({
              id: "policyEditor.mfa.body",
              defaultMessage:
                "Promoting a policy is a high-risk action and requires a fresh multi-factor confirmation. Enter the current 6-digit code from your authenticator app.",
            })}
          </p>
          <label className="field">
            <span>
              {intl.formatMessage({
                id: "policyEditor.mfa.codeLabel",
                defaultMessage: "Authentication code",
              })}
            </span>
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]*"
              maxLength={6}
              value={mfaCode}
              placeholder="123456"
              autoFocus
              onChange={(e) =>
                setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))
              }
              onKeyDown={(e) => {
                // Mirror the submit button's disabled guard so a rapid double
                // Enter cannot fire two concurrent promote() calls.
                if (
                  e.key === "Enter" &&
                  mfaCode.trim().length >= 6 &&
                  !promoteMut.isPending
                )
                  submitMfa();
              }}
            />
          </label>
          {mfaError && (
            <p className="muted" style={{ marginTop: 8, color: "var(--danger)" }}>
              {mfaError}
            </p>
          )}
        </Modal>
      )}
    </>
  );
}

function ImpactStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="stat">
      <div className="stat__label">{label}</div>
      <div className="stat__value">{value}</div>
    </div>
  );
}

function zeroImpact() {
  return {
    action: "",
    subject_count: 0,
    resource_count: 0,
    pair_count: 0,
    new_grant_pairs: 0,
    redundant_pairs: 0,
    wildcard_resource: false,
    affected_grants: 0,
  };
}

// Archive is only meaningful for a persisted policy (draft or active); a brand
// new, unsaved policy has nothing to archive.
function readOnlyArchiveHidden(isNew: boolean): boolean {
  return !isNew;
}

function errMessage(err: unknown, intl: IntlShape): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return intl.formatMessage({
    id: "policyEditor.error.unexpected",
    defaultMessage: "Unexpected error",
  });
}
