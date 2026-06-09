import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
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
  type SimulationResult,
  ApiError,
} from "@/api/access";
import { formatDateTime } from "@/lib/format";

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
                aria-label={`Remove ${v}`}
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
  return (
    <table className="data">
      <thead>
        <tr>
          <th>Type</th>
          <th>Subject</th>
          <th>Resource</th>
          <th>Conflicting policy</th>
        </tr>
      </thead>
      <tbody>
        {conflicts.map((c, i) => (
          <tr key={`${c.other_policy_id}-${c.subject}-${c.resource}-${i}`}>
            <td>
              <Badge tone={c.kind === "grant_vs_deny" ? "danger" : "warn"}>
                {c.kind === "grant_vs_deny" ? "Grant vs deny" : "Redundant"}
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
        toast.success("Draft created", "Now simulate it before rolling out.");
        navigate({
          to: "/policies/$policyId",
          params: { policyId: created.id },
        });
      } else {
        await updateMut.mutateAsync(body);
        baselineRef.current = JSON.stringify(form);
        setSim(null);
        toast.info(
          "Draft saved",
          "Editing cleared the previous test — simulate again before rollout.",
        );
      }
    } catch (err) {
      toast.error("Could not save draft", errMessage(err));
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
          "Simulation complete",
          `${hard} grant-vs-deny conflict(s) found — resolve or override to promote.`,
        );
      } else {
        toast.success(
          "Simulation complete",
          "No blocking conflicts. This draft is ready to promote.",
        );
      }
    } catch (err) {
      toast.error("Simulation failed", errMessage(err));
    }
  };

  const promote = async (force = false, reason?: string) => {
    if (!policyId) return;
    try {
      await promoteMut.mutateAsync(
        force ? { force: true, reason } : undefined,
      );
      toast.success(
        "Policy promoted",
        force
          ? "Promoted with an audited conflict override."
          : "This policy is now live.",
      );
      setOverrideOpen(false);
      setOverrideReason("");
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
        setOverrideOpen(true);
        return;
      }
      toast.error("Could not promote", errMessage(err));
    }
  };

  const archive = async () => {
    if (!policyId) return;
    try {
      await archiveMut.mutateAsync();
      toast.success("Policy archived");
      navigate({ to: "/policies" });
    } catch (err) {
      toast.error("Could not archive", errMessage(err));
    }
  };

  if (policyId && policyQuery.isLoading) {
    return (
      <div className="state">
        <Spinner />
        <p style={{ marginTop: 12 }}>Loading policy…</p>
      </div>
    );
  }
  if (policyId && policyQuery.error) {
    return (
      <PageHeader
        title="Policy not found"
        subtitle={errMessage(policyQuery.error)}
        actions={
          <button className="btn" onClick={() => navigate({ to: "/policies" })}>
            Back to policies
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
        title={isNew ? "New access policy" : form.name || "Access policy"}
        subtitle="Define who and which groups can reach which systems. Drafts never touch the data plane until you simulate and promote."
        actions={
          <span style={{ display: "inline-flex", gap: 8, alignItems: "center" }}>
            {policy && <StatusBadge status={policy.state} />}
            <button className="btn" onClick={() => navigate({ to: "/policies" })}>
              Back
            </button>
          </span>
        }
      />

      {readOnly && (
        <div className="notice notice--info" style={{ marginBottom: 16 }}>
          This policy is <b>{policy?.state}</b> and is read-only. To change live
          access, create a new draft — the original stays enforced until the new
          one is tested and promoted.
        </div>
      )}

      <div className="grid grid--2">
        <Card
          title="Rule"
          subtitle="A policy grants or denies a set of subjects access to a set of resources. Deny always wins on conflict."
        >
          <label className="field">
            <span>Policy name</span>
            <input
              value={form.name}
              disabled={readOnly}
              placeholder="e.g. Engineering → production apps"
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
          </label>

          <div className="field">
            <span>
              Decision{" "}
              <HelpTooltip>
                Grant opens access; Deny blocks it. When a subject/resource pair
                is matched by both a grant and a deny, deny wins.
              </HelpTooltip>
            </span>
            <div className="segmented" role="radiogroup" aria-label="Decision">
              <button
                type="button"
                role="radio"
                aria-checked={form.action === "grant"}
                disabled={readOnly}
                className={`segmented__option${form.action === "grant" ? " active" : ""}`}
                onClick={() => setForm({ ...form, action: "grant" })}
              >
                Grant
              </button>
              <button
                type="button"
                role="radio"
                aria-checked={form.action === "deny"}
                disabled={readOnly}
                className={`segmented__option${form.action === "deny" ? " active" : ""}`}
                onClick={() => setForm({ ...form, action: "deny" })}
              >
                Deny
              </button>
            </div>
          </div>

          <ChipInput
            label="Who / which groups"
            values={form.subjects}
            disabled={readOnly}
            onChange={(subjects) => setForm({ ...form, subjects })}
            placeholder="user:ada@corp, team:engineering, contractor:acme…"
            hints={SUBJECT_HINTS}
            invalidHint={
              !readOnly && form.subjects.length === 0
                ? "Add at least one subject (a user, team, group or contractor)."
                : undefined
            }
          />

          <ChipInput
            label="Which systems / resources"
            values={form.resources}
            disabled={readOnly}
            onChange={(resources) => setForm({ ...form, resources })}
            placeholder="app:salesforce, host:10.0.0.0/24, *…"
            hints={RESOURCE_HINTS}
            invalidHint={
              !readOnly && form.resources.length === 0
                ? "Add at least one resource. Use * for all resources (with care)."
                : undefined
            }
          />

          <label className="field">
            <span>
              Role <span className="muted">(optional)</span>
            </span>
            <input
              value={form.role}
              disabled={readOnly}
              placeholder="e.g. viewer, admin"
              onChange={(e) => setForm({ ...form, role: e.target.value })}
            />
          </label>

          {form.resources.includes("*") && !readOnly && (
            <div className="notice notice--warn">
              This rule targets <b>all resources</b> (<code>*</code>). Simulate
              carefully before rollout.
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
                  "Create draft"
                ) : (
                  "Save draft"
                )}
              </button>
              {readOnlyArchiveHidden(isNew) && (
                <button
                  className="btn btn--ghost"
                  onClick={archive}
                  disabled={archiveMut.isPending}
                >
                  Archive
                </button>
              )}
            </div>
          )}
        </Card>

        <Card
          title="Test before rollout"
          subtitle="Simulate computes the real impact and any conflicts against live policies. A draft can't go live until it's been simulated since its last edit."
        >
          {isNew ? (
            <div className="notice notice--info">
              Create the draft first, then simulate it here. Nothing is enforced
              until you promote.
            </div>
          ) : (
            <>
              <div className="rollout-steps">
                <div className={`rollout-step${!dirty ? " done" : ""}`}>
                  <span className="rollout-step__num">1</span>
                  <div>
                    <b>Save the draft</b>
                    <p className="muted">
                      {dirty
                        ? "You have unsaved edits. Save them before testing."
                        : "Draft saved."}
                    </p>
                  </div>
                </div>
                <div
                  className={`rollout-step${simulatedSinceEdit ? " done" : ""}`}
                >
                  <span className="rollout-step__num">2</span>
                  <div>
                    <b>Simulate</b>
                    <p className="muted">
                      {simulatedSinceEdit
                        ? "Tested against current live policies."
                        : "Required before rollout — computes impact + conflicts."}
                    </p>
                  </div>
                </div>
                <div className="rollout-step">
                  <span className="rollout-step__num">3</span>
                  <div>
                    <b>Promote</b>
                    <p className="muted">
                      Flips the policy live. Blocked on grant-vs-deny conflicts
                      unless you override with a reason (audited).
                    </p>
                  </div>
                </div>
              </div>

              {readOnly ? (
                <div className="kv" style={{ marginTop: 12 }}>
                  <div>
                    <dt>Promoted</dt>
                    <dd>{formatDateTime(policy?.promoted_at)}</dd>
                  </div>
                </div>
              ) : (
                <div className="field-row" style={{ marginTop: 12 }}>
                  <button
                    className="btn"
                    onClick={simulate}
                    disabled={dirty || simulateMut.isPending}
                    title={
                      dirty ? "Save your edits before simulating." : undefined
                    }
                  >
                    {simulateMut.isPending ? <Spinner /> : "Simulate"}
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
                        ? "Simulate this draft before promoting."
                        : undefined
                    }
                  >
                    {promoteMut.isPending ? <Spinner /> : "Promote to live"}
                  </button>
                </div>
              )}

              {!canPromote && !readOnly && (
                <p className="muted" style={{ marginTop: 8, fontSize: 12 }}>
                  {dirty
                    ? "Save your edits, then simulate, to enable promotion."
                    : !simulatedSinceEdit
                      ? "Simulate this draft to enable promotion."
                      : ""}
                </p>
              )}
            </>
          )}

          {impact && (
            <div style={{ marginTop: 16 }}>
              <h4 style={{ margin: "0 0 8px" }}>Impact</h4>
              <div className="grid grid--stats">
                <ImpactStat label="Subjects" value={impact.subject_count} />
                <ImpactStat label="Resources" value={impact.resource_count} />
                <ImpactStat label="Pairs" value={impact.pair_count} />
                <ImpactStat
                  label="New grants"
                  value={impact.new_grant_pairs}
                />
              </div>
              {impact.wildcard_resource && (
                <p className="muted" style={{ marginTop: 8, fontSize: 12 }}>
                  Includes a wildcard resource ·{" "}
                  {impact.redundant_pairs > 0
                    ? `${impact.redundant_pairs} redundant pair(s)`
                    : "no redundancy"}
                </p>
              )}
            </div>
          )}

          {sim && sim.conflicts.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <h4 style={{ margin: "0 0 8px" }}>
                Conflicts{" "}
                {hardConflicts.length > 0 ? (
                  <Badge tone="danger">{hardConflicts.length} blocking</Badge>
                ) : (
                  <Badge tone="warn">advisory only</Badge>
                )}
              </h4>
              <ConflictTable conflicts={sim.conflicts} />
            </div>
          )}
        </Card>
      </div>

      {overrideOpen && (
        <Modal
          title="Override conflicts and promote"
          onClose={() => setOverrideOpen(false)}
          footer={
            <>
              <button
                className="btn btn--ghost"
                onClick={() => setOverrideOpen(false)}
              >
                Cancel
              </button>
              <button
                className="btn btn--danger"
                disabled={!overrideReason.trim() || promoteMut.isPending}
                onClick={() => promote(true, overrideReason.trim())}
              >
                {promoteMut.isPending ? <Spinner /> : "Override and promote"}
              </button>
            </>
          }
        >
          <p>
            This draft has <b>{hardConflicts.length || "unresolved"}</b>{" "}
            grant-vs-deny conflict(s). Promoting anyway requires a written
            reason, which is recorded in the tamper-evident audit log.
          </p>
          {hardConflicts.length > 0 && (
            <div style={{ margin: "12px 0" }}>
              <ConflictTable conflicts={hardConflicts} />
            </div>
          )}
          <label className="field">
            <span>Reason for override (required)</span>
            <textarea
              rows={3}
              value={overrideReason}
              placeholder="e.g. Break-glass access approved by CISO under ticket SEC-1421."
              onChange={(e) => setOverrideReason(e.target.value)}
            />
          </label>
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

function errMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return "Unexpected error";
}
