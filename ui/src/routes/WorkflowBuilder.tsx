import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useIntl } from "react-intl";
import { PageHeader, Card, Badge, StatusBadge, Spinner } from "@/components/ui";
import { HelpTooltip } from "@/components/HelpTooltip";
import { useToast } from "@/components/Toast";
import {
  useWorkflow,
  useCreateWorkflow,
  useUpdateWorkflow,
  useSimulateWorkflow,
  usePublishWorkflow,
  useArchiveWorkflow,
  type Workflow,
  type WorkflowKind,
  type WorkflowTrigger,
  type WorkflowStep,
  type WorkflowCondition,
  type WorkflowDefinition,
  type WorkflowSubject,
  type WorkflowRunResult,
  type StepType,
  type ConditionOperator,
} from "@/api/workflows";
import { ApiError } from "@/api/access";
import { titleCase } from "@/lib/format";

// ---------------------------------------------------------------------------
// Form model + option catalogs
// ---------------------------------------------------------------------------

const KIND_OPTIONS: WorkflowKind[] = ["joiner", "mover", "leaver"];
const TRIGGER_OPTIONS: WorkflowTrigger[] = [
  "identity_event",
  "schedule",
  "manual",
];
const OPERATORS: ConditionOperator[] = [
  "eq",
  "neq",
  "in",
  "contains",
  "not_contains",
];
const OPERATOR_LABELS: Record<ConditionOperator, string> = {
  eq: "equals",
  neq: "does not equal",
  in: "is one of",
  contains: "contains",
  not_contains: "does not contain",
};

// Attributes the subject resolver understands first-class (workflow/subject.go),
// surfaced as datalist hints so a non-technical admin doesn't have to guess.
const ATTRIBUTE_HINTS = [
  "department",
  "email",
  "display_name",
  "groups",
  "external_id",
];

// All step types, with the human label and whether the step is destructive.
// run_kill_switch is leaver-only (enforced server-side); the builder hides it
// for joiner/mover lanes so it can't be assembled by mistake.
const STEP_CATALOG: {
  type: StepType;
  label: string;
  hint: string;
  leaverOnly?: boolean;
}[] = [
  {
    type: "grant_role",
    label: "Grant role",
    hint: "Provision a role on a connector for the identity.",
  },
  {
    type: "provision_connector",
    label: "Provision connector",
    hint: "Create the identity's account on a downstream connector.",
  },
  {
    type: "request_approval",
    label: "Request approval",
    hint: "Route a grant to a human approver before it is provisioned.",
  },
  {
    type: "notify",
    label: "Notify",
    hint: "Send a message to a channel (e.g. an onboarding buddy).",
  },
  {
    type: "start_access_review",
    label: "Start access review",
    hint: "Kick off a certification campaign for the identity's access.",
  },
  {
    type: "run_kill_switch",
    label: "Run kill switch",
    hint: "Six-layer irreversible offboard. Leaver workflows only.",
    leaverOnly: true,
  },
];

interface BuilderForm {
  name: string;
  kind: WorkflowKind;
  trigger: WorkflowTrigger;
  conditions: WorkflowCondition[];
  steps: WorkflowStep[];
}

const emptyForm: BuilderForm = {
  name: "",
  kind: "joiner",
  trigger: "identity_event",
  conditions: [],
  steps: [],
};

const emptySubject: WorkflowSubject = {
  external_id: "",
  email: "",
  display_name: "",
  department: "",
  groups: [],
};

function formFromWorkflow(w: Workflow): BuilderForm {
  const d = w.definition;
  return {
    name: w.name,
    kind: d.kind,
    trigger: d.trigger,
    conditions: (d.conditions ?? []).map((c) => ({ ...c, values: [...c.values] })),
    steps: (d.steps ?? []).map((s) => ({ ...s })),
  };
}

function toDefinition(f: BuilderForm): WorkflowDefinition {
  return {
    kind: f.kind,
    trigger: f.trigger,
    ...(f.conditions.length ? { conditions: f.conditions } : {}),
    steps: f.steps,
  };
}

// Mirror of workflow.Step.validate so Save is disabled until the document is
// well-formed. The server stays the source of truth — this only prevents an
// obviously-invalid round trip and guides the admin inline.
function stepValid(s: WorkflowStep, kind: WorkflowKind): boolean {
  switch (s.type) {
    case "grant_role":
    case "provision_connector":
      return !!s.connector_id && isUuid(s.connector_id) && !!s.resource_ref && !!s.role;
    case "request_approval":
      return (
        !!s.approver_role &&
        !!s.connector_id &&
        isUuid(s.connector_id) &&
        !!s.resource_ref &&
        !!s.role
      );
    case "notify":
      return !!s.channel;
    case "start_access_review":
      return !!s.review_name;
    case "run_kill_switch":
      return kind === "leaver";
    default:
      return false;
  }
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isUuid(v: string): boolean {
  return UUID_RE.test(v.trim());
}

function errMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return "Something went wrong.";
}

// ---------------------------------------------------------------------------
// Small tag-style multi-value input (local to the builder)
// ---------------------------------------------------------------------------

function ChipInput({
  values,
  onChange,
  placeholder,
  hints,
  ariaLabel,
}: {
  values: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  hints?: string[];
  ariaLabel: string;
}) {
  const [draft, setDraft] = useState("");
  const listId = useMemo(
    () => `chips-${ariaLabel.replace(/\s+/g, "-").toLowerCase()}`,
    [ariaLabel],
  );
  const commit = (raw: string) => {
    const v = raw.trim().replace(/,$/, "").trim();
    if (!v) return;
    if (!values.includes(v)) onChange([...values, v]);
    setDraft("");
  };
  return (
    <div className="chip-input">
      {values.map((v) => (
        <span className="chip" key={v}>
          {v}
          <button
            type="button"
            className="chip__remove"
            aria-label={`Remove ${v}`}
            onClick={() => onChange(values.filter((x) => x !== v))}
          >
            ✕
          </button>
        </span>
      ))}
      <input
        value={draft}
        list={hints ? listId : undefined}
        aria-label={ariaLabel}
        placeholder={values.length === 0 ? placeholder : ""}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === ",") {
            e.preventDefault();
            commit(draft);
          } else if (e.key === "Backspace" && draft === "" && values.length) {
            onChange(values.slice(0, -1));
          }
        }}
        onBlur={() => commit(draft)}
      />
      {hints && (
        <datalist id={listId}>
          {hints.map((h) => (
            <option key={h} value={h} />
          ))}
        </datalist>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step editor — fields adapt to the selected step type
// ---------------------------------------------------------------------------

function StepEditor({
  step,
  index,
  count,
  kind,
  onChange,
  onRemove,
  onMove,
}: {
  step: WorkflowStep;
  index: number;
  count: number;
  kind: WorkflowKind;
  onChange: (next: WorkflowStep) => void;
  onRemove: () => void;
  onMove: (dir: -1 | 1) => void;
}) {
  const set = (patch: Partial<WorkflowStep>) => onChange({ ...step, ...patch });
  const meta = STEP_CATALOG.find((s) => s.type === step.type);
  const needsTarget =
    step.type === "grant_role" ||
    step.type === "provision_connector" ||
    step.type === "request_approval";
  const connectorBad = !!step.connector_id && !isUuid(step.connector_id);

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          marginBottom: 10,
        }}
      >
        <span className="rollout-step__num">{index + 1}</span>
        <Badge tone={step.type === "run_kill_switch" ? "danger" : "info"}>
          {meta?.label ?? titleCase(step.type)}
        </Badge>
        <div style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
          <button
            className="btn btn--ghost btn--sm"
            aria-label="Move step up"
            disabled={index === 0}
            onClick={() => onMove(-1)}
          >
            ↑
          </button>
          <button
            className="btn btn--ghost btn--sm"
            aria-label="Move step down"
            disabled={index === count - 1}
            onClick={() => onMove(1)}
          >
            ↓
          </button>
          <button
            className="btn btn--ghost btn--sm"
            aria-label="Remove step"
            onClick={onRemove}
          >
            Remove
          </button>
        </div>
      </div>

      {meta?.hint && (
        <p className="muted" style={{ fontSize: 12, marginTop: 0 }}>
          {meta.hint}
        </p>
      )}

      <label className="field">
        <span>
          Label <span className="muted">(optional)</span>
        </span>
        <input
          value={step.name ?? ""}
          placeholder="Shown in the run audit"
          onChange={(e) => set({ name: e.target.value })}
        />
      </label>

      {needsTarget && (
        <>
          <label className="field">
            <span>Connector ID</span>
            <input
              value={step.connector_id ?? ""}
              placeholder="UUID of the target connector"
              onChange={(e) => set({ connector_id: e.target.value })}
            />
            {connectorBad && (
              <span className="field__error">
                Must be a connector UUID (copy it from the connector's page).
              </span>
            )}
          </label>
          <label className="field">
            <span>Resource</span>
            <input
              value={step.resource_ref ?? ""}
              placeholder="e.g. app:salesforce"
              onChange={(e) => set({ resource_ref: e.target.value })}
            />
          </label>
          <label className="field">
            <span>Role</span>
            <input
              value={step.role ?? ""}
              placeholder="e.g. viewer, admin"
              onChange={(e) => set({ role: e.target.value })}
            />
          </label>
        </>
      )}

      {step.type === "request_approval" && (
        <label className="field">
          <span>Approver role</span>
          <input
            value={step.approver_role ?? ""}
            placeholder="e.g. manager, security"
            onChange={(e) => set({ approver_role: e.target.value })}
          />
        </label>
      )}

      {step.type === "notify" && (
        <>
          <label className="field">
            <span>Channel</span>
            <input
              value={step.channel ?? ""}
              placeholder="e.g. #it-onboarding, email"
              onChange={(e) => set({ channel: e.target.value })}
            />
          </label>
          <label className="field">
            <span>
              Message <span className="muted">(optional)</span>
            </span>
            <input
              value={step.message ?? ""}
              placeholder="What to say"
              onChange={(e) => set({ message: e.target.value })}
            />
          </label>
        </>
      )}

      {step.type === "start_access_review" && (
        <label className="field">
          <span>Review name</span>
          <input
            value={step.review_name ?? ""}
            placeholder="e.g. Quarterly access certification"
            onChange={(e) => set({ review_name: e.target.value })}
          />
        </label>
      )}

      {step.type === "run_kill_switch" && (
        <div className="notice notice--warn">
          Runs all six offboarding layers (grant revoke → team remove → iam-core
          disable → session revoke → SCIM deprovision → identity disable). This
          is irreversible and only valid on a <b>leaver</b> workflow.
        </div>
      )}

      {step.type === "run_kill_switch" && kind !== "leaver" && (
        <div className="notice notice--danger">
          The kill switch is only allowed on a leaver workflow. Change the lane
          to <b>Leaver</b> or remove this step.
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Run outcome view (shared by the simulate panel)
// ---------------------------------------------------------------------------

export function RunOutcome({ result }: { result: WorkflowRunResult }) {
  if (!result.matched) {
    return (
      <div className="notice notice--info">
        The sample identity does not match this workflow's conditions, so no
        steps would run for them.
      </div>
    );
  }
  return (
    <div className="table-wrap">
      <table className="data">
        <thead>
          <tr>
            <th style={{ width: 40 }}>#</th>
            <th>Step</th>
            <th style={{ width: 120 }}>Outcome</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {result.steps.map((s) => (
            <tr key={s.index}>
              <td>{s.index + 1}</td>
              <td>
                <b>{s.name || titleCase(s.type)}</b>
                {s.layers && s.layers.length > 0 && (
                  <div style={{ marginTop: 6, display: "grid", gap: 4 }}>
                    {s.layers.map((l) => (
                      <span
                        key={l.layer}
                        style={{ display: "inline-flex", gap: 6, fontSize: 12 }}
                      >
                        <Badge tone={l.status === "failed" ? "danger" : "neutral"}>
                          {titleCase(l.layer)}
                        </Badge>
                        {l.detail && <span className="muted">{l.detail}</span>}
                      </span>
                    ))}
                  </div>
                )}
              </td>
              <td>
                <StatusBadge status={s.status} />
              </td>
              <td className="muted">{s.detail || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

export function WorkflowBuilder() {
  const params = useParams({ strict: false }) as { workflowId?: string };
  const workflowId = params.workflowId;
  const isNew = !workflowId;
  const navigate = useNavigate();
  const toast = useToast();
  const intl = useIntl();

  const wfQuery = useWorkflow(workflowId);
  const workflow = wfQuery.data;
  const isDraft = isNew || workflow?.state === "draft";
  const readOnly = !isDraft;

  const [form, setForm] = useState<BuilderForm>(emptyForm);
  const [subject, setSubject] = useState<WorkflowSubject>(emptySubject);
  const [sim, setSim] = useState<WorkflowRunResult | null>(null);

  const baselineRef = useRef<string>(JSON.stringify(emptyForm));
  const loadedVersionRef = useRef<string | null>(null);
  useEffect(() => {
    if (!workflow) return;
    const stamp = `${workflow.id}@${workflow.version}:${workflow.updated_at}`;
    if (loadedVersionRef.current === stamp) return;
    loadedVersionRef.current = stamp;
    const next = formFromWorkflow(workflow);
    setForm(next);
    baselineRef.current = JSON.stringify(next);
    // A fresh load reflects the server's cached draft_simulation; drop any
    // stale local snapshot that no longer matches.
    setSim(workflow.draft_simulation ?? null);
  }, [workflow]);

  const dirty = JSON.stringify(form) !== baselineRef.current;

  const stepsValid =
    form.steps.length > 0 && form.steps.every((s) => stepValid(s, form.kind));
  const conditionsValid = form.conditions.every(
    (c) => c.attribute.trim() && c.values.length > 0,
  );
  const valid = form.name.trim().length > 0 && stepsValid && conditionsValid;

  // The server stamps draft_simulation on a successful dry-run and clears it on
  // any edit; that — not the local snapshot — is the publish gate's source of
  // truth (mirroring the policy promote gate).
  const simulatedSinceEdit =
    !isNew && !!workflow?.draft_simulation && !dirty;
  const simulationFailed = workflow?.draft_simulation?.status === "failed";
  const canPublish = isDraft && simulatedSinceEdit && !simulationFailed && !dirty;

  const createMut = useCreateWorkflow();
  const updateMut = useUpdateWorkflow(workflowId ?? "");
  const simulateMut = useSimulateWorkflow(workflowId ?? "");
  const publishMut = usePublishWorkflow(workflowId ?? "");
  const archiveMut = useArchiveWorkflow(workflowId ?? "");

  const save = async () => {
    if (!valid) return;
    const body = { name: form.name.trim(), definition: toDefinition(form) };
    try {
      if (isNew) {
        const created = await createMut.mutateAsync(body);
        toast.success("Draft created", "Now simulate it for a sample user.");
        navigate({
          to: "/workflows/$workflowId",
          params: { workflowId: created.id },
        });
      } else {
        await updateMut.mutateAsync(body);
        baselineRef.current = JSON.stringify(form);
        setSim(null);
        toast.info(
          "Draft saved",
          "Editing cleared the previous test — simulate again before publishing.",
        );
      }
    } catch (err) {
      toast.error("Could not save draft", errMessage(err));
    }
  };

  const simulate = async () => {
    if (!workflowId) return;
    if (!subject.external_id.trim()) {
      toast.error("Sample user required", "Enter a sample external ID to simulate.");
      return;
    }
    try {
      const result = await simulateMut.mutateAsync(subject);
      setSim(result);
      if (result.status === "failed") {
        toast.info(
          "Simulation complete",
          "One or more steps would fail — resolve them before publishing.",
        );
      } else if (!result.matched) {
        toast.info(
          "Simulation complete",
          "This sample identity doesn't match the workflow conditions.",
        );
      } else {
        toast.success(
          "Simulation complete",
          "No failures. This draft is ready to publish.",
        );
      }
    } catch (err) {
      toast.error("Simulation failed", errMessage(err));
    }
  };

  const publish = async () => {
    if (!workflowId) return;
    try {
      await publishMut.mutateAsync();
      toast.success("Workflow published", "The engine now runs this workflow.");
      navigate({ to: "/workflows/$workflowId", params: { workflowId } });
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        toast.error(
          "Step-up MFA required",
          "Re-authenticate with MFA to publish this workflow.",
        );
        return;
      }
      toast.error("Could not publish", errMessage(err));
    }
  };

  const archive = async () => {
    if (!workflowId) return;
    try {
      await archiveMut.mutateAsync();
      toast.success("Workflow archived", "It will no longer run.");
      navigate({ to: "/workflows/$workflowId", params: { workflowId } });
    } catch (err) {
      toast.error("Could not archive", errMessage(err));
    }
  };

  const addStep = (type: StepType) =>
    setForm((f) => ({ ...f, steps: [...f.steps, { type }] }));
  const updateStep = (i: number, next: WorkflowStep) =>
    setForm((f) => ({
      ...f,
      steps: f.steps.map((s, idx) => (idx === i ? next : s)),
    }));
  const removeStep = (i: number) =>
    setForm((f) => ({ ...f, steps: f.steps.filter((_, idx) => idx !== i) }));
  const moveStep = (i: number, dir: -1 | 1) =>
    setForm((f) => {
      const j = i + dir;
      if (j < 0 || j >= f.steps.length) return f;
      const steps = [...f.steps];
      [steps[i], steps[j]] = [steps[j], steps[i]];
      return { ...f, steps };
    });

  const addCondition = () =>
    setForm((f) => ({
      ...f,
      conditions: [
        ...f.conditions,
        { attribute: "department", operator: "eq", values: [] },
      ],
    }));
  const updateCondition = (i: number, next: WorkflowCondition) =>
    setForm((f) => ({
      ...f,
      conditions: f.conditions.map((c, idx) => (idx === i ? next : c)),
    }));
  const removeCondition = (i: number) =>
    setForm((f) => ({
      ...f,
      conditions: f.conditions.filter((_, idx) => idx !== i),
    }));

  if (workflowId && wfQuery.isLoading) {
    return (
      <div className="state">
        <Spinner />
        <p style={{ marginTop: 12 }}>Loading workflow…</p>
      </div>
    );
  }
  if (workflowId && wfQuery.error) {
    return (
      <PageHeader
        title="Workflow not found"
        subtitle={errMessage(wfQuery.error)}
        actions={
          <button className="btn" onClick={() => navigate({ to: "/workflows" })}>
            Back to workflows
          </button>
        }
      />
    );
  }

  const availableSteps = STEP_CATALOG.filter(
    (s) => !s.leaverOnly || form.kind === "leaver",
  );

  return (
    <>
      <PageHeader
        title={
          isNew
            ? intl.formatMessage({
                id: "jml.new",
                defaultMessage: "New workflow",
              })
            : form.name ||
              intl.formatMessage({
                id: "nav.workflows",
                defaultMessage: "JML workflows",
              })
        }
        subtitle={intl.formatMessage({
          id: "jml.builder.subtitle",
          defaultMessage:
            "Assemble triggers, conditions and steps. Drafts never run until you simulate for a sample user and publish.",
        })}
        actions={
          <span style={{ display: "inline-flex", gap: 8, alignItems: "center" }}>
            {workflow && <StatusBadge status={workflow.state} />}
            <button className="btn" onClick={() => navigate({ to: "/workflows" })}>
              Back
            </button>
          </span>
        }
      />

      {readOnly && (
        <div className="notice notice--info" style={{ marginBottom: 16 }}>
          This workflow is <b>{workflow?.state}</b> and is read-only. To change
          it, create a new draft — a published workflow keeps running until it
          is archived.
        </div>
      )}

      <div className="grid grid--2">
        {/* ---- Authoring column ---- */}
        <div>
          <Card
            title="Workflow"
            subtitle="The lane and what fires it. The lane gates which steps are allowed."
          >
            <label className="field">
              <span>Name</span>
              <input
                value={form.name}
                disabled={readOnly}
                placeholder="e.g. Engineering joiner onboarding"
                onChange={(e) => setForm({ ...form, name: e.target.value })}
              />
            </label>

            <div className="field">
              <span>Lane</span>
              <div className="segmented" role="radiogroup" aria-label="Lane">
                {KIND_OPTIONS.map((k) => (
                  <button
                    key={k}
                    type="button"
                    role="radio"
                    aria-checked={form.kind === k}
                    disabled={readOnly}
                    className={`segmented__option${form.kind === k ? " active" : ""}`}
                    onClick={() => setForm({ ...form, kind: k })}
                  >
                    {titleCase(k)}
                  </button>
                ))}
              </div>
            </div>

            <label className="field">
              <span>
                Trigger{" "}
                <HelpTooltip>
                  What fires a published workflow: an identity event from SCIM, a
                  schedule, or a manual run.
                </HelpTooltip>
              </span>
              <select
                value={form.trigger}
                disabled={readOnly}
                onChange={(e) =>
                  setForm({ ...form, trigger: e.target.value as WorkflowTrigger })
                }
              >
                {TRIGGER_OPTIONS.map((t) => (
                  <option key={t} value={t}>
                    {titleCase(t)}
                  </option>
                ))}
              </select>
            </label>
          </Card>

          <Card
            title="Conditions"
            subtitle="All conditions must hold for the workflow to act on an identity. No conditions means it acts on everyone in the lane."
            className="mt-16"
          >
            {form.conditions.length === 0 && (
              <p className="muted">No conditions — acts on every identity.</p>
            )}
            {form.conditions.map((c, i) => (
              <div
                key={i}
                style={{
                  display: "grid",
                  gap: 8,
                  gridTemplateColumns: "1fr",
                  borderBottom: "1px solid var(--border-soft)",
                  paddingBottom: 12,
                  marginBottom: 12,
                }}
              >
                <div style={{ display: "flex", gap: 8 }}>
                  <input
                    style={{ flex: 1 }}
                    list="condition-attrs"
                    aria-label={`Condition ${i + 1} attribute`}
                    value={c.attribute}
                    disabled={readOnly}
                    placeholder="attribute (e.g. department)"
                    onChange={(e) =>
                      updateCondition(i, { ...c, attribute: e.target.value })
                    }
                  />
                  <select
                    aria-label={`Condition ${i + 1} operator`}
                    value={c.operator}
                    disabled={readOnly}
                    onChange={(e) =>
                      updateCondition(i, {
                        ...c,
                        operator: e.target.value as ConditionOperator,
                      })
                    }
                  >
                    {OPERATORS.map((op) => (
                      <option key={op} value={op}>
                        {OPERATOR_LABELS[op]}
                      </option>
                    ))}
                  </select>
                  {!readOnly && (
                    <button
                      className="btn btn--ghost btn--sm"
                      aria-label={`Remove condition ${i + 1}`}
                      onClick={() => removeCondition(i)}
                    >
                      ✕
                    </button>
                  )}
                </div>
                <ChipInput
                  ariaLabel={`Condition ${i + 1} values`}
                  values={c.values}
                  onChange={(values) => updateCondition(i, { ...c, values })}
                  placeholder="value, then Enter"
                />
              </div>
            ))}
            <datalist id="condition-attrs">
              {ATTRIBUTE_HINTS.map((a) => (
                <option key={a} value={a} />
              ))}
            </datalist>
            {!readOnly && (
              <button className="btn btn--sm" onClick={addCondition}>
                Add condition
              </button>
            )}
          </Card>

          <Card
            title="Steps"
            subtitle="The ordered pipeline. Steps run top to bottom; each appends to the audit chain on a live run."
            className="mt-16"
          >
            {form.steps.length === 0 && (
              <div className="notice notice--warn">
                Add at least one step. A workflow with no steps can't be saved.
              </div>
            )}
            {form.steps.map((s, i) => (
              <StepEditor
                key={i}
                step={s}
                index={i}
                count={form.steps.length}
                kind={form.kind}
                onChange={(next) => updateStep(i, next)}
                onRemove={() => removeStep(i)}
                onMove={(dir) => moveStep(i, dir)}
              />
            ))}
            {!readOnly && (
              <div className="field-row" style={{ flexWrap: "wrap", gap: 8 }}>
                {availableSteps.map((s) => (
                  <button
                    key={s.type}
                    className="btn btn--sm"
                    onClick={() => addStep(s.type)}
                  >
                    + {s.label}
                  </button>
                ))}
              </div>
            )}
          </Card>

          {!readOnly && (
            <div className="field-row" style={{ marginTop: 16 }}>
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
              {!isNew && (
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
        </div>

        {/* ---- Simulate + publish column ---- */}
        <div>
          <Card
            title="Simulate for a sample user"
            subtitle="A dry-run shows exactly what would happen for a sample identity, with no side effects. Required before publishing."
          >
            {isNew ? (
              <div className="notice notice--info">
                Create the draft first, then simulate it here. Nothing runs until
                you publish.
              </div>
            ) : (
              <>
                <label className="field">
                  <span>External ID</span>
                  <input
                    value={subject.external_id}
                    placeholder="e.g. ada@corp.example"
                    onChange={(e) =>
                      setSubject({ ...subject, external_id: e.target.value })
                    }
                  />
                </label>
                <div className="grid grid--2">
                  <label className="field">
                    <span>Department</span>
                    <input
                      value={subject.department ?? ""}
                      placeholder="e.g. engineering"
                      onChange={(e) =>
                        setSubject({ ...subject, department: e.target.value })
                      }
                    />
                  </label>
                  <label className="field">
                    <span>Email</span>
                    <input
                      value={subject.email ?? ""}
                      placeholder="e.g. ada@corp.example"
                      onChange={(e) =>
                        setSubject({ ...subject, email: e.target.value })
                      }
                    />
                  </label>
                </div>
                <label className="field">
                  <span>Groups</span>
                  <ChipInput
                    ariaLabel="Sample user groups"
                    values={subject.groups ?? []}
                    onChange={(groups) => setSubject({ ...subject, groups })}
                    placeholder="group, then Enter"
                  />
                </label>

                <div className="field-row" style={{ marginTop: 4 }}>
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
                </div>
                {dirty && (
                  <p className="muted" style={{ fontSize: 12 }}>
                    You have unsaved edits. Save the draft before simulating.
                  </p>
                )}
              </>
            )}
          </Card>

          {sim && (
            <Card title="What would happen" className="mt-16">
              <div style={{ marginBottom: 10 }}>
                <StatusBadge status={sim.status} />{" "}
                <span className="muted">
                  {sim.mode === "dry_run" ? "Dry-run (no side effects)" : "Live"}
                </span>
              </div>
              <RunOutcome result={sim} />
            </Card>
          )}

          {!isNew && isDraft && (
            <Card title="Publish" className="mt-16">
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
                <div className={`rollout-step${simulatedSinceEdit ? " done" : ""}`}>
                  <span className="rollout-step__num">2</span>
                  <div>
                    <b>Simulate</b>
                    <p className="muted">
                      {simulatedSinceEdit
                        ? simulationFailed
                          ? "Last dry-run had failures — fix them to publish."
                          : "Dry-run passed for the sample identity."
                        : "Required before publishing — runs a no-side-effect dry-run."}
                    </p>
                  </div>
                </div>
                <div className="rollout-step">
                  <span className="rollout-step__num">3</span>
                  <div>
                    <b>Publish</b>
                    <p className="muted">
                      Makes the workflow live. Requires step-up MFA. Editing a
                      published workflow means creating a new draft.
                    </p>
                  </div>
                </div>
              </div>
              <div className="field-row" style={{ marginTop: 12 }}>
                <button
                  className="btn btn--primary"
                  onClick={publish}
                  disabled={!canPublish || publishMut.isPending}
                  title={
                    !simulatedSinceEdit
                      ? "Simulate the current draft before publishing."
                      : simulationFailed
                        ? "The last dry-run had failures."
                        : undefined
                  }
                >
                  {publishMut.isPending ? <Spinner /> : "Publish"}
                </button>
              </div>
            </Card>
          )}
        </div>
      </div>
    </>
  );
}
