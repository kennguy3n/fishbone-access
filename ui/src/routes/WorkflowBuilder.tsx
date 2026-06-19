import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useIntl, FormattedMessage, type IntlShape } from "react-intl";
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

// Plain-language operator labels, localized at render time so a non-technical
// admin reads "equals" / "is one of" rather than the raw enum.
function operatorLabel(intl: IntlShape, op: ConditionOperator): string {
  switch (op) {
    case "eq":
      return intl.formatMessage({ id: "jml.operator.eq", defaultMessage: "equals" });
    case "neq":
      return intl.formatMessage({ id: "jml.operator.neq", defaultMessage: "does not equal" });
    case "in":
      return intl.formatMessage({ id: "jml.operator.in", defaultMessage: "is one of" });
    case "contains":
      return intl.formatMessage({ id: "jml.operator.contains", defaultMessage: "contains" });
    case "not_contains":
      return intl.formatMessage({ id: "jml.operator.not_contains", defaultMessage: "does not contain" });
  }
}

// Attributes the subject resolver understands first-class (workflow/subject.go),
// surfaced as datalist hints so a non-technical admin doesn't have to guess.
const ATTRIBUTE_HINTS = [
  "department",
  "email",
  "display_name",
  "groups",
  "external_id",
];

// All step types and whether each is leaver-only. run_kill_switch is leaver-only
// (enforced server-side); the builder hides it for joiner/mover lanes so it
// can't be assembled by mistake. Human labels and hints are localized via
// stepLabel/stepHint so the catalog stays pure data.
const STEP_CATALOG: { type: StepType; leaverOnly?: boolean }[] = [
  { type: "grant_role" },
  { type: "provision_connector" },
  { type: "request_approval" },
  { type: "notify" },
  { type: "start_access_review" },
  { type: "run_kill_switch", leaverOnly: true },
];

function stepLabel(intl: IntlShape, type: StepType): string {
  switch (type) {
    case "grant_role":
      return intl.formatMessage({ id: "jml.step.grant_role.label", defaultMessage: "Grant role" });
    case "provision_connector":
      return intl.formatMessage({ id: "jml.step.provision_connector.label", defaultMessage: "Provision connector" });
    case "request_approval":
      return intl.formatMessage({ id: "jml.step.request_approval.label", defaultMessage: "Request approval" });
    case "notify":
      return intl.formatMessage({ id: "jml.step.notify.label", defaultMessage: "Notify" });
    case "start_access_review":
      return intl.formatMessage({ id: "jml.step.start_access_review.label", defaultMessage: "Start access review" });
    case "run_kill_switch":
      return intl.formatMessage({ id: "jml.step.run_kill_switch.label", defaultMessage: "Run kill switch" });
    default:
      return titleCase(type);
  }
}

function stepHint(intl: IntlShape, type: StepType): string | null {
  switch (type) {
    case "grant_role":
      return intl.formatMessage({ id: "jml.step.grant_role.hint", defaultMessage: "Provision a role on a connector for the identity." });
    case "provision_connector":
      return intl.formatMessage({ id: "jml.step.provision_connector.hint", defaultMessage: "Create the identity's account on a downstream connector." });
    case "request_approval":
      return intl.formatMessage({ id: "jml.step.request_approval.hint", defaultMessage: "Route a grant to a human approver before it is provisioned." });
    case "notify":
      return intl.formatMessage({ id: "jml.step.notify.hint", defaultMessage: "Send a message to a channel (e.g. an onboarding buddy)." });
    case "start_access_review":
      return intl.formatMessage({ id: "jml.step.start_access_review.hint", defaultMessage: "Kick off a certification campaign for the identity's access." });
    case "run_kill_switch":
      return intl.formatMessage({ id: "jml.step.run_kill_switch.hint", defaultMessage: "Six-layer irreversible offboard. Leaver workflows only." });
    default:
      return null;
  }
}

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

function errMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return fallback;
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
  const intl = useIntl();
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
            aria-label={intl.formatMessage(
              { id: "jml.chip.remove", defaultMessage: "Remove {value}" },
              { value: v },
            )}
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
  const intl = useIntl();
  const set = (patch: Partial<WorkflowStep>) => onChange({ ...step, ...patch });
  const hint = stepHint(intl, step.type);
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
          {stepLabel(intl, step.type)}
        </Badge>
        <div style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
          <button
            className="btn btn--ghost btn--sm"
            aria-label={intl.formatMessage({ id: "jml.step.moveUp", defaultMessage: "Move step up" })}
            disabled={index === 0}
            onClick={() => onMove(-1)}
          >
            ↑
          </button>
          <button
            className="btn btn--ghost btn--sm"
            aria-label={intl.formatMessage({ id: "jml.step.moveDown", defaultMessage: "Move step down" })}
            disabled={index === count - 1}
            onClick={() => onMove(1)}
          >
            ↓
          </button>
          <button
            className="btn btn--ghost btn--sm"
            aria-label={intl.formatMessage({ id: "jml.step.remove", defaultMessage: "Remove step" })}
            onClick={onRemove}
          >
            {intl.formatMessage({ id: "common.remove", defaultMessage: "Remove" })}
          </button>
        </div>
      </div>

      {hint && (
        <p className="muted" style={{ fontSize: 12, marginTop: 0 }}>
          {hint}
        </p>
      )}

      <label className="field">
        <span>
          {intl.formatMessage({ id: "jml.step.labelField", defaultMessage: "Label" })}{" "}
          <span className="muted">
            {intl.formatMessage({ id: "common.optional", defaultMessage: "(optional)" })}
          </span>
        </span>
        <input
          value={step.name ?? ""}
          placeholder={intl.formatMessage({
            id: "jml.step.labelPlaceholder",
            defaultMessage: "Shown in the run audit",
          })}
          onChange={(e) => set({ name: e.target.value })}
        />
      </label>

      {needsTarget && (
        <>
          <label className="field">
            <span>{intl.formatMessage({ id: "jml.step.connectorId", defaultMessage: "Connector ID" })}</span>
            <input
              value={step.connector_id ?? ""}
              placeholder={intl.formatMessage({
                id: "jml.step.connectorIdPlaceholder",
                defaultMessage: "UUID of the target connector",
              })}
              onChange={(e) => set({ connector_id: e.target.value })}
            />
            {connectorBad && (
              <span className="field__error">
                {intl.formatMessage({
                  id: "jml.step.connectorBad",
                  defaultMessage:
                    "Enter the connector's ID — a UUID you can copy from the connector's page.",
                })}
              </span>
            )}
          </label>
          <label className="field">
            <span>{intl.formatMessage({ id: "jml.step.resource", defaultMessage: "Resource" })}</span>
            <input
              value={step.resource_ref ?? ""}
              placeholder={intl.formatMessage({
                id: "jml.step.resourcePlaceholder",
                defaultMessage: "e.g. app:salesforce",
              })}
              onChange={(e) => set({ resource_ref: e.target.value })}
            />
          </label>
          <label className="field">
            <span>{intl.formatMessage({ id: "jml.step.role", defaultMessage: "Role" })}</span>
            <input
              value={step.role ?? ""}
              placeholder={intl.formatMessage({
                id: "jml.step.rolePlaceholder",
                defaultMessage: "e.g. viewer, admin",
              })}
              onChange={(e) => set({ role: e.target.value })}
            />
          </label>
        </>
      )}

      {step.type === "request_approval" && (
        <label className="field">
          <span>{intl.formatMessage({ id: "jml.step.approverRole", defaultMessage: "Approver role" })}</span>
          <input
            value={step.approver_role ?? ""}
            placeholder={intl.formatMessage({
              id: "jml.step.approverRolePlaceholder",
              defaultMessage: "e.g. manager, security",
            })}
            onChange={(e) => set({ approver_role: e.target.value })}
          />
        </label>
      )}

      {step.type === "notify" && (
        <>
          <label className="field">
            <span>{intl.formatMessage({ id: "jml.step.channel", defaultMessage: "Channel" })}</span>
            <input
              value={step.channel ?? ""}
              placeholder={intl.formatMessage({
                id: "jml.step.channelPlaceholder",
                defaultMessage: "e.g. #it-onboarding, email",
              })}
              onChange={(e) => set({ channel: e.target.value })}
            />
          </label>
          <label className="field">
            <span>
              {intl.formatMessage({ id: "jml.step.message", defaultMessage: "Message" })}{" "}
              <span className="muted">
                {intl.formatMessage({ id: "common.optional", defaultMessage: "(optional)" })}
              </span>
            </span>
            <input
              value={step.message ?? ""}
              placeholder={intl.formatMessage({
                id: "jml.step.messagePlaceholder",
                defaultMessage: "What to say",
              })}
              onChange={(e) => set({ message: e.target.value })}
            />
          </label>
        </>
      )}

      {step.type === "start_access_review" && (
        <label className="field">
          <span>{intl.formatMessage({ id: "jml.step.reviewName", defaultMessage: "Review name" })}</span>
          <input
            value={step.review_name ?? ""}
            placeholder={intl.formatMessage({
              id: "jml.step.reviewNamePlaceholder",
              defaultMessage: "e.g. Quarterly access certification",
            })}
            onChange={(e) => set({ review_name: e.target.value })}
          />
        </label>
      )}

      {step.type === "run_kill_switch" && (
        <div className="notice notice--warn">
          <FormattedMessage
            id="jml.step.killWarning"
            defaultMessage="Runs all six offboarding layers (grant revoke → team remove → iam-core disable → session revoke → SCIM deprovision → identity disable). This is irreversible and only valid on a <b>leaver</b> workflow."
            values={{ b: (chunks) => <b>{chunks}</b> }}
          />
        </div>
      )}

      {step.type === "run_kill_switch" && kind !== "leaver" && (
        <div className="notice notice--danger">
          <FormattedMessage
            id="jml.step.killWrongLane"
            defaultMessage="The kill switch is only allowed on a leaver workflow. Change the lane to <b>Leaver</b> or remove this step."
            values={{ b: (chunks) => <b>{chunks}</b> }}
          />
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Run outcome view (shared by the simulate panel)
// ---------------------------------------------------------------------------

export function RunOutcome({ result }: { result: WorkflowRunResult }) {
  const intl = useIntl();
  if (!result.matched) {
    return (
      <div className="notice notice--info">
        {intl.formatMessage({
          id: "jml.sim.noMatch",
          defaultMessage:
            "The sample identity does not match this workflow's conditions, so no steps would run for them.",
        })}
      </div>
    );
  }
  return (
    <div className="table-wrap">
      <table className="data">
        <thead>
          <tr>
            <th style={{ width: 40 }}>#</th>
            <th>{intl.formatMessage({ id: "jml.step.col.step", defaultMessage: "Step" })}</th>
            <th style={{ width: 120 }}>{intl.formatMessage({ id: "jml.step.col.outcome", defaultMessage: "Outcome" })}</th>
            <th>{intl.formatMessage({ id: "jml.step.col.detail", defaultMessage: "Detail" })}</th>
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
  // A non-matching dry-run never exercises the steps, so the server rejects a
  // publish gated only on it; require a matching simulation here too so the
  // button reflects the real gate instead of failing on click.
  const simulationMatched = workflow?.draft_simulation?.matched === true;
  const canPublish =
    isDraft &&
    simulatedSinceEdit &&
    !simulationFailed &&
    simulationMatched &&
    !dirty;

  const createMut = useCreateWorkflow();
  const updateMut = useUpdateWorkflow(workflowId ?? "");
  const simulateMut = useSimulateWorkflow(workflowId ?? "");
  const publishMut = usePublishWorkflow(workflowId ?? "");
  const archiveMut = useArchiveWorkflow(workflowId ?? "");

  const genericError = intl.formatMessage({
    id: "common.genericError",
    defaultMessage: "Something went wrong. Please try again.",
  });

  const save = async () => {
    if (!valid) return;
    const body = { name: form.name.trim(), definition: toDefinition(form) };
    try {
      if (isNew) {
        const created = await createMut.mutateAsync(body);
        toast.success(
          intl.formatMessage({ id: "jml.builder.draftCreated", defaultMessage: "Draft created" }),
          intl.formatMessage({
            id: "jml.builder.draftCreatedDetail",
            defaultMessage: "Now simulate it for a sample user.",
          }),
        );
        navigate({
          to: "/workflows/$workflowId",
          params: { workflowId: created.id },
        });
      } else {
        await updateMut.mutateAsync(body);
        baselineRef.current = JSON.stringify(form);
        setSim(null);
        toast.info(
          intl.formatMessage({ id: "jml.builder.draftSaved", defaultMessage: "Draft saved" }),
          intl.formatMessage({
            id: "jml.builder.draftSavedDetail",
            defaultMessage:
              "Editing cleared the previous test — simulate again before publishing.",
          }),
        );
      }
    } catch (err) {
      toast.error(
        intl.formatMessage({ id: "jml.builder.saveFailed", defaultMessage: "Could not save draft" }),
        errMessage(err, genericError),
      );
    }
  };

  const simulate = async () => {
    if (!workflowId) return;
    if (!subject.external_id.trim()) {
      toast.error(
        intl.formatMessage({ id: "jml.sim.userRequired", defaultMessage: "Sample user required" }),
        intl.formatMessage({
          id: "jml.sim.userRequiredDetail",
          defaultMessage: "Enter a sample external ID to simulate.",
        }),
      );
      return;
    }
    try {
      const result = await simulateMut.mutateAsync(subject);
      setSim(result);
      if (result.status === "failed") {
        toast.info(
          intl.formatMessage({ id: "jml.sim.complete", defaultMessage: "Simulation complete" }),
          intl.formatMessage({
            id: "jml.sim.completeFailed",
            defaultMessage:
              "One or more steps would fail — resolve them before publishing.",
          }),
        );
      } else if (!result.matched) {
        toast.info(
          intl.formatMessage({ id: "jml.sim.complete", defaultMessage: "Simulation complete" }),
          intl.formatMessage({
            id: "jml.sim.completeNoMatch",
            defaultMessage:
              "This sample identity doesn't match the workflow conditions.",
          }),
        );
      } else {
        toast.success(
          intl.formatMessage({ id: "jml.sim.complete", defaultMessage: "Simulation complete" }),
          intl.formatMessage({
            id: "jml.sim.completeOk",
            defaultMessage: "No failures. This draft is ready to publish.",
          }),
        );
      }
    } catch (err) {
      toast.error(
        intl.formatMessage({ id: "jml.sim.failed", defaultMessage: "Simulation failed" }),
        errMessage(err, genericError),
      );
    }
  };

  const publish = async () => {
    if (!workflowId) return;
    try {
      await publishMut.mutateAsync();
      toast.success(
        intl.formatMessage({ id: "jml.publish.done", defaultMessage: "Workflow published" }),
        intl.formatMessage({
          id: "jml.publish.doneDetail",
          defaultMessage: "The engine now runs this workflow.",
        }),
      );
      navigate({ to: "/workflows/$workflowId", params: { workflowId } });
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        toast.error(
          intl.formatMessage({ id: "jml.publish.stepupTitle", defaultMessage: "Step-up MFA required" }),
          intl.formatMessage({
            id: "jml.publish.stepupDetail",
            defaultMessage: "Re-authenticate with MFA to publish this workflow.",
          }),
        );
        return;
      }
      toast.error(
        intl.formatMessage({ id: "jml.publish.failed", defaultMessage: "Could not publish" }),
        errMessage(err, genericError),
      );
    }
  };

  const archive = async () => {
    if (!workflowId) return;
    try {
      await archiveMut.mutateAsync();
      toast.success(
        intl.formatMessage({ id: "jml.archive.done", defaultMessage: "Workflow archived" }),
        intl.formatMessage({
          id: "jml.archive.doneDetail",
          defaultMessage: "It will no longer run.",
        }),
      );
      navigate({ to: "/workflows/$workflowId", params: { workflowId } });
    } catch (err) {
      toast.error(
        intl.formatMessage({ id: "jml.archive.failed", defaultMessage: "Could not archive" }),
        errMessage(err, genericError),
      );
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
        <p style={{ marginTop: 12 }}>
          {intl.formatMessage({
            id: "jml.builder.loading",
            defaultMessage: "Loading workflow…",
          })}
        </p>
      </div>
    );
  }
  if (workflowId && wfQuery.error) {
    return (
      <PageHeader
        title={intl.formatMessage({
          id: "jml.builder.notFound",
          defaultMessage: "Workflow not found",
        })}
        subtitle={errMessage(wfQuery.error, genericError)}
        actions={
          <button className="btn" onClick={() => navigate({ to: "/workflows" })}>
            {intl.formatMessage({
              id: "jml.builder.backToWorkflows",
              defaultMessage: "Back to workflows",
            })}
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
              {intl.formatMessage({ id: "common.back", defaultMessage: "Back" })}
            </button>
          </span>
        }
      />

      {readOnly && (
        <div className="notice notice--info" style={{ marginBottom: 16 }}>
          <FormattedMessage
            id="jml.builder.readOnly"
            defaultMessage="This workflow is <b>{state}</b> and is read-only. To change it, create a new draft — a published workflow keeps running until it is archived."
            values={{ state: workflow?.state ?? "", b: (chunks) => <b>{chunks}</b> }}
          />
        </div>
      )}

      <div className="grid grid--2">
        {/* ---- Authoring column ---- */}
        <div>
          <Card
            title={intl.formatMessage({ id: "jml.builder.card.workflow", defaultMessage: "Workflow" })}
            subtitle={intl.formatMessage({
              id: "jml.builder.card.workflowSub",
              defaultMessage:
                "The lane and what fires it. The lane gates which steps are allowed.",
            })}
          >
            <label className="field">
              <span>{intl.formatMessage({ id: "jml.builder.name", defaultMessage: "Name" })}</span>
              <input
                value={form.name}
                disabled={readOnly}
                placeholder={intl.formatMessage({
                  id: "jml.builder.namePlaceholder",
                  defaultMessage: "e.g. Engineering joiner onboarding",
                })}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
              />
            </label>

            <div className="field">
              <span>{intl.formatMessage({ id: "jml.builder.lane", defaultMessage: "Lane" })}</span>
              <div
                className="segmented"
                role="radiogroup"
                aria-label={intl.formatMessage({ id: "jml.builder.lane", defaultMessage: "Lane" })}
              >
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
                {intl.formatMessage({ id: "jml.builder.trigger", defaultMessage: "Trigger" })}{" "}
                <HelpTooltip>
                  {intl.formatMessage({
                    id: "jml.builder.triggerHelp",
                    defaultMessage:
                      "What fires a published workflow: an identity event from SCIM, a schedule, or a manual run.",
                  })}
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
            title={intl.formatMessage({ id: "jml.builder.card.conditions", defaultMessage: "Conditions" })}
            subtitle={intl.formatMessage({
              id: "jml.builder.card.conditionsSub",
              defaultMessage:
                "All conditions must hold for the workflow to act on an identity. No conditions means it acts on everyone in the lane.",
            })}
            className="mt-16"
          >
            {form.conditions.length === 0 && (
              <p className="muted">
                {intl.formatMessage({
                  id: "jml.builder.noConditions",
                  defaultMessage: "No conditions — acts on every identity.",
                })}
              </p>
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
                    aria-label={intl.formatMessage(
                      { id: "jml.cond.attribute", defaultMessage: "Condition {n} attribute" },
                      { n: i + 1 },
                    )}
                    value={c.attribute}
                    disabled={readOnly}
                    placeholder={intl.formatMessage({
                      id: "jml.cond.attributePlaceholder",
                      defaultMessage: "attribute (e.g. department)",
                    })}
                    onChange={(e) =>
                      updateCondition(i, { ...c, attribute: e.target.value })
                    }
                  />
                  <select
                    aria-label={intl.formatMessage(
                      { id: "jml.cond.operator", defaultMessage: "Condition {n} operator" },
                      { n: i + 1 },
                    )}
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
                        {operatorLabel(intl, op)}
                      </option>
                    ))}
                  </select>
                  {!readOnly && (
                    <button
                      className="btn btn--ghost btn--sm"
                      aria-label={intl.formatMessage(
                        { id: "jml.cond.remove", defaultMessage: "Remove condition {n}" },
                        { n: i + 1 },
                      )}
                      onClick={() => removeCondition(i)}
                    >
                      ✕
                    </button>
                  )}
                </div>
                <ChipInput
                  ariaLabel={intl.formatMessage(
                    { id: "jml.cond.values", defaultMessage: "Condition {n} values" },
                    { n: i + 1 },
                  )}
                  values={c.values}
                  onChange={(values) => updateCondition(i, { ...c, values })}
                  placeholder={intl.formatMessage({
                    id: "jml.cond.valuePlaceholder",
                    defaultMessage: "value, then Enter",
                  })}
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
                {intl.formatMessage({
                  id: "jml.builder.addCondition",
                  defaultMessage: "Add condition",
                })}
              </button>
            )}
          </Card>

          <Card
            title={intl.formatMessage({ id: "jml.builder.card.steps", defaultMessage: "Steps" })}
            subtitle={intl.formatMessage({
              id: "jml.builder.card.stepsSub",
              defaultMessage:
                "The ordered pipeline. Steps run top to bottom; each appends to the audit chain on a live run.",
            })}
            className="mt-16"
          >
            {form.steps.length === 0 && (
              <div className="notice notice--warn">
                {intl.formatMessage({
                  id: "jml.builder.noSteps",
                  defaultMessage:
                    "Add at least one step. A workflow with no steps can't be saved.",
                })}
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
                    + {stepLabel(intl, s.type)}
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
                  intl.formatMessage({ id: "jml.builder.createDraft", defaultMessage: "Create draft" })
                ) : (
                  intl.formatMessage({ id: "jml.builder.saveDraft", defaultMessage: "Save draft" })
                )}
              </button>
              {!isNew && (
                <button
                  className="btn btn--ghost"
                  onClick={archive}
                  disabled={archiveMut.isPending}
                >
                  {intl.formatMessage({ id: "jml.builder.archive", defaultMessage: "Archive" })}
                </button>
              )}
            </div>
          )}
        </div>

        {/* ---- Simulate + publish column ---- */}
        <div>
          <Card
            title={intl.formatMessage({
              id: "jml.sim.cardTitle",
              defaultMessage: "Simulate for a sample user",
            })}
            subtitle={intl.formatMessage({
              id: "jml.sim.cardSub",
              defaultMessage:
                "A dry-run shows exactly what would happen for a sample identity, with no side effects. Required before publishing.",
            })}
          >
            {isNew ? (
              <div className="notice notice--info">
                {intl.formatMessage({
                  id: "jml.sim.createFirst",
                  defaultMessage:
                    "Create the draft first, then simulate it here. Nothing runs until you publish.",
                })}
              </div>
            ) : (
              <>
                <label className="field">
                  <span>{intl.formatMessage({ id: "jml.sim.externalId", defaultMessage: "External ID" })}</span>
                  <input
                    value={subject.external_id}
                    placeholder={intl.formatMessage({
                      id: "jml.sim.externalIdPlaceholder",
                      defaultMessage: "e.g. ada@corp.example",
                    })}
                    onChange={(e) =>
                      setSubject({ ...subject, external_id: e.target.value })
                    }
                  />
                </label>
                <div className="grid grid--2">
                  <label className="field">
                    <span>{intl.formatMessage({ id: "jml.sim.department", defaultMessage: "Department" })}</span>
                    <input
                      value={subject.department ?? ""}
                      placeholder={intl.formatMessage({
                        id: "jml.sim.departmentPlaceholder",
                        defaultMessage: "e.g. engineering",
                      })}
                      onChange={(e) =>
                        setSubject({ ...subject, department: e.target.value })
                      }
                    />
                  </label>
                  <label className="field">
                    <span>{intl.formatMessage({ id: "jml.sim.email", defaultMessage: "Email" })}</span>
                    <input
                      value={subject.email ?? ""}
                      placeholder={intl.formatMessage({
                        id: "jml.sim.emailPlaceholder",
                        defaultMessage: "e.g. ada@corp.example",
                      })}
                      onChange={(e) =>
                        setSubject({ ...subject, email: e.target.value })
                      }
                    />
                  </label>
                </div>
                <label className="field">
                  <span>{intl.formatMessage({ id: "jml.sim.groups", defaultMessage: "Groups" })}</span>
                  <ChipInput
                    ariaLabel={intl.formatMessage({
                      id: "jml.sim.groupsAria",
                      defaultMessage: "Sample user groups",
                    })}
                    values={subject.groups ?? []}
                    onChange={(groups) => setSubject({ ...subject, groups })}
                    placeholder={intl.formatMessage({
                      id: "jml.sim.groupsPlaceholder",
                      defaultMessage: "group, then Enter",
                    })}
                  />
                </label>

                <div className="field-row" style={{ marginTop: 4 }}>
                  <button
                    className="btn"
                    onClick={simulate}
                    disabled={dirty || simulateMut.isPending}
                    title={
                      dirty
                        ? intl.formatMessage({
                            id: "jml.sim.saveFirstTitle",
                            defaultMessage: "Save your edits before simulating.",
                          })
                        : undefined
                    }
                  >
                    {simulateMut.isPending ? (
                      <Spinner />
                    ) : (
                      intl.formatMessage({ id: "jml.sim.run", defaultMessage: "Simulate" })
                    )}
                  </button>
                </div>
                {dirty && (
                  <p className="muted" style={{ fontSize: 12 }}>
                    {intl.formatMessage({
                      id: "jml.sim.dirtyHint",
                      defaultMessage:
                        "You have unsaved edits. Save the draft before simulating.",
                    })}
                  </p>
                )}
              </>
            )}
          </Card>

          {sim && (
            <Card
              title={intl.formatMessage({
                id: "jml.sim.outcomeTitle",
                defaultMessage: "What would happen",
              })}
              className="mt-16"
            >
              <div style={{ marginBottom: 10 }}>
                <StatusBadge status={sim.status} />{" "}
                <span className="muted">
                  {sim.mode === "dry_run"
                    ? intl.formatMessage({
                        id: "jml.sim.modeDryRun",
                        defaultMessage: "Dry-run (no side effects)",
                      })
                    : intl.formatMessage({ id: "jml.mode.live", defaultMessage: "Live" })}
                </span>
              </div>
              <RunOutcome result={sim} />
            </Card>
          )}

          {!isNew && isDraft && (
            <Card
              title={intl.formatMessage({ id: "jml.publish.cardTitle", defaultMessage: "Publish" })}
              className="mt-16"
            >
              <div className="rollout-steps">
                <div className={`rollout-step${!dirty ? " done" : ""}`}>
                  <span className="rollout-step__num">1</span>
                  <div>
                    <b>{intl.formatMessage({ id: "jml.publish.step1", defaultMessage: "Save the draft" })}</b>
                    <p className="muted">
                      {dirty
                        ? intl.formatMessage({
                            id: "jml.publish.step1Dirty",
                            defaultMessage:
                              "You have unsaved edits. Save them before testing.",
                          })
                        : intl.formatMessage({
                            id: "jml.publish.step1Done",
                            defaultMessage: "Draft saved.",
                          })}
                    </p>
                  </div>
                </div>
                <div className={`rollout-step${simulatedSinceEdit ? " done" : ""}`}>
                  <span className="rollout-step__num">2</span>
                  <div>
                    <b>{intl.formatMessage({ id: "jml.publish.step2", defaultMessage: "Simulate" })}</b>
                    <p className="muted">
                      {simulatedSinceEdit
                        ? simulationFailed
                          ? intl.formatMessage({
                              id: "jml.publish.step2Failed",
                              defaultMessage: "Last dry-run had failures — fix them to publish.",
                            })
                          : !simulationMatched
                            ? intl.formatMessage({
                                id: "jml.publish.step2NoMatch",
                                defaultMessage:
                                  "Sample didn't match the conditions — simulate a matching identity to publish.",
                              })
                            : intl.formatMessage({
                                id: "jml.publish.step2Ok",
                                defaultMessage: "Dry-run passed for the sample identity.",
                              })
                        : intl.formatMessage({
                            id: "jml.publish.step2Todo",
                            defaultMessage:
                              "Required before publishing — runs a no-side-effect dry-run.",
                          })}
                    </p>
                  </div>
                </div>
                <div className="rollout-step">
                  <span className="rollout-step__num">3</span>
                  <div>
                    <b>{intl.formatMessage({ id: "jml.publish.step3", defaultMessage: "Publish" })}</b>
                    <p className="muted">
                      {intl.formatMessage({
                        id: "jml.publish.step3Detail",
                        defaultMessage:
                          "Makes the workflow live. Requires step-up MFA. Editing a published workflow means creating a new draft.",
                      })}
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
                      ? intl.formatMessage({
                          id: "jml.publish.titleSimulate",
                          defaultMessage: "Simulate the current draft before publishing.",
                        })
                      : simulationFailed
                        ? intl.formatMessage({
                            id: "jml.publish.titleFailed",
                            defaultMessage: "The last dry-run had failures.",
                          })
                        : !simulationMatched
                          ? intl.formatMessage({
                              id: "jml.publish.titleNoMatch",
                              defaultMessage:
                                "Simulate a sample identity that matches the conditions before publishing.",
                            })
                          : undefined
                  }
                >
                  {publishMut.isPending ? (
                    <Spinner />
                  ) : (
                    intl.formatMessage({ id: "jml.publish.button", defaultMessage: "Publish" })
                  )}
                </button>
              </div>
            </Card>
          )}
        </div>
      </div>
    </>
  );
}
