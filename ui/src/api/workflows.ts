// Typed client for the JML no-code workflow builder.
//
// Mirrors the Go control plane in internal/services/workflow (Doc / Step /
// Condition / RunResult) and internal/models (Workflow / WorkflowRun). Every
// operation goes through the shared `call` helper in api/access.ts so it reuses
// the bearer token, Accept-Language, gin.H envelope unwrapping, and the
// ApiError normalization (including the 403 "step-up MFA required" surfaced by
// publish / run / emergency-offboard).
//
// React-Query hooks live alongside the raw functions; a global MutationCache
// onSuccess (src/main.tsx) invalidates active queries after any mutation, so
// these hooks don't repeat per-call invalidation.

import {
  useMutation,
  useQuery,
  type UseQueryOptions,
} from "@tanstack/react-query";
import { apiRequest } from "./http-client";
import { ApiError, toApiError } from "./access";

// ---------------------------------------------------------------------------
// Domain types (mirror internal/services/workflow + internal/models)
// ---------------------------------------------------------------------------

export type WorkflowKind = "joiner" | "mover" | "leaver";
export type WorkflowTrigger = "identity_event" | "schedule" | "manual";
export type WorkflowState = "draft" | "published" | "archived";

export type StepType =
  | "grant_role"
  | "provision_connector"
  | "request_approval"
  | "notify"
  | "start_access_review"
  | "run_kill_switch";

export type ConditionOperator =
  | "eq"
  | "neq"
  | "in"
  | "contains"
  | "not_contains";

export type RunMode = "dry_run" | "live";

/** Per-step / aggregate outcome statuses (workflow.Status* in Go). */
export type RunStatus =
  | "planned"
  | "done"
  | "skipped"
  | "failed"
  | "succeeded"
  | "partial";

/** One ANDed attribute predicate gating which identities a workflow acts on. */
export interface WorkflowCondition {
  attribute: string;
  operator: ConditionOperator;
  values: string[];
}

/**
 * One ordered action. The fields are a flat, optional superset across step
 * types (mirroring workflow.Step) so the builder form binds directly to it;
 * the backend enforces the per-type required fields.
 */
export interface WorkflowStep {
  type: StepType;
  name?: string;
  // grant_role / provision_connector
  connector_id?: string;
  resource_ref?: string;
  role?: string;
  // request_approval
  approver_role?: string;
  // notify
  channel?: string;
  message?: string;
  // start_access_review
  review_name?: string;
}

/** The declarative workflow document (workflow.Doc). */
export interface WorkflowDefinition {
  kind: WorkflowKind;
  trigger: WorkflowTrigger;
  conditions?: WorkflowCondition[];
  steps: WorkflowStep[];
}

export interface Workflow {
  id: string;
  workspace_id: string;
  name: string;
  trigger: WorkflowTrigger;
  state: WorkflowState;
  version: number;
  definition: WorkflowDefinition;
  draft_simulation?: WorkflowRunResult | null;
  published_at?: string | null;
  created_at: string;
  updated_at: string;
}

/** The identity a workflow targets — sample for a dry-run, real for a live run. */
export interface WorkflowSubject {
  external_id: string;
  email?: string;
  display_name?: string;
  department?: string;
  groups?: string[];
  attributes?: Record<string, string>;
}

/** One layer outcome of the six-layer kill switch, surfaced inside a run step. */
export interface KillSwitchLayer {
  layer: string;
  status: RunStatus;
  detail?: string;
}

export interface WorkflowStepOutcome {
  index: number;
  type: StepType;
  name?: string;
  status: RunStatus;
  detail?: string;
  ref?: string;
  /** Present only for a run_kill_switch step. */
  layers?: KillSwitchLayer[];
}

/** Outcome of a dry-run (planned) or a live run (workflow.RunResult). */
export interface WorkflowRunResult {
  mode: RunMode;
  matched: boolean;
  status: RunStatus;
  subject: WorkflowSubject;
  steps: WorkflowStepOutcome[];
  run_id?: string | null;
}

/** A persisted live run (models.WorkflowRun) shown on the JML dashboard. */
export interface WorkflowRun {
  id: string;
  workspace_id: string;
  workflow_id: string;
  workflow_version: number;
  trigger?: string;
  subject_external_id: string;
  mode: RunMode;
  status: RunStatus;
  steps?: WorkflowStepOutcome[];
  started_at: string;
  completed_at?: string | null;
}

/** The standalone six-layer emergency-offboard outcome (lifecycle.LeaverResult). */
export interface LeaverResult {
  user_external_id: string;
  layers: KillSwitchLayer[];
  errored: boolean;
}

export interface WorkflowInput {
  name: string;
  definition: WorkflowDefinition;
}

// ---------------------------------------------------------------------------
// Query keys
// ---------------------------------------------------------------------------

export const wfqk = {
  workflows: ["workflows"] as const,
  workflow: (id: string) => ["workflow", id] as const,
  // The limit is part of the key so two callers with different page sizes get
  // distinct cache entries instead of one serving the other's stale rows.
  runs: (limit?: number) => ["workflow-runs", limit ?? null] as const,
  run: (id: string) => ["workflow-run", id] as const,
};

// A request that normalizes any thrown error into ApiError (the access.ts
// `call` helper is module-private, so we re-wrap here against the same type).
async function call<T>(config: Parameters<typeof apiRequest>[0]): Promise<T> {
  try {
    return await apiRequest<T>(config);
  } catch (err) {
    throw toApiError(err);
  }
}

// ---------------------------------------------------------------------------
// Workflows — draft → simulate → publish
// ---------------------------------------------------------------------------

export const listWorkflows = () =>
  call<{ workflows: Workflow[] }>({ url: "/workflows", method: "GET" }).then(
    (r) => r.workflows ?? [],
  );

export const getWorkflow = (id: string) =>
  call<{ workflow: Workflow }>({
    url: `/workflows/${id}`,
    method: "GET",
  }).then((r) => r.workflow);

export const createWorkflow = (body: WorkflowInput) =>
  call<{ workflow: Workflow }>({
    url: "/workflows",
    method: "POST",
    data: body,
  }).then((r) => r.workflow);

export const updateWorkflow = (id: string, body: WorkflowInput) =>
  call<{ workflow: Workflow }>({
    url: `/workflows/${id}`,
    method: "PUT",
    data: body,
  }).then((r) => r.workflow);

export const simulateWorkflow = (id: string, subject: WorkflowSubject) =>
  call<{ simulation: WorkflowRunResult }>({
    url: `/workflows/${id}/simulate`,
    method: "POST",
    data: subject,
  }).then((r) => normalizeResult(r.simulation));

export const publishWorkflow = (id: string) =>
  call<{ workflow: Workflow }>({
    url: `/workflows/${id}/publish`,
    method: "POST",
  }).then((r) => r.workflow);

export const archiveWorkflow = (id: string) =>
  call<{ workflow: Workflow }>({
    url: `/workflows/${id}/archive`,
    method: "POST",
  }).then((r) => r.workflow);

// runWorkflow resolves with the run breakdown on success. On a completed run
// with step failures the server returns 500 carrying the SAME breakdown under
// `run`, which `call` surfaces as an ApiError. The breakdown is preserved on
// `ApiError.details` (it would otherwise be discarded by the generic error
// path) — use `failedRunFromError` to recover it so a caller can render the
// per-step failure detail the operator needs to act on.
export const runWorkflow = (id: string, subject: WorkflowSubject) =>
  call<{ run: WorkflowRunResult }>({
    url: `/workflows/${id}/run`,
    method: "POST",
    data: subject,
  }).then((r) => normalizeResult(r.run));

// failedRunFromError extracts the per-step run breakdown a failed runWorkflow
// call carries on its ApiError (the 500 body's `run`), returning undefined when
// the error is not a run failure (e.g. a 403 step-up-MFA or 404). This lets a
// caller render the failed steps instead of only the generic error message.
export function failedRunFromError(
  err: unknown,
): WorkflowRunResult | undefined {
  if (!(err instanceof ApiError)) return undefined;
  const details = err.details;
  if (typeof details !== "object" || details === null) return undefined;
  const run = (details as { run?: WorkflowRunResult }).run;
  return run ? normalizeResult(run) : undefined;
}

export const listRuns = (limit?: number) =>
  call<{ runs: WorkflowRun[] }>({
    url: "/workflow-runs",
    method: "GET",
    params: limit ? { limit } : undefined,
  }).then((r) => (r.runs ?? []).map(normalizeRun));

export const getRun = (id: string) =>
  call<{ run: WorkflowRun }>({
    url: `/workflow-runs/${id}`,
    method: "GET",
  }).then((r) => normalizeRun(r.run));

// emergencyOffboard resolves with the per-layer leaver breakdown on success.
// On a completed offboard with layer failures the server returns 500 carrying
// the SAME breakdown under `leaver` (with `errored: true`), which `call`
// surfaces as an ApiError. The breakdown is preserved on `ApiError.details` —
// use `failedOffboardFromError` to recover it so the caller can render which
// layers failed instead of an opaque error, mirroring the Android/iOS SDKs.
//
// Identity is trimmed and required up-front, matching the Android/iOS SDK
// contract (both trim and throw InvalidInput on a blank id) so a direct caller
// can't send an empty user_external_id and we skip a guaranteed-400 round-trip.
// Reason is trimmed and omitted when blank, also mirroring the SDKs.
export const emergencyOffboard = (userExternalID: string, reason?: string) => {
  const externalID = userExternalID.trim();
  if (!externalID) {
    return Promise.reject(new ApiError(0, "user_external_id is required"));
  }
  return call<{ leaver: LeaverResult }>({
    url: "/emergency-offboard",
    method: "POST",
    data: { user_external_id: externalID, reason: reason?.trim() || undefined },
  }).then((r) => normalizeLeaver(r.leaver));
};

// failedOffboardFromError extracts the per-layer leaver breakdown a failed
// emergencyOffboard call carries on its ApiError (the 500 body's `leaver`),
// returning undefined when the error is not a partial-failure offboard (e.g. a
// 403 step-up-MFA or 404) so the caller falls through to the generic error
// path. Mirrors OkHttpAccessClient/URLSessionAccessClient, which likewise
// recover the LeaverResult from a 500 partial-failure body.
export function failedOffboardFromError(
  err: unknown,
): LeaverResult | undefined {
  if (!(err instanceof ApiError)) return undefined;
  const details = err.details;
  if (typeof details !== "object" || details === null) return undefined;
  const leaver = (details as { leaver?: LeaverResult }).leaver;
  return leaver ? normalizeLeaver(leaver) : undefined;
}

// Idiomatic Go marshals an empty slice as JSON null; the breakdown UI maps over
// `layers`, so normalize a missing/null slice to [] once here.
function normalizeLeaver(r: LeaverResult): LeaverResult {
  return { ...r, layers: r.layers ?? [] };
}

// Idiomatic Go marshals an empty slice as JSON null; the UI treats steps/layers
// as always-present arrays, so normalize here rather than guarding at every use.
function normalizeResult(r: WorkflowRunResult): WorkflowRunResult {
  return {
    ...r,
    steps: (r.steps ?? []).map((s) => ({ ...s, layers: s.layers ?? [] })),
  };
}

function normalizeRun(r: WorkflowRun): WorkflowRun {
  return {
    ...r,
    steps: (r.steps ?? []).map((s) => ({ ...s, layers: s.layers ?? [] })),
  };
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

export function useWorkflows() {
  return useQuery<Workflow[], ApiError>({
    queryKey: wfqk.workflows,
    queryFn: listWorkflows,
  });
}

export function useWorkflow(
  id: string | undefined,
  options?: Partial<UseQueryOptions<Workflow, ApiError>>,
) {
  return useQuery<Workflow, ApiError>({
    queryKey: wfqk.workflow(id ?? ""),
    queryFn: () => getWorkflow(id as string),
    enabled: !!id,
    ...options,
  });
}

export function useCreateWorkflow() {
  return useMutation<Workflow, ApiError, WorkflowInput>({
    mutationFn: createWorkflow,
  });
}

export function useUpdateWorkflow(id: string) {
  return useMutation<Workflow, ApiError, WorkflowInput>({
    mutationFn: (body) => updateWorkflow(id, body),
  });
}

export function useSimulateWorkflow(id: string) {
  return useMutation<WorkflowRunResult, ApiError, WorkflowSubject>({
    mutationFn: (subject) => simulateWorkflow(id, subject),
  });
}

export function usePublishWorkflow(id: string) {
  return useMutation<Workflow, ApiError, void>({
    mutationFn: () => publishWorkflow(id),
  });
}

export function useArchiveWorkflow(id: string) {
  return useMutation<Workflow, ApiError, void>({
    mutationFn: () => archiveWorkflow(id),
  });
}

export function useRunWorkflow(id: string) {
  return useMutation<WorkflowRunResult, ApiError, WorkflowSubject>({
    mutationFn: (subject) => runWorkflow(id, subject),
  });
}

export function useRuns(limit?: number) {
  return useQuery<WorkflowRun[], ApiError>({
    queryKey: wfqk.runs(limit),
    queryFn: () => listRuns(limit),
  });
}

export function useRun(
  id: string | undefined,
  options?: Partial<UseQueryOptions<WorkflowRun, ApiError>>,
) {
  return useQuery<WorkflowRun, ApiError>({
    queryKey: wfqk.run(id ?? ""),
    queryFn: () => getRun(id as string),
    enabled: !!id,
    ...options,
  });
}

export function useEmergencyOffboard() {
  return useMutation<
    LeaverResult,
    ApiError,
    { userExternalID: string; reason?: string }
  >({
    mutationFn: ({ userExternalID, reason }) =>
      emergencyOffboard(userExternalID, reason),
  });
}
