// Typed access-layer client for the ztna-api control plane.
//
// Every operation goes through `apiRequest` (api/http-client.ts), which injects
// the bearer token, Accept-Language, and base URL, and surfaces 401s globally.
// Responses are unwrapped from their gin.H envelope key (e.g. {"policy": …})
// here so callers work with domain types, not transport shapes.
//
// React-Query hooks live alongside the raw functions. A global MutationCache
// onSuccess (src/main.tsx) invalidates active queries after any mutation, so
// hooks here don't repeat per-call invalidation.

import {
  useMutation,
  useQuery,
  type UseQueryOptions,
} from "@tanstack/react-query";
import type { AxiosError } from "axios";
import { apiRequest } from "./http-client";

// ---------------------------------------------------------------------------
// Domain types (mirror internal/models + internal/services/lifecycle)
// ---------------------------------------------------------------------------

export type PolicyAction = "grant" | "deny";
export type PolicyState = "draft" | "active" | "archived";

/** The cartesian rule a policy encodes: {action} × {subjects} × {resources}. */
export interface PolicyDefinition {
  action: PolicyAction;
  subjects: string[];
  resources: string[];
  role?: string;
}

export interface ImpactReport {
  action: string;
  subject_count: number;
  resource_count: number;
  pair_count: number;
  new_grant_pairs: number;
  redundant_pairs: number;
  wildcard_resource: boolean;
  affected_grants: number;
}

export type ConflictKind = "grant_vs_deny" | "redundant";

export interface PolicyConflict {
  kind: ConflictKind;
  other_policy_id: string;
  other_policy_name: string;
  other_policy_state: string;
  subject: string;
  resource: string;
}

export interface SimulationResult {
  impact: ImpactReport;
  conflicts: PolicyConflict[];
}

export interface Policy {
  id: string;
  workspace_id: string;
  name: string;
  state: PolicyState;
  version: number;
  definition: PolicyDefinition;
  draft_impact?: ImpactReport | null;
  promoted_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface AccessRequest {
  id: string;
  workspace_id: string;
  requester_id: string;
  target_user_id?: string;
  connector_id?: string;
  resource_ref: string;
  role: string;
  justification: string;
  state: string;
  risk_level?: string;
  expires_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface AccessRequestHistoryEntry {
  id: string;
  request_id: string;
  from_state: string;
  to_state: string;
  actor: string;
  reason?: string;
  created_at: string;
}

export interface AccessGrant {
  id: string;
  workspace_id: string;
  request_id?: string;
  connector_id: string;
  iam_core_user_id: string;
  resource_ref: string;
  role: string;
  state: string;
  granted_at: string;
  expires_at?: string | null;
  revoked_at?: string | null;
}

export interface OrphanAccount {
  id: string;
  workspace_id: string;
  connector_id: string;
  external_user_id: string;
  display_name?: string;
  disposition: string;
  created_at: string;
}

export interface Me {
  user_id: string;
  tenant_id: string;
  roles: string[];
  scopes: string[];
  mfa_satisfied: boolean;
}

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

/**
 * Normalized API error. `conflicts` is populated on a 409 from the promote
 * endpoint (grant-vs-deny block), so the editor can render the offending
 * pairs and offer the audited-override path.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly conflicts?: PolicyConflict[];
  constructor(status: number, message: string, conflicts?: PolicyConflict[]) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.conflicts = conflicts;
  }
}

interface ApiErrorBody {
  error?: string;
  conflicts?: PolicyConflict[];
}

/** Coerce an axios failure into an ApiError with the server's message/conflicts. */
export function toApiError(err: unknown): ApiError {
  const ax = err as AxiosError<ApiErrorBody>;
  if (ax?.isAxiosError) {
    const status = ax.response?.status ?? 0;
    const body = ax.response?.data;
    const message =
      body?.error ?? ax.message ?? "Request failed. Please try again.";
    return new ApiError(status, message, body?.conflicts);
  }
  if (err instanceof Error) return new ApiError(0, err.message);
  return new ApiError(0, "Unknown error");
}

// A request that normalizes any thrown error into ApiError.
async function call<T>(config: Parameters<typeof apiRequest>[0]): Promise<T> {
  try {
    return await apiRequest<T>(config);
  } catch (err) {
    throw toApiError(err);
  }
}

// ---------------------------------------------------------------------------
// Query keys
// ---------------------------------------------------------------------------

export const qk = {
  me: ["me"] as const,
  policies: ["policies"] as const,
  policy: (id: string) => ["policy", id] as const,
  packs: (filter: PackFilter) => ["packs", filter] as const,
  pack: (id: string) => ["pack", id] as const,
  requests: ["access-requests"] as const,
  request: (id: string) => ["access-request", id] as const,
  requestHistory: (id: string) => ["access-request", id, "history"] as const,
  orphans: ["orphan-accounts"] as const,
};

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

export const getMe = () => call<Me>({ url: "/me", method: "GET" });

export function useMe(options?: Partial<UseQueryOptions<Me, ApiError>>) {
  return useQuery<Me, ApiError>({
    queryKey: qk.me,
    queryFn: getMe,
    staleTime: 5 * 60_000,
    ...options,
  });
}

// ---------------------------------------------------------------------------
// Policies — draft → simulate → promote
// ---------------------------------------------------------------------------

export const listPolicies = () =>
  call<{ policies: Policy[] }>({ url: "/policies", method: "GET" }).then(
    (r) => r.policies ?? [],
  );

export const getPolicy = (id: string) =>
  call<{ policy: Policy }>({ url: `/policies/${id}`, method: "GET" }).then(
    (r) => r.policy,
  );

export interface PolicyInput {
  name: string;
  definition: PolicyDefinition;
}

export const createPolicy = (body: PolicyInput) =>
  call<{ policy: Policy }>({
    url: "/policies",
    method: "POST",
    data: body,
  }).then((r) => r.policy);

export const updatePolicy = (id: string, body: PolicyInput) =>
  call<{ policy: Policy }>({
    url: `/policies/${id}`,
    method: "PUT",
    data: body,
  }).then((r) => r.policy);

export const simulatePolicy = (id: string) =>
  call<{ simulation: SimulationResult }>({
    url: `/policies/${id}/simulate`,
    method: "POST",
  }).then((r) => ({
    // The API omits an empty conflict slice as JSON null (idiomatic Go); the
    // UI treats conflicts as an always-present array, so normalize here.
    ...r.simulation,
    conflicts: r.simulation.conflicts ?? [],
  }));

export interface PromoteInput {
  force?: boolean;
  reason?: string;
}

export const promotePolicy = (id: string, body?: PromoteInput) =>
  call<{ policy: Policy }>({
    url: `/policies/${id}/promote`,
    method: "POST",
    data: body ?? {},
  }).then((r) => r.policy);

export const archivePolicy = (id: string) =>
  call<{ policy: Policy }>({
    url: `/policies/${id}/archive`,
    method: "POST",
  }).then((r) => r.policy);

export function usePolicies() {
  return useQuery<Policy[], ApiError>({
    queryKey: qk.policies,
    queryFn: listPolicies,
  });
}

export function usePolicy(
  id: string | undefined,
  options?: Partial<UseQueryOptions<Policy, ApiError>>,
) {
  return useQuery<Policy, ApiError>({
    queryKey: qk.policy(id ?? ""),
    queryFn: () => getPolicy(id as string),
    enabled: !!id,
    ...options,
  });
}

export function useCreatePolicy() {
  return useMutation<Policy, ApiError, PolicyInput>({
    mutationFn: createPolicy,
  });
}

export function useUpdatePolicy(id: string) {
  return useMutation<Policy, ApiError, PolicyInput>({
    mutationFn: (body) => updatePolicy(id, body),
  });
}

export function useSimulatePolicy(id: string) {
  return useMutation<SimulationResult, ApiError, void>({
    mutationFn: () => simulatePolicy(id),
  });
}

export function usePromotePolicy(id: string) {
  return useMutation<Policy, ApiError, PromoteInput | undefined>({
    mutationFn: (body) => promotePolicy(id, body),
  });
}

export function useArchivePolicy(id: string) {
  return useMutation<Policy, ApiError, void>({
    mutationFn: () => archivePolicy(id),
  });
}

// ---------------------------------------------------------------------------
// Policy packs — curated templates that materialize as DRAFT policies
// ---------------------------------------------------------------------------

/** One smart-default access rule inside a pack. */
export interface PackTemplate {
  key: string;
  name: string;
  summary: string;
  action: PolicyAction;
  subjects: string[];
  resources: string[];
  role?: string;
  control: string;
}

export interface Pack {
  id: string;
  name: string;
  authority: string;
  description: string;
  tier: 1 | 2 | 3;
  regions: string[];
  industries: string[];
  frameworks: string[];
  templates: PackTemplate[];
}

export interface PackFilter {
  tier?: number;
  region?: string;
  industry?: string;
  framework?: string;
}

/** A draft materialized from a pack template, paired with its source key. */
export interface AppliedPolicy {
  template_key: string;
  policy: Policy;
}

export const listPacks = (filter: PackFilter = {}) => {
  const params = new URLSearchParams();
  if (filter.tier) params.set("tier", String(filter.tier));
  if (filter.region) params.set("region", filter.region);
  if (filter.industry) params.set("industry", filter.industry);
  if (filter.framework) params.set("framework", filter.framework);
  const qs = params.toString();
  return call<{ packs: Pack[] }>({
    url: qs ? `/packs?${qs}` : "/packs",
    method: "GET",
  }).then((r) => r.packs ?? []);
};

export const getPack = (id: string) =>
  call<{ pack: Pack }>({ url: `/packs/${id}`, method: "GET" }).then(
    (r) => r.pack,
  );

export const applyPack = (id: string, templateKeys?: string[]) =>
  call<{ applied: AppliedPolicy[]; count: number }>({
    url: `/packs/${id}/apply`,
    method: "POST",
    // Omit the field entirely (rather than send []) when applying the whole
    // pack — the API treats empty/absent as "all templates".
    data: templateKeys && templateKeys.length ? { template_keys: templateKeys } : {},
  });

export function usePacks(filter: PackFilter = {}) {
  return useQuery<Pack[], ApiError>({
    queryKey: qk.packs(filter),
    queryFn: () => listPacks(filter),
  });
}

export function usePack(id: string | undefined) {
  return useQuery<Pack, ApiError>({
    queryKey: qk.pack(id ?? ""),
    queryFn: () => getPack(id as string),
    enabled: !!id,
  });
}

export function useApplyPack(id: string) {
  return useMutation<
    { applied: AppliedPolicy[]; count: number },
    ApiError,
    string[] | undefined
  >({
    mutationFn: (templateKeys) => applyPack(id, templateKeys),
  });
}

// ---------------------------------------------------------------------------
// Access requests (JML provisioning lane)
// ---------------------------------------------------------------------------

export const listRequests = () =>
  call<{ requests: AccessRequest[] }>({
    url: "/access-requests",
    method: "GET",
  }).then((r) => r.requests ?? []);

export const getRequest = (id: string) =>
  call<{ request: AccessRequest }>({
    url: `/access-requests/${id}`,
    method: "GET",
  }).then((r) => r.request);

export const getRequestHistory = (id: string) =>
  call<{ history: AccessRequestHistoryEntry[] }>({
    url: `/access-requests/${id}/history`,
    method: "GET",
  }).then((r) => r.history ?? []);

export interface CreateRequestInput {
  target_user_id?: string;
  connector_id?: string;
  resource_ref: string;
  role?: string;
  justification: string;
}

export const createRequest = (body: CreateRequestInput) =>
  call<{ request: AccessRequest }>({
    url: "/access-requests",
    method: "POST",
    data: body,
  }).then((r) => r.request);

type RequestAction = "approve" | "deny" | "cancel" | "provision";

const requestAction = (id: string, action: RequestAction, reason?: string) =>
  call<{ request?: AccessRequest; grant?: AccessGrant }>({
    url: `/access-requests/${id}/${action}`,
    method: "POST",
    data: reason ? { reason } : {},
  });

export function useAccessRequests() {
  return useQuery<AccessRequest[], ApiError>({
    queryKey: qk.requests,
    queryFn: listRequests,
  });
}

export function useAccessRequest(id: string | undefined) {
  return useQuery<AccessRequest, ApiError>({
    queryKey: qk.request(id ?? ""),
    queryFn: () => getRequest(id as string),
    enabled: !!id,
  });
}

export function useRequestHistory(id: string | undefined) {
  return useQuery<AccessRequestHistoryEntry[], ApiError>({
    queryKey: qk.requestHistory(id ?? ""),
    queryFn: () => getRequestHistory(id as string),
    enabled: !!id,
  });
}

export function useCreateRequest() {
  return useMutation<AccessRequest, ApiError, CreateRequestInput>({
    mutationFn: createRequest,
  });
}

export function useRequestAction(id: string) {
  return useMutation<
    { request?: AccessRequest; grant?: AccessGrant },
    ApiError,
    { action: RequestAction; reason?: string }
  >({
    mutationFn: ({ action, reason }) => requestAction(id, action, reason),
  });
}

// ---------------------------------------------------------------------------
// Directory — orphan accounts (leaver / un-grant detection)
// ---------------------------------------------------------------------------

export const listOrphans = () =>
  call<{ orphans: OrphanAccount[] }>({
    url: "/orphan-accounts",
    method: "GET",
  }).then((r) => r.orphans ?? []);

export const setOrphanDisposition = (id: string, disposition: string) =>
  call<{ status: string }>({
    url: `/orphan-accounts/${id}/disposition`,
    method: "POST",
    data: { disposition },
  });

export function useOrphans() {
  return useQuery<OrphanAccount[], ApiError>({
    queryKey: qk.orphans,
    queryFn: listOrphans,
  });
}

export function useSetOrphanDisposition(id: string) {
  return useMutation<{ status: string }, ApiError, string>({
    mutationFn: (disposition) => setOrphanDisposition(id, disposition),
  });
}

// ---------------------------------------------------------------------------
// PAM — targets, JIT leases, sessions, live session control (WS4)
//
// Mirrors internal/models (PAMTarget, PAMLease, PAMSession) and the REST surface
// in internal/handlers/pam.go. The lease state is the server-derived machine
// state (requested → approved → active → expired/revoked); the broker turns an
// approved lease active on first session open, so the UI renders state from the
// server rather than re-deriving it from timestamps.
// ---------------------------------------------------------------------------

export type PamProtocol =
  | "ssh"
  | "postgres"
  | "mysql"
  | "mssql"
  | "mongodb"
  | "redis"
  | "k8s-exec"
  | "rdp"
  | "vnc"
  | "http";

export type PamLeaseState =
  | "requested"
  | "approved"
  | "active"
  | "expired"
  | "revoked";

export interface PamTarget {
  id: string;
  workspace_id: string;
  name: string;
  protocol: string;
  address: string;
  username: string;
  require_mfa: boolean;
  lease_ttl_seconds: number;
  secret_rotated_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface PamLease {
  id: string;
  workspace_id: string;
  target_id: string;
  subject: string;
  requested_by: string;
  reason?: string;
  request_id?: string;
  approved_by?: string;
  requested_ttl_seconds: number;
  risk_level?: string;
  risk_reason?: string;
  risk_degraded: boolean;
  granted_at?: string | null;
  activated_at?: string | null;
  expires_at?: string | null;
  expired_at?: string | null;
  revoked_at?: string | null;
  revoke_reason?: string;
  state: PamLeaseState;
  created_at: string;
  updated_at: string;
}

export interface PamSession {
  id: string;
  workspace_id: string;
  target_id: string;
  subject: string;
  protocol: string;
  state: string;
  client_addr?: string;
  replay_key?: string;
  started_at: string;
  ended_at?: string | null;
  terminated_by?: string;
  lease_id?: string;
  paused: boolean;
  paused_by?: string;
  paused_at?: string | null;
}

export interface ReplayFrame {
  direction: string;
  at: string;
  payload: string; // base64
}

export interface ReplayResponse {
  session_id: string;
  frames: ReplayFrame[];
  truncated: boolean;
}

export interface CreatePamTargetInput {
  name: string;
  protocol: string;
  address: string;
  username?: string;
  require_mfa?: boolean;
  lease_ttl_seconds?: number;
  secret: {
    username?: string;
    password?: string;
    private_key?: string;
    token?: string;
  };
}

export interface RequestPamLeaseInput {
  target_id: string;
  subject?: string;
  ttl_seconds?: number;
  reason?: string;
  request_id?: string;
}

export interface PamSessionFilters {
  target_id?: string;
  subject?: string;
  active_only?: boolean;
}

const pamSessionParams = (f: PamSessionFilters = {}) => ({
  ...(f.target_id ? { target_id: f.target_id } : {}),
  ...(f.subject ? { subject: f.subject } : {}),
  ...(f.active_only ? { active_only: "true" } : {}),
});

export const listPamTargets = () =>
  call<{ targets: PamTarget[] }>({ url: "/pam/targets", method: "GET" }).then(
    (r) => r.targets ?? [],
  );

export const createPamTarget = (body: CreatePamTargetInput) =>
  call<PamTarget>({ url: "/pam/targets", method: "POST", data: body });

export const listPamLeases = (f: PamSessionFilters = {}) =>
  call<{ leases: PamLease[] }>({
    url: "/pam/leases",
    method: "GET",
    params: pamSessionParams(f),
  }).then((r) => r.leases ?? []);

export const getPamLease = (id: string) =>
  call<PamLease>({ url: `/pam/leases/${id}`, method: "GET" });

export const requestPamLease = (body: RequestPamLeaseInput) =>
  call<PamLease>({ url: "/pam/leases", method: "POST", data: body });

export const approvePamLease = (id: string, durationOverrideSeconds?: number) =>
  call<PamLease>({
    url: `/pam/leases/${id}/approve`,
    method: "POST",
    data: durationOverrideSeconds
      ? { duration_override_seconds: durationOverrideSeconds }
      : {},
  });

export const revokePamLease = (id: string, reason?: string) =>
  call<PamLease>({
    url: `/pam/leases/${id}/revoke`,
    method: "POST",
    data: { reason: reason ?? "" },
  });

export const listPamSessions = (f: PamSessionFilters = {}) =>
  call<{ sessions: PamSession[] }>({
    url: "/pam/sessions",
    method: "GET",
    params: pamSessionParams(f),
  }).then((r) => r.sessions ?? []);

export const getPamSession = (id: string) =>
  call<PamSession>({ url: `/pam/sessions/${id}`, method: "GET" });

export const getPamSessionReplay = (id: string) =>
  call<ReplayResponse>({ url: `/pam/sessions/${id}/replay`, method: "GET" });

export const pausePamSession = (id: string) =>
  call<{ status: string }>({
    url: `/pam/sessions/${id}/pause`,
    method: "POST",
  });

export const resumePamSession = (id: string) =>
  call<{ status: string }>({
    url: `/pam/sessions/${id}/resume`,
    method: "POST",
  });

export const terminatePamSession = (id: string) =>
  call<{ status: string }>({
    url: `/pam/sessions/${id}/terminate`,
    method: "POST",
  });

export const pamQk = {
  targets: ["pam-targets"] as const,
  leases: (f: PamSessionFilters = {}) => ["pam-leases", f] as const,
  lease: (id: string) => ["pam-lease", id] as const,
  sessions: (f: PamSessionFilters = {}) => ["pam-sessions", f] as const,
  session: (id: string) => ["pam-session", id] as const,
  replay: (id: string) => ["pam-session", id, "replay"] as const,
};

export function usePamTargets() {
  return useQuery<PamTarget[], ApiError>({
    queryKey: pamQk.targets,
    queryFn: listPamTargets,
  });
}

export function useCreatePamTarget() {
  return useMutation<PamTarget, ApiError, CreatePamTargetInput>({
    mutationFn: createPamTarget,
  });
}

export function usePamLeases(f: PamSessionFilters = {}) {
  return useQuery<PamLease[], ApiError>({
    queryKey: pamQk.leases(f),
    queryFn: () => listPamLeases(f),
  });
}

export function usePamLease(
  id: string | undefined,
  options?: Partial<UseQueryOptions<PamLease, ApiError>>,
) {
  return useQuery<PamLease, ApiError>({
    queryKey: pamQk.lease(id ?? ""),
    queryFn: () => getPamLease(id as string),
    enabled: !!id,
    ...options,
  });
}

export function useRequestPamLease() {
  return useMutation<PamLease, ApiError, RequestPamLeaseInput>({
    mutationFn: requestPamLease,
  });
}

export function useApprovePamLease(id: string) {
  return useMutation<PamLease, ApiError, number | undefined>({
    mutationFn: (durationOverrideSeconds) =>
      approvePamLease(id, durationOverrideSeconds),
  });
}

export function useRevokePamLease(id: string) {
  return useMutation<PamLease, ApiError, string | undefined>({
    mutationFn: (reason) => revokePamLease(id, reason),
  });
}

export function usePamSessions(
  f: PamSessionFilters = {},
  options?: Partial<UseQueryOptions<PamSession[], ApiError>>,
) {
  return useQuery<PamSession[], ApiError>({
    queryKey: pamQk.sessions(f),
    queryFn: () => listPamSessions(f),
    ...options,
  });
}

export function usePamSession(id: string | undefined) {
  return useQuery<PamSession, ApiError>({
    queryKey: pamQk.session(id ?? ""),
    queryFn: () => getPamSession(id as string),
    enabled: !!id,
  });
}

export function useSessionReplay(
  id: string | undefined,
  options?: Partial<UseQueryOptions<ReplayResponse, ApiError>>,
) {
  return useQuery<ReplayResponse, ApiError>({
    queryKey: pamQk.replay(id ?? ""),
    queryFn: () => getPamSessionReplay(id as string),
    enabled: !!id,
    ...options,
  });
}

export function usePausePamSession(id: string) {
  return useMutation<{ status: string }, ApiError, void>({
    mutationFn: () => pausePamSession(id),
  });
}

export function useResumePamSession(id: string) {
  return useMutation<{ status: string }, ApiError, void>({
    mutationFn: () => resumePamSession(id),
  });
}

export function useTerminatePamSession(id: string) {
  return useMutation<{ status: string }, ApiError, void>({
    mutationFn: () => terminatePamSession(id),
  });
}
