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

// Routing-facing AI recommendation, mirroring the Go
// lifecycle.Recommendation* constants. The control plane derives this
// authoritatively from the normalized risk band; the UI only ever displays it
// and NEVER uses it to silently auto-approve a high-risk request.
export type RiskRecommendation =
  | "auto_approve_eligible"
  | "needs_review"
  | "high_risk";

// RiskVerdict is one immutable AI risk assessment persisted against a request.
// `degraded` is true when the AI agent was unreachable and the fail-open
// fallback supplied the verdict (never auto_approve_eligible), so the UI can
// distinguish an AI-derived score from a degraded one.
export interface RiskVerdict {
  id: string;
  request_id: string;
  score: string;
  recommendation: RiskRecommendation;
  factors?: string[];
  rationale?: string;
  source: string;
  degraded: boolean;
  created_at: string;
}

// AnomalyFlag is one advisory observation from the anomaly-detection skill
// surfaced against an approved elevation. Advisory only — never an enforcement
// gate.
export interface AnomalyFlag {
  id: string;
  request_id: string;
  grant_id?: string;
  kind: string;
  severity?: string;
  reason?: string;
  confidence?: number;
  created_at: string;
}

// WorkflowDecision is the routing outcome returned by the create flow: which
// lane the request was placed in and whether it was auto-approved (true only
// for the low-risk auto_approve lane).
export interface WorkflowDecision {
  step_type: string;
  reason: string;
  approved: boolean;
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
  // The full parsed response body. Some endpoints return a structured payload
  // alongside a non-2xx status that callers need (e.g. the workflow /run 500
  // carries the per-step failure breakdown under `run`); preserving the raw
  // body here keeps it from being discarded by the generic error path.
  readonly details?: unknown;
  constructor(
    status: number,
    message: string,
    conflicts?: PolicyConflict[],
    details?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.conflicts = conflicts;
    this.details = details;
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
    return new ApiError(status, message, body?.conflicts, body);
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
  rbacRoles: ["rbac", "roles"] as const,
  rbacMembers: ["rbac", "members"] as const,
  connectors: (filter: ConnectorCatalogueFilter) =>
    ["connectors", filter] as const,
  connector: (provider: string) => ["connector", provider] as const,
  connectorFacets: ["connector-facets"] as const,
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

/**
 * Header carrying the step-up MFA assertion (a 6-digit TOTP code, or a WebAuthn
 * assertion JSON blob) for a high-risk action. Must match the server constant
 * middleware.StepUpAssertionHeader in internal/middleware/stepup.go.
 */
export const STEP_UP_ASSERTION_HEADER = "X-MFA-Assertion";

export interface PromoteInput {
  force?: boolean;
  reason?: string;
  /**
   * Step-up MFA assertion sent as the X-MFA-Assertion header (NOT part of the
   * JSON body) to satisfy the server's RequireStepUpMFA gate on promote. When
   * omitted the server replies 400 ("step-up MFA assertion required") so the
   * UI can prompt for it; a wrong/replayed code yields 403.
   */
  mfaAssertion?: string;
}

export const promotePolicy = (id: string, body?: PromoteInput) => {
  const { mfaAssertion, ...rest } = body ?? {};
  return call<{ policy: Policy }>({
    url: `/policies/${encodeURIComponent(id)}/promote`,
    method: "POST",
    data: rest,
    headers: mfaAssertion
      ? { [STEP_UP_ASSERTION_HEADER]: mfaAssertion }
      : undefined,
  }).then((r) => r.policy);
};

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

// RequestDetailResult is the request plus its operative AI risk verdict and any
// advisory anomaly flags. `risk` is absent for requests created before WS5 (no
// verdict was ever persisted); `anomalies` is empty until an approved elevation
// is scored by the anomaly skill.
export interface RequestDetailResult {
  request: AccessRequest;
  risk?: RiskVerdict;
  anomalies?: AnomalyFlag[];
}

export const getRequest = (id: string) =>
  call<RequestDetailResult>({
    url: `/access-requests/${id}`,
    method: "GET",
  });

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
  // Model-input signals for the server-side AI risk review. The client never
  // supplies a risk level — the AI gate is the sole source of the verdict.
  resource_tags?: string[];
  duration_hours?: number;
}

// CreateRequestResult carries the created request, the AI risk verdict produced
// synchronously by the server-side gate, and the routing decision so the create
// flow can show the risk panel inline immediately after submission.
export interface CreateRequestResult {
  request: AccessRequest;
  risk: RiskVerdict;
  workflow: WorkflowDecision;
}

export const createRequest = (body: CreateRequestInput) =>
  call<CreateRequestResult>({
    url: "/access-requests",
    method: "POST",
    data: body,
  });

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
  return useQuery<RequestDetailResult, ApiError>({
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
  return useMutation<CreateRequestResult, ApiError, CreateRequestInput>({
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
// RBAC — workspace roles, the permission matrix, and membership administration
// ---------------------------------------------------------------------------

/** One workspace role and the flat permission set it grants. */
export interface RbacRole {
  role: string;
  permissions: string[];
}

/** The role catalogue plus the flat list of every permission (matrix columns). */
export interface RbacCatalog {
  roles: RbacRole[];
  permissions: string[];
}

/** A single membership in the caller's workspace. */
export interface RbacMember {
  user_id: string;
  role: string;
  created_at: string;
  updated_at: string;
}

export const listRbacRoles = () =>
  call<RbacCatalog>({ url: "/rbac/roles", method: "GET" }).then((r) => ({
    roles: r.roles ?? [],
    permissions: r.permissions ?? [],
  }));

export const listRbacMembers = () =>
  call<{ members: RbacMember[] }>({ url: "/rbac/members", method: "GET" }).then(
    (r) => r.members ?? [],
  );

export const assignRbacMember = (userId: string, role: string) =>
  call<RbacMember>({
    url: `/rbac/members/${encodeURIComponent(userId)}`,
    method: "PUT",
    data: { role },
  });

export function useRbacRoles(
  options?: Partial<UseQueryOptions<RbacCatalog, ApiError>>,
) {
  return useQuery<RbacCatalog, ApiError>({
    queryKey: qk.rbacRoles,
    queryFn: listRbacRoles,
    staleTime: 5 * 60_000,
    ...options,
  });
}

export function useRbacMembers(
  options?: Partial<UseQueryOptions<RbacMember[], ApiError>>,
) {
  return useQuery<RbacMember[], ApiError>({
    queryKey: qk.rbacMembers,
    queryFn: listRbacMembers,
    ...options,
  });
}

export function useAssignRbacMember() {
  return useMutation<RbacMember, ApiError, { userId: string; role: string }>({
    mutationFn: ({ userId, role }) => assignRbacMember(userId, role),
  });
}

// ---------------------------------------------------------------------------
// Connector fabric — capability matrix + AI-assisted setup wizard
//
// Types mirror internal/services/access (CapabilityDescriptor, catalogue
// entry, facets), internal/pkg/aiclient (setup plan), and internal/models
// (AccessConnector). The catalogue is the single source of truth for "which
// connectors does this binary ship and what can each one do?" — enriched
// per-workspace with whether the operator has already connected each provider.
// ---------------------------------------------------------------------------

/** The five user-facing capability flags surfaced in the matrix. */
export interface UserFacingCapabilities {
  sync_identity: boolean;
  provision_access: boolean;
  list_entitlements: boolean;
  get_access_log: boolean;
  sso_federation: boolean;
}

/**
 * The seven operational capabilities, derived server-side by type-asserting
 * the registered connector against the optional Go interfaces — so they can
 * never drift from the shipped binary.
 */
export interface OperationalCapabilities {
  group_sync: boolean;
  identity_delta_sync: boolean;
  access_audit_stream: boolean;
  scim_provisioning: boolean;
  session_revoke: boolean;
  sso_enforcement_check: boolean;
  credential_renewal: boolean;
}

/** One row of the capability matrix, with this workspace's connection state. */
export interface ConnectorCatalogueEntry {
  provider: string;
  display_name: string;
  tier: string;
  category: string;
  registered: boolean;
  user_facing: UserFacingCapabilities;
  operational: OperationalCapabilities;
  connected: boolean;
  connector_id?: string;
  status?: string;
}

/** Distinct filter vocabularies present across the whole catalogue. */
export interface CatalogueFacets {
  tiers: string[];
  categories: string[];
  user_facing_capabilities: string[];
  operational_capabilities: string[];
}

export interface ConnectorCatalogueFilter {
  capability?: string;
  tier?: string;
  category?: string;
  connected?: boolean;
}

export interface ConnectorSetupFieldMapping {
  source: string;
  target: string;
  /** True when the source boolean has opposite polarity to the target (e.g.
   * Google `suspended` → platform `active`) and must be negated on sync. */
  invert?: boolean;
}

export interface ConnectorSetupStep {
  step: number;
  title: string;
  description: string;
  required_scopes?: string[];
  field_mappings?: ConnectorSetupFieldMapping[];
  common_pitfalls?: string[];
  estimated_minutes?: number;
}

export interface ConnectorSetupPlan {
  strategy: string;
  explanation: string;
  steps: ConnectorSetupStep[];
  model_used: boolean;
  /** True when the AI agent was unavailable and the plan is the deterministic
   *  manual fallback — the wizard is fail-OPEN, so a model outage degrades to
   *  a manual plan rather than blocking the operator. */
  degraded: boolean;
}

export interface ConnectorSetupResult {
  suggestion_id: string;
  plan: ConnectorSetupPlan;
}

export interface AccessConnector {
  id: string;
  workspace_id: string;
  provider: string;
  display_name: string;
  status: string;
  config?: Record<string, unknown> | null;
  last_synced_at?: string | null;
  created_at: string;
  updated_at: string;
}

export const listConnectors = (filter: ConnectorCatalogueFilter = {}) => {
  const params = new URLSearchParams();
  if (filter.capability) params.set("capability", filter.capability);
  if (filter.tier) params.set("tier", filter.tier);
  if (filter.category) params.set("category", filter.category);
  if (filter.connected !== undefined)
    params.set("connected", String(filter.connected));
  const qs = params.toString();
  return call<{ connectors: ConnectorCatalogueEntry[] }>({
    url: qs ? `/connectors?${qs}` : "/connectors",
    method: "GET",
  }).then((r) => r.connectors ?? []);
};

export const getConnectorCatalogueEntry = (provider: string) =>
  call<ConnectorCatalogueEntry>({
    url: `/connectors/catalogue/${encodeURIComponent(provider)}`,
    method: "GET",
  });

export const getConnectorFacets = () =>
  call<CatalogueFacets>({
    url: "/connectors/catalogue/facets",
    method: "GET",
  });

export interface SetupWizardInput {
  admin_intent?: string;
  connector_id?: string;
}

export const requestSetupPlan = (provider: string, body: SetupWizardInput) =>
  call<ConnectorSetupResult>({
    url: `/connectors/catalogue/${encodeURIComponent(provider)}/setup-wizard`,
    method: "POST",
    data: body,
  });

export interface CreateConnectorInput {
  provider: string;
  display_name?: string;
  config?: Record<string, unknown>;
  secrets?: Record<string, unknown>;
}

export const createConnector = (body: CreateConnectorInput) =>
  call<AccessConnector>({
    url: "/connectors",
    method: "POST",
    data: body,
  });

export function useConnectors(filter: ConnectorCatalogueFilter = {}) {
  return useQuery<ConnectorCatalogueEntry[], ApiError>({
    queryKey: qk.connectors(filter),
    queryFn: () => listConnectors(filter),
  });
}

export function useConnectorCatalogueEntry(provider: string | undefined) {
  return useQuery<ConnectorCatalogueEntry, ApiError>({
    queryKey: qk.connector(provider ?? ""),
    queryFn: () => getConnectorCatalogueEntry(provider as string),
    enabled: !!provider,
  });
}

export function useConnectorFacets() {
  return useQuery<CatalogueFacets, ApiError>({
    queryKey: qk.connectorFacets,
    queryFn: getConnectorFacets,
    staleTime: 5 * 60_000,
  });
}

export function useRequestSetupPlan(provider: string) {
  return useMutation<ConnectorSetupResult, ApiError, SetupWizardInput>({
    mutationFn: (body) => requestSetupPlan(provider, body),
  });
}

export function useCreateConnector() {
  return useMutation<AccessConnector, ApiError, CreateConnectorInput>({
    mutationFn: createConnector,
  });
}
