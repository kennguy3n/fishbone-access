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
import { apiDownload, apiRequest } from "./http-client";

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
  evidence: (filter: EvidenceFilter) =>
    ["compliance-evidence", filter] as const,
  coverage: (framework: string, from?: string, to?: string) =>
    ["compliance-coverage", framework, from ?? null, to ?? null] as const,
  chainVerify: ["compliance-chain-verify"] as const,
  campaigns: ["certification-campaigns"] as const,
  campaign: (id: string) => ["certification-campaign", id] as const,
  campaignItems: (id: string, reviewer?: string) =>
    ["certification-campaign", id, "items", reviewer ?? ""] as const,
  revocationPreview: (id: string) =>
    ["certification-campaign", id, "revocation-preview"] as const,
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
// Compliance — evidence stream, certification campaigns, evidence-pack export
// (mirror internal/services/compliance + internal/handlers/compliance.go)
// ---------------------------------------------------------------------------

/** Control-relevant classification of an audit-chain event (compliance.EvidenceKind). */
export type EvidenceKind = string;

/** Compliance frameworks the evidence pack can be mapped to. */
export const FRAMEWORKS = ["SOC 2", "ISO 27001", "PCI-DSS"] as const;
export type Framework = (typeof FRAMEWORKS)[number];

/** One evidence record — a control-labelled view of an audit-chain entry. */
export interface EvidenceRecord {
  id: string;
  workspace_id: string;
  chain_seq: number;
  kind: EvidenceKind;
  action: string;
  actor: string;
  target_ref?: string;
  metadata?: unknown;
  prev_hash?: string;
  chain_hash: string;
  occurred_at: string;
}

export interface EvidenceFilter {
  from?: string;
  to?: string;
  kinds?: EvidenceKind[];
  controlled_only?: boolean;
  limit?: number;
}

/** Result of recomputing the audit hash chain (compliance.ChainVerification). */
export interface ChainVerification {
  workspace_id: string;
  ok: boolean;
  length: number;
  status: string;
  broken_at_seq?: number;
  reason?: string;
  /**
   * Rows that predate the canonical (recomputable) hash format and are
   * validated by chain linkage only. Non-zero is not a failure — it means the
   * chain spans a pre-verification baseline; it is omitted when zero.
   */
  legacy_unverified?: number;
}

export interface ControlCoverage {
  id: string;
  title: string;
  covered: boolean;
  evidence_count: number;
  by_kind?: Record<string, number>;
  kinds: EvidenceKind[];
}

export interface FrameworkCoverage {
  framework: Framework;
  from?: string;
  to?: string;
  controls: ControlCoverage[];
  controls_total: number;
  controls_covered: number;
  evidence_total: number;
}

export interface CertificationCampaign {
  id: string;
  workspace_id: string;
  name: string;
  state: string;
  framework?: string;
  scope_resource?: string;
  scope_role?: string;
  scope_connector_id?: string;
  reviewers?: string[];
  due_at?: string | null;
  started_at?: string | null;
  closed_at?: string | null;
  overdue_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface CampaignItemView {
  item_id: string;
  grant_id: string;
  resource_ref: string;
  role: string;
  subject: string;
  reviewer?: string;
  decision: string;
  decided_by?: string;
  decided_at?: string | null;
  reason?: string;
  revoked_at?: string | null;
}

export interface CampaignReport {
  campaign_id: string;
  name: string;
  state: string;
  framework?: string;
  total: number;
  pending: number;
  certified: number;
  revoked: number;
  escalated: number;
  due_at?: string | null;
  overdue: boolean;
  all_decided: boolean;
}

export interface RevocationPreview {
  item_id: string;
  grant_id: string;
  resource_ref: string;
  role: string;
  subject: string;
  decided_by: string;
  reason: string;
}

export interface StartCampaignInput {
  name: string;
  framework?: string;
  scope_resource?: string;
  scope_role?: string;
  scope_connector_id?: string;
  reviewers?: string[];
  due_at?: string | null;
}

export interface DecisionInput {
  decision: "certify" | "revoke" | "escalate";
  reason?: string;
}

// --- evidence stream + coverage + chain ---

function evidenceParams(filter: EvidenceFilter): Record<string, string> {
  const params: Record<string, string> = {};
  if (filter.from) params.from = filter.from;
  if (filter.to) params.to = filter.to;
  if (filter.kinds && filter.kinds.length > 0)
    params.kinds = filter.kinds.join(",");
  if (filter.controlled_only) params.controlled_only = "true";
  if (filter.limit != null) params.limit = String(filter.limit);
  return params;
}

export const listEvidence = (filter: EvidenceFilter = {}) =>
  call<{ records: EvidenceRecord[]; count: number }>({
    url: "/compliance/evidence",
    method: "GET",
    params: evidenceParams(filter),
  }).then((r) => r.records ?? []);

export const getCoverage = (framework: string, from?: string, to?: string) =>
  call<FrameworkCoverage>({
    url: "/compliance/coverage",
    method: "GET",
    params: { framework, ...(from ? { from } : {}), ...(to ? { to } : {}) },
  });

export const verifyChain = () =>
  call<ChainVerification>({
    url: "/compliance/chain/verify",
    method: "GET",
  });

export function useEvidence(filter: EvidenceFilter = {}) {
  return useQuery<EvidenceRecord[], ApiError>({
    queryKey: qk.evidence(filter),
    queryFn: () => listEvidence(filter),
  });
}

export function useCoverage(
  framework: string,
  from?: string,
  to?: string,
  options?: Partial<UseQueryOptions<FrameworkCoverage, ApiError>>,
) {
  return useQuery<FrameworkCoverage, ApiError>({
    queryKey: qk.coverage(framework, from, to),
    queryFn: () => getCoverage(framework, from, to),
    ...options,
  });
}

export function useChainVerification(
  options?: Partial<UseQueryOptions<ChainVerification, ApiError>>,
) {
  return useQuery<ChainVerification, ApiError>({
    queryKey: qk.chainVerify,
    queryFn: verifyChain,
    ...options,
  });
}

// --- certification campaigns ---

export const listCampaigns = () =>
  call<{ campaigns: CertificationCampaign[] }>({
    url: "/compliance/campaigns",
    method: "GET",
  }).then((r) => r.campaigns ?? []);

export const startCampaign = (body: StartCampaignInput) =>
  call<{ campaign: CertificationCampaign; item_count: number }>({
    url: "/compliance/campaigns",
    method: "POST",
    data: body,
  });

export const getCampaignReport = (id: string) =>
  call<CampaignReport>({
    url: `/compliance/campaigns/${id}`,
    method: "GET",
  });

export const listCampaignItems = (id: string, reviewer?: string) =>
  call<{ items: CampaignItemView[] }>({
    url: `/compliance/campaigns/${id}/items`,
    method: "GET",
    params: reviewer ? { reviewer } : undefined,
  }).then((r) => r.items ?? []);

export const submitDecision = (
  id: string,
  itemID: string,
  body: DecisionInput,
) =>
  call<{ status: string }>({
    url: `/compliance/campaigns/${id}/items/${itemID}/decision`,
    method: "POST",
    data: body,
  });

export const previewRevocations = (id: string) =>
  call<{ revocations: RevocationPreview[]; count: number }>({
    url: `/compliance/campaigns/${id}/revocation-preview`,
    method: "GET",
  }).then((r) => r.revocations ?? []);

export const closeCampaign = (id: string) =>
  call<CampaignReport>({
    url: `/compliance/campaigns/${id}/close`,
    method: "POST",
  });

export const enforceOverdue = () =>
  call<{ marked_overdue: number }>({
    url: "/compliance/campaigns/overdue-enforce",
    method: "POST",
  });

export function useCampaigns() {
  return useQuery<CertificationCampaign[], ApiError>({
    queryKey: qk.campaigns,
    queryFn: listCampaigns,
  });
}

export function useCampaignReport(
  id: string | undefined,
  options?: Partial<UseQueryOptions<CampaignReport, ApiError>>,
) {
  return useQuery<CampaignReport, ApiError>({
    queryKey: qk.campaign(id ?? ""),
    queryFn: () => getCampaignReport(id as string),
    enabled: !!id,
    ...options,
  });
}

export function useCampaignItems(id: string | undefined, reviewer?: string) {
  return useQuery<CampaignItemView[], ApiError>({
    queryKey: qk.campaignItems(id ?? "", reviewer),
    queryFn: () => listCampaignItems(id as string, reviewer),
    enabled: !!id,
  });
}

export function useRevocationPreview(
  id: string | undefined,
  options?: Partial<UseQueryOptions<RevocationPreview[], ApiError>>,
) {
  return useQuery<RevocationPreview[], ApiError>({
    queryKey: qk.revocationPreview(id ?? ""),
    queryFn: () => previewRevocations(id as string),
    enabled: !!id,
    ...options,
  });
}

export function useStartCampaign() {
  return useMutation<
    { campaign: CertificationCampaign; item_count: number },
    ApiError,
    StartCampaignInput
  >({
    mutationFn: startCampaign,
  });
}

export function useSubmitDecision(id: string) {
  return useMutation<
    { status: string },
    ApiError,
    { itemID: string; body: DecisionInput }
  >({
    mutationFn: ({ itemID, body }) => submitDecision(id, itemID, body),
  });
}

export function useCloseCampaign(id: string) {
  return useMutation<CampaignReport, ApiError, void>({
    mutationFn: () => closeCampaign(id),
  });
}

export function useEnforceOverdue() {
  return useMutation<{ marked_overdue: number }, ApiError, void>({
    mutationFn: enforceOverdue,
  });
}

// --- evidence-pack export ---

/**
 * exportEvidencePack downloads a framework-mapped evidence pack as a ZIP. The
 * route is gated server-side by RequirePermission("compliance.export") +
 * step-up MFA, so a caller lacking either gets a 403 ApiError surfaced to the
 * UI. Returns the digest the control plane stamped (X-Evidence-Pack-Digest),
 * which the audit chain also records, so the operator can cross-check.
 */
export interface ExportPackInput {
  framework: string;
  from?: string;
  to?: string;
}

export interface ExportedPack {
  blob: Blob;
  filename: string;
  digest: string | null;
}

export async function exportEvidencePack(
  body: ExportPackInput,
): Promise<ExportedPack> {
  try {
    const res = await apiDownload({
      url: "/compliance/export",
      method: "POST",
      data: body,
    });
    const blob = res.data;
    const digest = (res.headers?.["x-evidence-pack-digest"] as string) ?? null;
    const filename =
      filenameFromDisposition(
        res.headers?.["content-disposition"] as string | undefined,
      ) ?? `evidence-pack-${body.framework.replace(/\s+/g, "_")}.zip`;
    return { blob, filename, digest };
  } catch (err) {
    // A blob error response arrives as a Blob, not JSON — read it back so the
    // server's message (e.g. "step-up MFA required") reaches the user.
    throw await toApiErrorFromBlob(err);
  }
}

function filenameFromDisposition(value?: string): string | null {
  if (!value) return null;
  const match = /filename="?([^"]+)"?/.exec(value);
  return match ? match[1] : null;
}

async function toApiErrorFromBlob(err: unknown): Promise<ApiError> {
  const ax = err as AxiosError<Blob>;
  if (ax?.isAxiosError && ax.response?.data instanceof Blob) {
    try {
      const text = await ax.response.data.text();
      const body = JSON.parse(text) as ApiErrorBody;
      return new ApiError(
        ax.response.status,
        body.error ?? ax.message,
        body.conflicts,
      );
    } catch {
      return new ApiError(ax.response?.status ?? 0, ax.message);
    }
  }
  return toApiError(err);
}

export function useExportEvidencePack() {
  return useMutation<ExportedPack, ApiError, ExportPackInput>({
    mutationFn: exportEvidencePack,
  });
}
