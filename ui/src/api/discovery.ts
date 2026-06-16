// Typed client for Feature E — account/asset auto-discovery + auto-onboarding.
//
// Mirrors the Go control plane in internal/services/discovery (Engine read
// surface, sweep/onboard/policy operations) and internal/models/discovery.go
// (DiscoveredAsset / DiscoveredAccount / DiscoveryScan / AutoOnboardingPolicy).
// Every operation goes through the shared `call` pattern (re-wrapped here
// against ApiError since access.ts's helper is module-private) so it reuses the
// bearer token, Accept-Language, gin.H envelope unwrapping, and ApiError
// normalization — including the 403 "step-up MFA required" the onboard path can
// surface and the 422 "unsupported" a connector with no inventory API returns.
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
import { ApiError, toApiError, type PamTarget } from "./access";

// ---------------------------------------------------------------------------
// Domain types (mirror internal/models/discovery.go + service view structs)
// ---------------------------------------------------------------------------

/** Discovery sources (models.DiscoverySource*). */
export type DiscoverySource =
  | "agent_sweep"
  | "connector_inventory"
  | "db_accounts";

/** Inventory classification (models.DiscoveryStatus*). */
export type DiscoveryStatus = "unmanaged" | "managed" | "orphan" | "ignored";

/** Scan lifecycle (models.DiscoveryScan*). */
export type ScanStatus = "running" | "completed" | "failed";

export type ScanTrigger = "manual" | "scheduled";

export interface DiscoveredAsset {
  id: string;
  workspace_id: string;
  source: DiscoverySource;
  external_id: string;
  name: string;
  protocol: string;
  address: string;
  status: DiscoveryStatus;
  agent_id?: string | null;
  connector_id?: string | null;
  target_id?: string | null;
  metadata?: Record<string, unknown> | null;
  policy_matched: boolean;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
}

export interface DiscoveredAccount {
  id: string;
  workspace_id: string;
  target_id: string;
  username: string;
  source: DiscoverySource;
  status: DiscoveryStatus;
  can_login: boolean;
  superuser: boolean;
  attributes?: Record<string, unknown> | null;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
}

export interface DiscoveryScan {
  id: string;
  workspace_id: string;
  source: DiscoverySource | "";
  trigger: ScanTrigger;
  status: ScanStatus;
  actor: string;
  assets_found: number;
  assets_new: number;
  accounts_found: number;
  onboarded_count: number;
  started_at: string;
  finished_at?: string | null;
  error?: string;
  params?: Record<string, unknown> | null;
}

/** Aggregate counts the stat cards render (discovery.InventorySummary). */
export interface InventorySummary {
  total_assets: number;
  unmanaged_assets: number;
  managed_assets: number;
  orphan_accounts: number;
  recommended_now: number;
}

/** discovery.SweepResult — agent import / connector inventory outcome. */
export interface SweepResult {
  scan_id: string;
  probed?: number;
  reachable?: number;
  assets_found: number;
  assets_new: number;
}

/** discovery.AccountScanResult — DB account enumeration outcome. */
export interface AccountScanResult {
  scan_id: string;
  accounts_found: number;
}

/** One auto-onboarding match rule (discovery.AutoOnboardRule). */
export interface AutoOnboardRule {
  name: string;
  protocols?: string[];
  sources?: DiscoverySource[];
  cidrs?: string[];
  agent_id?: string | null;
}

/** Non-secret policy view (discovery.PolicyView) — never carries the credential. */
export interface PolicyView {
  enabled: boolean;
  create_targets: boolean;
  require_lease: boolean;
  rules: AutoOnboardRule[];
  default_agent_id?: string | null;
  credential_username?: string;
  has_credential: boolean;
  updated_by?: string;
  updated_at?: string;
}

export interface AssetFilters {
  source?: string;
  protocol?: string;
  status?: string;
  limit?: number;
}

export interface OnboardAssetInput {
  name?: string;
  protocol?: string;
  address?: string;
  username?: string;
  password?: string;
  private_key?: string;
  token?: string;
  agent_id?: string;
  require_mfa?: boolean;
  lease_ttl_seconds?: number;
}

export interface SavePolicyInput {
  enabled: boolean;
  create_targets: boolean;
  rules: AutoOnboardRule[];
  default_agent_id?: string;
  /** Optional onboarding credential. Omit to leave any sealed credential
   *  untouched; send with an empty password to clear it (flag-only mode). */
  credential?: {
    username?: string;
    password?: string;
    private_key?: string;
    token?: string;
  };
}

// Operator dispositions accepted by the backend DispositionAccount endpoint
// (internal/services/discovery/onboard.go): ignore a discovered account, or
// reclassify it back to unmanaged/orphan. "managed" is never set by hand — an
// account becomes managed only when a real grant exists — and there is no
// "pending" state, so neither belongs in this contract.
export type AccountDisposition = "ignored" | "unmanaged" | "orphan";

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

// A request that normalizes any thrown error into ApiError (the access.ts
// `call` helper is module-private, so we re-wrap here against the same type).
async function call<T>(config: Parameters<typeof apiRequest>[0]): Promise<T> {
  try {
    return await apiRequest<T>(config);
  } catch (err) {
    throw toApiError(err);
  }
}

function assetQuery(f: AssetFilters): Record<string, string | number> {
  const params: Record<string, string | number> = {};
  if (f.source) params.source = f.source;
  if (f.protocol) params.protocol = f.protocol;
  if (f.status) params.status = f.status;
  if (f.limit) params.limit = f.limit;
  return params;
}

// ---------------------------------------------------------------------------
// Raw operations
// ---------------------------------------------------------------------------

export const getDiscoverySummary = () =>
  call<InventorySummary>({ url: "/discovery/summary", method: "GET" });

export const listDiscoveredAssets = (f: AssetFilters = {}) =>
  call<{ assets: DiscoveredAsset[] }>({
    url: "/discovery/assets",
    method: "GET",
    params: assetQuery(f),
  }).then((r) => r.assets ?? []);

export const getDiscoveredAsset = (id: string) =>
  call<DiscoveredAsset>({ url: `/discovery/assets/${id}`, method: "GET" });

export const onboardAsset = (id: string, body: OnboardAssetInput) =>
  call<PamTarget>({
    url: `/discovery/assets/${id}/onboard`,
    method: "POST",
    data: body,
  });

export const ignoreAsset = (id: string) =>
  call<{ status: string }>({
    url: `/discovery/assets/${id}/ignore`,
    method: "POST",
  });

export const listDiscoveredAccounts = (targetId?: string, limit?: number) =>
  call<{ accounts: DiscoveredAccount[] }>({
    url: "/discovery/accounts",
    method: "GET",
    params: {
      ...(targetId ? { target_id: targetId } : {}),
      ...(limit ? { limit } : {}),
    },
  }).then((r) => r.accounts ?? []);

export const dispositionAccount = (id: string, status: AccountDisposition) =>
  call<{ status: string }>({
    url: `/discovery/accounts/${id}/disposition`,
    method: "POST",
    data: { status },
  });

export const listDiscoveryScans = (limit?: number) =>
  call<{ scans: DiscoveryScan[] }>({
    url: "/discovery/scans",
    method: "GET",
    params: limit ? { limit } : {},
  }).then((r) => r.scans ?? []);

export const importAgentReachable = (agentId: string) =>
  call<SweepResult>({
    url: "/discovery/scans/agent",
    method: "POST",
    data: { agent_id: agentId },
  });

export const scanConnectorInventory = (connectorId: string) =>
  call<SweepResult>({
    url: `/discovery/scans/connector/${connectorId}`,
    method: "POST",
  });

export const scanDBAccounts = (targetId: string) =>
  call<AccountScanResult>({
    url: `/discovery/scans/db/${targetId}`,
    method: "POST",
  });

export const getAutoOnboardingPolicy = () =>
  call<PolicyView>({ url: "/discovery/policy", method: "GET" });

export const saveAutoOnboardingPolicy = (body: SavePolicyInput) =>
  call<PolicyView>({ url: "/discovery/policy", method: "PUT", data: body });

// ---------------------------------------------------------------------------
// Query keys + hooks
// ---------------------------------------------------------------------------

export const discoveryQk = {
  summary: ["discovery", "summary"] as const,
  assets: (f: AssetFilters = {}) => ["discovery", "assets", f] as const,
  asset: (id: string) => ["discovery", "asset", id] as const,
  accounts: (targetId?: string) =>
    ["discovery", "accounts", targetId ?? ""] as const,
  scans: ["discovery", "scans"] as const,
  policy: ["discovery", "policy"] as const,
};

export function useDiscoverySummary(
  options?: Partial<UseQueryOptions<InventorySummary, ApiError>>,
) {
  return useQuery<InventorySummary, ApiError>({
    queryKey: discoveryQk.summary,
    queryFn: getDiscoverySummary,
    ...options,
  });
}

export function useDiscoveredAssets(
  f: AssetFilters = {},
  options?: Partial<UseQueryOptions<DiscoveredAsset[], ApiError>>,
) {
  return useQuery<DiscoveredAsset[], ApiError>({
    queryKey: discoveryQk.assets(f),
    queryFn: () => listDiscoveredAssets(f),
    ...options,
  });
}

export function useDiscoveredAccounts(
  targetId?: string,
  options?: Partial<UseQueryOptions<DiscoveredAccount[], ApiError>>,
) {
  return useQuery<DiscoveredAccount[], ApiError>({
    queryKey: discoveryQk.accounts(targetId),
    queryFn: () => listDiscoveredAccounts(targetId),
    ...options,
  });
}

export function useDiscoveryScans(
  options?: Partial<UseQueryOptions<DiscoveryScan[], ApiError>>,
) {
  return useQuery<DiscoveryScan[], ApiError>({
    queryKey: discoveryQk.scans,
    queryFn: () => listDiscoveryScans(),
    ...options,
  });
}

export function useAutoOnboardingPolicy(
  options?: Partial<UseQueryOptions<PolicyView, ApiError>>,
) {
  return useQuery<PolicyView, ApiError>({
    queryKey: discoveryQk.policy,
    queryFn: getAutoOnboardingPolicy,
    ...options,
  });
}

export function useOnboardAsset(id: string) {
  return useMutation<PamTarget, ApiError, OnboardAssetInput>({
    mutationFn: (body) => onboardAsset(id, body),
  });
}

export function useIgnoreAsset() {
  return useMutation<{ status: string }, ApiError, string>({
    mutationFn: (id) => ignoreAsset(id),
  });
}

export function useDispositionAccount() {
  return useMutation<
    { status: string },
    ApiError,
    { id: string; status: AccountDisposition }
  >({
    mutationFn: ({ id, status }) => dispositionAccount(id, status),
  });
}

export function useImportAgentReachable() {
  return useMutation<SweepResult, ApiError, string>({
    mutationFn: (agentId) => importAgentReachable(agentId),
  });
}

export function useScanConnectorInventory() {
  return useMutation<SweepResult, ApiError, string>({
    mutationFn: (connectorId) => scanConnectorInventory(connectorId),
  });
}

export function useScanDBAccounts() {
  return useMutation<AccountScanResult, ApiError, string>({
    mutationFn: (targetId) => scanDBAccounts(targetId),
  });
}

export function useSaveAutoOnboardingPolicy() {
  return useMutation<PolicyView, ApiError, SavePolicyInput>({
    mutationFn: saveAutoOnboardingPolicy,
  });
}
