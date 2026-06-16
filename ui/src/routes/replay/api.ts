// Typed client + React-Query hooks for the searchable session-recording
// forensic store (internal/handlers/recordings_handlers.go on the tenant-scoped
// /api/v1 group). This module lives under the replay route's own directory so
// the feature owns its transport types; it reuses the shared axios mutator
// (bearer token, Accept-Language, 401 handling) and the shared ApiError so it
// behaves identically to the rest of the console.

import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseQueryOptions,
} from "@tanstack/react-query";
import { apiRequest } from "@/api/http-client";
import { ApiError, toApiError } from "@/api/access";

async function call<T>(config: Parameters<typeof apiRequest>[0]): Promise<T> {
  try {
    return await apiRequest<T>(config);
  } catch (err) {
    throw toApiError(err);
  }
}

// --- Domain types (mirror internal/models.SessionRecording + the service) ----

/** A recording's light, searchable projection — the row search returns. */
export interface RecordingSummary {
  id: string;
  workspace_id: string;
  session_id: string;
  target_id?: string;
  operator: string;
  target_name: string;
  protocol: string;
  state: string;
  client_addr: string;
  started_at?: string | null;
  ended_at?: string | null;
  duration_ms: number;
  command_count: number;
  deny_count: number;
  frame_count: number;
  bytes: number;
  truncated: boolean;
  replay_key: string;
  sha256: string;
  sha256_verified: boolean;
  indexed_at?: string | null;
  blob_pruned: boolean;
  blob_pruned_at?: string | null;
}

export interface RecordingSearchResponse {
  recordings: RecordingSummary[];
  total: number;
  limit: number;
  offset: number;
}

/** One row of the synchronized command timeline. */
export interface CommandTimelineEntry {
  seq: number;
  command: string;
  decision: string;
  reason?: string;
  denied: boolean;
}

export interface RecordingDetail {
  recording: RecordingSummary;
  timeline: CommandTimelineEntry[];
}

/** A single decoded transcript frame (payload is base64). */
export interface ReplayFrame {
  direction: "input" | "output" | "control" | string;
  at: string;
  payload: string;
}

/** The decoded, time-ordered transcript plus the live tamper verdict. */
export interface ReplayStream {
  session_id: string;
  frames: ReplayFrame[];
  bytes: number;
  sha256: string;
  anchored: boolean;
  verified: boolean;
  truncated: boolean;
}

export interface RetentionPolicy {
  retention_days: number;
  is_default: boolean;
  updated_by: string;
  updated_at?: string | null;
}

export interface RecordingSearchParams {
  q?: string;
  operator?: string;
  protocol?: string;
  target?: string;
  from?: string;
  to?: string;
  include_pruned?: boolean;
  limit?: number;
  offset?: number;
}

// --- Raw calls ---------------------------------------------------------------

const searchParams = (p: RecordingSearchParams) => ({
  ...(p.q ? { q: p.q } : {}),
  ...(p.operator ? { operator: p.operator } : {}),
  ...(p.protocol ? { protocol: p.protocol } : {}),
  ...(p.target ? { target: p.target } : {}),
  ...(p.from ? { from: p.from } : {}),
  ...(p.to ? { to: p.to } : {}),
  ...(p.include_pruned ? { include_pruned: "true" } : {}),
  ...(p.limit != null ? { limit: String(p.limit) } : {}),
  ...(p.offset != null ? { offset: String(p.offset) } : {}),
});

export const searchRecordings = (p: RecordingSearchParams) =>
  call<RecordingSearchResponse>({
    url: "/pam/recordings",
    method: "GET",
    params: searchParams(p),
  });

export const getRecording = (id: string) =>
  call<RecordingDetail>({ url: `/pam/recordings/${id}`, method: "GET" });

export const getRecordingFrames = (id: string) =>
  call<ReplayStream>({ url: `/pam/recordings/${id}/frames`, method: "GET" });

export const getRetentionPolicy = () =>
  call<RetentionPolicy>({
    url: "/pam/recordings/retention-policy",
    method: "GET",
  });

export const setRetentionPolicy = (retentionDays: number) =>
  call<RetentionPolicy>({
    url: "/pam/recordings/retention-policy",
    method: "PUT",
    data: { retention_days: retentionDays },
  });

// --- Query keys + hooks ------------------------------------------------------

export const recordingsQk = {
  search: (p: RecordingSearchParams) => ["recordings", "search", p] as const,
  detail: (id: string) => ["recordings", "detail", id] as const,
  frames: (id: string) => ["recordings", "frames", id] as const,
  retention: ["recordings", "retention-policy"] as const,
};

export function useRecordingSearch(
  p: RecordingSearchParams,
  options?: Partial<UseQueryOptions<RecordingSearchResponse, ApiError>>,
) {
  return useQuery<RecordingSearchResponse, ApiError>({
    queryKey: recordingsQk.search(p),
    queryFn: () => searchRecordings(p),
    ...options,
  });
}

export function useRecording(
  id: string | undefined,
  options?: Partial<UseQueryOptions<RecordingDetail, ApiError>>,
) {
  return useQuery<RecordingDetail, ApiError>({
    queryKey: recordingsQk.detail(id ?? ""),
    queryFn: () => getRecording(id as string),
    enabled: !!id,
    ...options,
  });
}

export function useRecordingFrames(
  id: string | undefined,
  options?: Partial<UseQueryOptions<ReplayStream, ApiError>>,
) {
  return useQuery<ReplayStream, ApiError>({
    queryKey: recordingsQk.frames(id ?? ""),
    queryFn: () => getRecordingFrames(id as string),
    enabled: !!id,
    ...options,
  });
}

export function useRetentionPolicy(
  options?: Partial<UseQueryOptions<RetentionPolicy, ApiError>>,
) {
  return useQuery<RetentionPolicy, ApiError>({
    queryKey: recordingsQk.retention,
    queryFn: getRetentionPolicy,
    ...options,
  });
}

export function useSetRetentionPolicy() {
  const queryClient = useQueryClient();
  return useMutation<RetentionPolicy, ApiError, number>({
    mutationFn: setRetentionPolicy,
    // The PUT returns the updated policy, so prime the cache with it directly
    // (the read-only view re-renders immediately with the new value) and then
    // invalidate so any other observer refetches the authoritative row.
    onSuccess: (policy) => {
      queryClient.setQueryData(recordingsQk.retention, policy);
      void queryClient.invalidateQueries({ queryKey: recordingsQk.retention });
    },
  });
}
