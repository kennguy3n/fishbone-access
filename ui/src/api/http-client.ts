// Central axios mutator used by every API call in the Access console.
//
// Callers pass the method/url/params/data for a given ztna-api endpoint; this
// wrapper centralises the base URL, bearer-token injection, Accept-Language
// negotiation, and 401 handling so the typed hooks in api/access.ts stay
// declarative.

import axios, {
  type AxiosError,
  type AxiosRequestConfig,
  type AxiosResponse,
} from "axios";
import { runtimeConfig } from "@/lib/runtime-config";
import { clearAccessToken, getAccessToken } from "@/auth/token-store";
import { getActiveLocale } from "@/lib/i18n/locale-store";

const instance = axios.create();

instance.interceptors.request.use((config) => {
  config.baseURL = runtimeConfig().apiBaseUrl;
  const token = getAccessToken();
  if (token) {
    config.headers.set("Authorization", `Bearer ${token}`);
  }
  // Negotiate the API response language with the operator's selected
  // UI locale. The control plane reads Accept-Language (internal/i18n)
  // and falls back to English, so an unsupported value is harmless.
  config.headers.set("Accept-Language", getActiveLocale());
  return config;
});

/** Dispatched when any request comes back 401 so the app can redirect. */
export const UNAUTHORIZED_EVENT = "sng:unauthorized";

instance.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      clearAccessToken();
      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
      }
    }
    return Promise.reject(error);
  },
);

export const apiRequest = <T>(
  config: AxiosRequestConfig,
  options?: AxiosRequestConfig,
): Promise<T> =>
  // Cancellation flows through the AbortSignal that TanStack Query v5 passes
  // into the request config (`config.signal`); axios aborts on it natively.
  // We deliberately avoid the deprecated `CancelToken` here.
  instance({
    ...config,
    ...options,
  }).then(({ data }: AxiosResponse<T>) => data);

export default apiRequest;
