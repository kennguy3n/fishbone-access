import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import {
  MutationCache,
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { AuthProvider } from "@/auth/auth-context";
import { LocaleProvider } from "@/lib/i18n/locale-context";
import { ToastProvider } from "@/components/Toast";
import { router } from "@/router";
import { initTheme } from "@/lib/theme";
import "@/styles.css";

// Re-apply the persisted theme and wire the System-mode OS listener. The inline
// script in index.html already stamped data-theme before first paint.
initTheme();

// The api/access.ts mutation hooks don't each wire their own cache
// invalidation. A single global rule — invalidate every active query after any
// successful mutation — keeps list/detail views (policies, requests, history,
// orphans) consistent after a save/simulate/promote/disposition without having
// to remember per-call `onSuccess` wiring. Any per-call `onSuccess` a page
// passes still runs; this is additive, not a replacement.
const queryClient: QueryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 30_000,
    },
  },
  mutationCache: new MutationCache({
    onSuccess: () => {
      void queryClient.invalidateQueries();
    },
  }),
});

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("Root element #root not found");

createRoot(rootEl).render(
  <StrictMode>
    <LocaleProvider>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <ToastProvider>
            <RouterProvider router={router} />
          </ToastProvider>
        </AuthProvider>
      </QueryClientProvider>
    </LocaleProvider>
  </StrictMode>,
);
