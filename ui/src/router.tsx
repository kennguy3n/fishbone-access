import { lazy, Suspense } from "react";
import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
} from "@tanstack/react-router";
import { AppLayout } from "@/components/AppLayout";
import { Login } from "@/routes/Login";
import { OidcCallback } from "@/routes/OidcCallback";
import { LoadingState, ErrorState } from "@/components/ui";

// A dynamic import that rejects almost always means this tab is holding a stale
// chunk manifest from a previous deploy — the content-hashed chunk it wants no
// longer exists on the server (404). Rather than surfacing a hard error, reload
// once to pull the current bundle. The sessionStorage timestamp guards against
// a reload loop when the failure is a genuine (non-stale) error.
const RELOAD_KEY = "sng-chunk-reload-at";
function recoverFromStaleChunk<T>(err: unknown): Promise<T> {
  const last = Number(sessionStorage.getItem(RELOAD_KEY) ?? 0);
  if (Date.now() - last > 10_000) {
    sessionStorage.setItem(RELOAD_KEY, String(Date.now()));
    window.location.reload();
    // Keep the Suspense fallback up while the reload takes over instead of
    // resolving/rejecting (which would flash an error first).
    return new Promise<T>(() => {});
  }
  throw err;
}

// Feature routes are code-split: each becomes its own chunk fetched on first
// navigation, so the initial bundle stays small at 5k-tenant scale. The app
// shell (AppLayout) and the auth screens load eagerly since they're on the
// critical path of every session.
function lazyPage(factory: () => Promise<{ default: () => JSX.Element }>) {
  const Lazy = lazy(() =>
    factory().catch((err) => recoverFromStaleChunk<{ default: () => JSX.Element }>(err)),
  );
  return function LazyRoute() {
    return (
      <Suspense fallback={<LoadingState />}>
        <Lazy />
      </Suspense>
    );
  };
}

const Dashboard = lazyPage(() =>
  import("@/routes/Dashboard").then((m) => ({ default: m.Dashboard })),
);
const Policies = lazyPage(() =>
  import("@/routes/Policies").then((m) => ({ default: m.Policies })),
);
const PolicyEditor = lazyPage(() =>
  import("@/routes/PolicyEditor").then((m) => ({ default: m.PolicyEditor })),
);
const Packs = lazyPage(() =>
  import("@/routes/Packs").then((m) => ({ default: m.Packs })),
);
const PackDetail = lazyPage(() =>
  import("@/routes/PackDetail").then((m) => ({ default: m.PackDetail })),
);
const Requests = lazyPage(() =>
  import("@/routes/Requests").then((m) => ({ default: m.Requests })),
);
const RequestDetail = lazyPage(() =>
  import("@/routes/RequestDetail").then((m) => ({ default: m.RequestDetail })),
);
const Directory = lazyPage(() =>
  import("@/routes/Directory").then((m) => ({ default: m.Directory })),
);
const Settings = lazyPage(() =>
  import("@/routes/Settings").then((m) => ({ default: m.Settings })),
);
const RolesPermissions = lazyPage(() =>
  import("@/routes/RolesPermissions").then((m) => ({
    default: m.RolesPermissions,
  })),
);

const rootRoute = createRootRoute({ component: Outlet });

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  component: Login,
});

const callbackRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/auth/callback",
  component: OidcCallback,
});

// Pathless layout route: wraps every authenticated page in the app shell
// (sidebar + topbar) and enforces the auth guard.
const appLayoutRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "app",
  component: AppLayout,
});

const page = <P extends string>(path: P, component: () => JSX.Element) =>
  createRoute({ getParentRoute: () => appLayoutRoute, path, component });

const appRoutes = [
  page("/", Dashboard),
  page("/policies", Policies),
  page("/policies/new", PolicyEditor),
  page("/policies/$policyId", PolicyEditor),
  page("/packs", Packs),
  page("/packs/$packId", PackDetail),
  page("/requests", Requests),
  page("/requests/$requestId", RequestDetail),
  page("/directory", Directory),
  page("/settings", Settings),
  page("/settings/roles", RolesPermissions),
];

const routeTree = rootRoute.addChildren([
  loginRoute,
  callbackRoute,
  appLayoutRoute.addChildren(appRoutes),
]);

export const router = createRouter({
  routeTree,
  // Branded fallback for any uncaught render/load error, with a one-click
  // reload — far friendlier than the framework's bare "Something went wrong".
  defaultErrorComponent: ({ error }) => (
    <div style={{ padding: 24 }}>
      <ErrorState error={error} onRetry={() => window.location.reload()} />
    </div>
  ),
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
