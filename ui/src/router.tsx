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
import { LoadingState } from "@/components/ui";

// Feature routes are code-split: each becomes its own chunk fetched on first
// navigation, so the initial bundle stays small at 5k-tenant scale. The app
// shell (AppLayout) and the auth screens load eagerly since they're on the
// critical path of every session.
function lazyPage(factory: () => Promise<{ default: () => JSX.Element }>) {
  const Lazy = lazy(factory);
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
  page("/requests", Requests),
  page("/requests/$requestId", RequestDetail),
  page("/directory", Directory),
  page("/settings", Settings),
];

const routeTree = rootRoute.addChildren([
  loginRoute,
  callbackRoute,
  appLayoutRoute.addChildren(appRoutes),
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
