// Sidebar navigation model for the Access console. Each entry maps to a route
// built in `src/router.tsx`. Labels are i18n message ids (resolved in
// AppLayout via <FormattedMessage>) so the navigation is localized across all
// supported locales. Grouped to mirror the operator mental model: an overview,
// the policy authoring surface (Govern), and the day-to-day identity lifecycle
// (Lifecycle).

import type { IconName } from "./Icon";
import type { MessageKey } from "@/lib/i18n/messages";

export interface NavItem {
  /** i18n message id; English is the source-of-truth fallback. */
  labelId: MessageKey;
  to: string;
  icon: IconName;
  /** Only shown to workspace admins (day-1 setup surfaces). The server still
   *  authorizes every action; this just keeps a plain operator from being shown
   *  a setup flow whose mutations their role can't perform. */
  adminOnly?: boolean;
}

export interface NavGroup {
  labelId: MessageKey;
  items: NavItem[];
}

export const NAV: NavGroup[] = [
  {
    labelId: "nav.group.getStarted",
    items: [
      { labelId: "nav.onboarding", to: "/onboarding", icon: "rocket", adminOnly: true },
      { labelId: "nav.selfService", to: "/self-service", icon: "key" },
    ],
  },
  {
    labelId: "nav.group.overview",
    items: [{ labelId: "nav.dashboard", to: "/", icon: "dashboard" }],
  },
  {
    labelId: "nav.group.govern",
    items: [
      { labelId: "nav.policies", to: "/policies", icon: "policy" },
      { labelId: "nav.packs", to: "/packs", icon: "compliance" },
    ],
  },
  {
    labelId: "nav.group.lifecycle",
    items: [
      { labelId: "nav.connectors", to: "/connectors", icon: "integrations" },
      { labelId: "nav.requests", to: "/requests", icon: "rbac" },
      { labelId: "nav.workflows", to: "/workflows", icon: "playbooks" },
      { labelId: "nav.jmlRuns", to: "/jml-runs", icon: "audit" },
      { labelId: "nav.directory", to: "/directory", icon: "scim" },
    ],
  },
  {
    labelId: "nav.group.pam",
    items: [
      { labelId: "nav.pam.targets", to: "/pam/targets", icon: "key" },
      { labelId: "nav.pam.agents", to: "/pam/agents", icon: "integrations" },
      { labelId: "nav.pam.leases", to: "/pam/leases", icon: "playbooks" },
      { labelId: "nav.pam.webAccess", to: "/pam/web-access", icon: "browser" },
      { labelId: "nav.pam.sessions", to: "/pam/sessions", icon: "troubleshoot" },
      { labelId: "nav.pam.recordings", to: "/pam/recordings", icon: "audit" },
      { labelId: "nav.pam.rotation", to: "/pam/rotation", icon: "audit" },
    ],
  },
  {
    labelId: "nav.group.compliance",
    items: [
      { labelId: "nav.campaigns", to: "/compliance/campaigns", icon: "audit" },
      { labelId: "nav.evidence", to: "/compliance/evidence", icon: "compliance" },
    ],
  },
  {
    labelId: "nav.group.preferences",
    items: [
      {
        labelId: "nav.rolesPermissions",
        to: "/settings/roles",
        icon: "rbac",
      },
      { labelId: "nav.settings", to: "/settings", icon: "settings" },
    ],
  },
];
