import {
  Link,
  Outlet,
  useNavigate,
  useRouterState,
} from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import { NAV } from "./nav";
import { Icon } from "./Icon";
import { LanguageSwitcher } from "./LanguageSwitcher";
import { useAuth } from "@/auth/auth-context";
import { useMe } from "@/api/access";
import { useIsWorkspaceAdmin } from "@/lib/permissions";

// The Access console is single-tenant per session: the bearer token resolves to
// exactly one workspace server-side (iam-core tenant_id → workspace), so there
// is no tenant *switcher* — instead we surface the bound tenant read-only from
// /me so the operator always knows which workspace they're acting in.
function TenantBadge() {
  const { data, isLoading } = useMe();
  if (isLoading) return null;
  if (!data) return null;
  return (
    <div className="tenant-switcher">
      <span className="muted" style={{ fontSize: 12 }}>
        <FormattedMessage id="topbar.tenant" />
      </span>
      <code style={{ fontSize: 12 }}>{data.tenant_id}</code>
    </div>
  );
}

function Sidebar() {
  const { location } = useRouterState();
  const path = location.pathname;
  const isAdmin = useIsWorkspaceAdmin();
  // Hide admin-only setup surfaces from a plain operator, then drop any group
  // left with no visible items so an empty header never renders.
  const groups = NAV.map((group) => ({
    ...group,
    items: group.items.filter((item) => !item.adminOnly || isAdmin),
  })).filter((group) => group.items.length > 0);
  return (
    <aside className="sidebar">
      <div className="sidebar__brand">
        <span className="sidebar__logo">S</span>
        <span>
          ShieldNet
          <small>
            <FormattedMessage id="app.subtitle" />
          </small>
        </span>
      </div>
      <nav>
        {groups.map((group, gi) => (
          <div className="nav-group" key={`${group.labelId}-${gi}`}>
            <div className="nav-group__label">
              <FormattedMessage id={group.labelId} />
            </div>
            {group.items.map((item) => {
              const active =
                item.to === "/"
                  ? path === "/"
                  : path === item.to || path.startsWith(`${item.to}/`);
              return (
                <Link
                  key={item.to}
                  to={item.to}
                  className={`nav-link${active ? " active" : ""}`}
                >
                  <span className="nav-link__icon">
                    <Icon name={item.icon} size={17} />
                  </span>
                  <span>
                    <FormattedMessage id={item.labelId} />
                  </span>
                </Link>
              );
            })}
          </div>
        ))}
      </nav>
    </aside>
  );
}

function Topbar({ onToggleNav }: { onToggleNav: () => void }) {
  const { claims, logout } = useAuth();
  const intl = useIntl();
  const name = claims?.name || claims?.email || claims?.sub || "Operator";
  const issuer = claims?.iss ?? "shieldnet";
  // Up-to-two-letter monogram for the identity avatar: initials of a display
  // name ("Ada Lovelace" -> "AL"), or the first one-to-two characters otherwise.
  const initials = (() => {
    const trimmed = name.trim();
    const parts = trimmed.split(/\s+/).filter(Boolean);
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
    return (trimmed.slice(0, 2) || "OP").toUpperCase();
  })();
  const identity = `${name} · ${issuer}`;
  return (
    <header className="topbar">
      <button
        className="icon-btn"
        onClick={onToggleNav}
        aria-label={intl.formatMessage({ id: "topbar.menu" })}
      >
        <Icon name="menu" size={18} />
      </button>
      <TenantBadge />
      <div className="topbar__spacer" />
      <LanguageSwitcher />
      <div className="topbar__user">
        <span className="avatar" aria-hidden>
          {initials}
        </span>
        <span className="topbar__identity">
          <b>{name}</b>
          <span className="muted">{issuer}</span>
        </span>
      </div>
      <button
        className="btn btn--ghost btn--sm"
        onClick={logout}
        title={`${intl.formatMessage({ id: "topbar.signOut" })} — ${identity}`}
        aria-label={`${intl.formatMessage({ id: "topbar.signOut" })} — ${identity}`}
      >
        <Icon name="logout" size={15} />
        <FormattedMessage id="topbar.signOut" />
      </button>
    </header>
  );
}

export function AppLayout() {
  const { isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const { location } = useRouterState();
  const [navOpen, setNavOpen] = useState(false);

  useEffect(() => {
    if (!isAuthenticated) {
      navigate({ to: "/login" });
    }
  }, [isAuthenticated, navigate]);

  // Close the mobile nav drawer whenever the route changes.
  useEffect(() => {
    setNavOpen(false);
  }, [location.pathname]);

  if (!isAuthenticated) return null;

  return (
    <div className={`app-shell${navOpen ? " nav-open" : ""}`}>
      <div
        className="sidebar__scrim"
        onClick={() => setNavOpen(false)}
        aria-hidden
      />
      <Sidebar />
      <div className="main">
        <Topbar onToggleNav={() => setNavOpen((v) => !v)} />
        <div className="content">
          <Outlet />
        </div>
      </div>
    </div>
  );
}
