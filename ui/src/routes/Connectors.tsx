import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useIntl } from "react-intl";
import { PageHeader, Card, Badge, AsyncBoundary } from "@/components/ui";
import { EmptyState } from "@/components/EmptyState";
import {
  useConnectors,
  useConnectorFacets,
  type ConnectorCatalogueEntry,
  type ConnectorCatalogueFilter,
  type UserFacingCapabilities,
  type OperationalCapabilities,
} from "@/api/access";
import { titleCase } from "@/lib/format";

// The capability columns rendered in the matrix and as chips on each gallery
// card. Keys are the JSON field names from the backend descriptor
// (internal/services/access/capability_descriptor.go); the labels are the
// admin-facing names. User-facing capabilities are the five product verbs an
// operator reasons about; operational capabilities are the seven optional Go
// interfaces the connector implements (derived server-side, never drifting
// from the binary).
// Each column carries an explicit `dimension` discriminator so the matrix can
// read the right capability bag (user_facing vs operational) by switching on it,
// rather than probing which object a key happens to live in. This keeps the
// lookup type-safe (no casts) and correct even if a key name were ever shared
// across the two dimensions.
type UserFacingColumn = {
  dimension: "user_facing";
  key: keyof UserFacingCapabilities;
  label: string;
};
type OperationalColumn = {
  dimension: "operational";
  key: keyof OperationalCapabilities;
  label: string;
};
type CapabilityColumn = UserFacingColumn | OperationalColumn;

const USER_FACING: UserFacingColumn[] = [
  { dimension: "user_facing", key: "sync_identity", label: "Sync identities" },
  { dimension: "user_facing", key: "provision_access", label: "Provision access" },
  { dimension: "user_facing", key: "list_entitlements", label: "List entitlements" },
  { dimension: "user_facing", key: "get_access_log", label: "Access logs" },
  { dimension: "user_facing", key: "sso_federation", label: "SSO federation" },
];

const OPERATIONAL: OperationalColumn[] = [
  { dimension: "operational", key: "group_sync", label: "Group sync" },
  { dimension: "operational", key: "identity_delta_sync", label: "Delta sync" },
  { dimension: "operational", key: "access_audit_stream", label: "Audit stream" },
  { dimension: "operational", key: "scim_provisioning", label: "SCIM" },
  { dimension: "operational", key: "session_revoke", label: "Session revoke" },
  { dimension: "operational", key: "sso_enforcement_check", label: "SSO enforcement" },
  { dimension: "operational", key: "credential_renewal", label: "Credential renewal" },
];

// Tier tone: T1 connectors are the most-adopted, fully-supported integrations
// (info/brand); deeper tiers are progressively more specialized (neutral).
function tierTone(tier: string): "info" | "neutral" {
  return tier === "T1" || tier === "T2" ? "info" : "neutral";
}

// Connection status tone, mirroring the backend access_connectors.status values
// (internal/services/access/connector_management.go): "active" is healthy (ok),
// "degraded" means connected but missing a requested scope (warn), "error" is a
// failed connectivity test (danger). Anything else (e.g. "pending") is neutral.
function statusTone(status: string | undefined): "ok" | "warn" | "danger" | "neutral" {
  switch (status) {
    case "active":
      return "ok";
    case "degraded":
      return "warn";
    case "error":
      return "danger";
    default:
      return "neutral";
  }
}

type View = "gallery" | "matrix";

export function Connectors() {
  const intl = useIntl();
  const [view, setView] = useState<View>("gallery");
  const [tier, setTier] = useState("");
  const [category, setCategory] = useState("");
  const [capability, setCapability] = useState("");
  const [connectedOnly, setConnectedOnly] = useState(false);

  // The catalogue is filtered server-side so the capability/tier/category
  // semantics match the API exactly (and a 5k-tenant workspace never ships the
  // full 200-row matrix when a filter is set). The facet vocabularies drive the
  // dropdown options so they always reflect what the binary actually ships.
  const filter: ConnectorCatalogueFilter = useMemo(
    () => ({
      tier: tier || undefined,
      category: category || undefined,
      capability: capability || undefined,
      connected: connectedOnly || undefined,
    }),
    [tier, category, capability, connectedOnly],
  );
  const { data, isLoading, error, refetch } = useConnectors(filter);
  const facets = useConnectorFacets();

  const hasFilters =
    tier !== "" || category !== "" || capability !== "" || connectedOnly;
  const clearFilters = () => {
    setTier("");
    setCategory("");
    setCapability("");
    setConnectedOnly(false);
  };

  const capabilityOptions = useMemo(() => {
    const f = facets.data;
    if (!f) return [];
    return [
      ...f.user_facing_capabilities.map((c) => ({ value: c, group: "Product" })),
      ...f.operational_capabilities.map((c) => ({
        value: c,
        group: "Operational",
      })),
    ];
  }, [facets.data]);

  return (
    <>
      <PageHeader
        title={intl.formatMessage({
          id: "connectors.title",
          defaultMessage: "Connectors",
        })}
        subtitle={intl.formatMessage({
          id: "connectors.subtitle",
          defaultMessage:
            "Every identity, IT, and security platform this control plane can connect to, with the capabilities each one supports. Connect a provider to start syncing identities and provisioning access.",
        })}
      />

      <div
        className="pill-tabs"
        role="tablist"
        aria-label={intl.formatMessage({
          id: "connectors.view",
          defaultMessage: "View",
        })}
      >
        <button
          role="tab"
          aria-selected={view === "gallery"}
          className={view === "gallery" ? "active" : ""}
          onClick={() => setView("gallery")}
        >
          {intl.formatMessage({
            id: "connectors.view.gallery",
            defaultMessage: "Gallery",
          })}
        </button>
        <button
          role="tab"
          aria-selected={view === "matrix"}
          className={view === "matrix" ? "active" : ""}
          onClick={() => setView("matrix")}
        >
          {intl.formatMessage({
            id: "connectors.view.matrix",
            defaultMessage: "Capability matrix",
          })}
        </button>
      </div>

      <div className="filter-bar">
        <select
          value={tier}
          onChange={(e) => setTier(e.target.value)}
          style={{ width: "auto", minWidth: 120 }}
          aria-label={intl.formatMessage({
            id: "connectors.filter.tier",
            defaultMessage: "Tier",
          })}
        >
          <option value="">All tiers</option>
          {(facets.data?.tiers ?? []).map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <select
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          style={{ width: "auto", minWidth: 160 }}
          aria-label={intl.formatMessage({
            id: "connectors.filter.category",
            defaultMessage: "Category",
          })}
        >
          <option value="">All categories</option>
          {(facets.data?.categories ?? []).map((c) => (
            <option key={c} value={c}>
              {titleCase(c)}
            </option>
          ))}
        </select>
        <select
          value={capability}
          onChange={(e) => setCapability(e.target.value)}
          style={{ width: "auto", minWidth: 180 }}
          aria-label={intl.formatMessage({
            id: "connectors.filter.capability",
            defaultMessage: "Capability",
          })}
        >
          <option value="">All capabilities</option>
          {capabilityOptions.map((o) => (
            <option key={o.value} value={o.value}>
              {titleCase(o.value)}
            </option>
          ))}
        </select>
        <label className="checkbox-inline">
          <input
            type="checkbox"
            checked={connectedOnly}
            onChange={(e) => setConnectedOnly(e.target.checked)}
          />
          {intl.formatMessage({
            id: "connectors.filter.connectedOnly",
            defaultMessage: "Connected only",
          })}
        </label>
        {hasFilters && (
          <button className="btn btn--ghost btn--sm" onClick={clearFilters}>
            {intl.formatMessage({
              id: "connectors.filter.clear",
              defaultMessage: "Clear filters",
            })}
          </button>
        )}
      </div>

      <AsyncBoundary
        isLoading={isLoading}
        error={error}
        data={data}
        onRetry={refetch}
        isEmpty={(rows) => rows.length === 0}
        empty={
          <EmptyState
            title={intl.formatMessage({
              id: "connectors.empty.title",
              defaultMessage: "No connectors match these filters",
            })}
            description={intl.formatMessage({
              id: "connectors.empty.desc",
              defaultMessage:
                "Try a different tier, category, or capability, or clear the filters to see the full catalog.",
            })}
          />
        }
      >
        {(rows) =>
          view === "gallery" ? (
            <ConnectorGallery rows={rows} />
          ) : (
            <CapabilityMatrix rows={rows} />
          )
        }
      </AsyncBoundary>
    </>
  );
}

function ConnectorGallery({ rows }: { rows: ConnectorCatalogueEntry[] }) {
  const navigate = useNavigate();
  return (
    <div className="grid grid--3">
      {rows.map((entry) => {
        const caps = [
          ...USER_FACING.filter((c) => entry.user_facing[c.key]),
          ...OPERATIONAL.filter((c) => entry.operational[c.key]),
        ];
        return (
          <Card key={entry.provider} className="connector-card">
            <div className="connector-card__head">
              <div>
                <h3 className="connector-card__title">{entry.display_name}</h3>
                <span className="muted" style={{ fontSize: 12 }}>
                  {titleCase(entry.category)}
                </span>
              </div>
              <Badge tone={tierTone(entry.tier)}>{entry.tier}</Badge>
            </div>
            <div className="connector-card__caps">
              {caps.slice(0, 6).map((c) => (
                <Badge key={c.label} tone="neutral">
                  {c.label}
                </Badge>
              ))}
              {caps.length > 6 && (
                <span className="muted" style={{ fontSize: 12 }}>
                  +{caps.length - 6}
                </span>
              )}
            </div>
            <div className="connector-card__foot">
              {entry.connected ? (
                <Badge tone={statusTone(entry.status)} dot>
                  {titleCase(entry.status) || "Connected"}
                </Badge>
              ) : (
                <span className="muted" style={{ fontSize: 12.5 }}>
                  Not connected
                </span>
              )}
              <button
                className="btn btn--primary btn--sm"
                onClick={() =>
                  navigate({
                    to: "/connectors/$provider/setup",
                    params: { provider: entry.provider },
                  })
                }
              >
                {entry.connected ? "Configure" : "Set up"}
              </button>
            </div>
          </Card>
        );
      })}
    </div>
  );
}

function CapabilityMatrix({ rows }: { rows: ConnectorCatalogueEntry[] }) {
  const navigate = useNavigate();
  const columns: CapabilityColumn[] = [...USER_FACING, ...OPERATIONAL];
  return (
    <div className="matrix-scroll">
      <table className="table matrix">
        <thead>
          <tr>
            <th className="matrix__rowhead">Connector</th>
            {columns.map((c) => (
              <th key={c.label} className="matrix__cap">
                <span>{c.label}</span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((entry) => (
            <tr
              key={entry.provider}
              className="matrix__row"
              onClick={() =>
                navigate({
                  to: "/connectors/$provider/setup",
                  params: { provider: entry.provider },
                })
              }
            >
              <th scope="row" className="matrix__rowhead">
                <span className="matrix__name">{entry.display_name}</span>
                <Badge tone={tierTone(entry.tier)}>{entry.tier}</Badge>
              </th>
              {columns.map((c) => {
                const supported =
                  c.dimension === "user_facing"
                    ? entry.user_facing[c.key]
                    : entry.operational[c.key];
                return (
                  <td key={c.label} className="matrix__cell">
                    {supported ? (
                      <span
                        className="matrix__dot matrix__dot--ok"
                        role="img"
                        aria-label={`${c.label}: supported`}
                      />
                    ) : (
                      <span
                        className="matrix__dot matrix__dot--no"
                        role="img"
                        aria-label={`${c.label}: not supported`}
                      />
                    )}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
