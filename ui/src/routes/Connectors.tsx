import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useIntl, type IntlShape } from "react-intl";
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
import { categoryLabel } from "./discovery/labels";

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
  labelId: string;
  defaultLabel: string;
};
type OperationalColumn = {
  dimension: "operational";
  key: keyof OperationalCapabilities;
  labelId: string;
  defaultLabel: string;
};
type CapabilityColumn = UserFacingColumn | OperationalColumn;

const USER_FACING: UserFacingColumn[] = [
  { dimension: "user_facing", key: "sync_identity", labelId: "connectors.cap.sync_identity", defaultLabel: "Sync identities" },
  { dimension: "user_facing", key: "provision_access", labelId: "connectors.cap.provision_access", defaultLabel: "Provision access" },
  { dimension: "user_facing", key: "list_entitlements", labelId: "connectors.cap.list_entitlements", defaultLabel: "List entitlements" },
  { dimension: "user_facing", key: "get_access_log", labelId: "connectors.cap.get_access_log", defaultLabel: "Access logs" },
  { dimension: "user_facing", key: "sso_federation", labelId: "connectors.cap.sso_federation", defaultLabel: "SSO federation" },
];

const OPERATIONAL: OperationalColumn[] = [
  { dimension: "operational", key: "group_sync", labelId: "connectors.cap.group_sync", defaultLabel: "Group sync" },
  { dimension: "operational", key: "identity_delta_sync", labelId: "connectors.cap.identity_delta_sync", defaultLabel: "Delta sync" },
  { dimension: "operational", key: "access_audit_stream", labelId: "connectors.cap.access_audit_stream", defaultLabel: "Audit stream" },
  { dimension: "operational", key: "scim_provisioning", labelId: "connectors.cap.scim_provisioning", defaultLabel: "SCIM" },
  { dimension: "operational", key: "session_revoke", labelId: "connectors.cap.session_revoke", defaultLabel: "Session revoke" },
  { dimension: "operational", key: "sso_enforcement_check", labelId: "connectors.cap.sso_enforcement_check", defaultLabel: "SSO enforcement" },
  { dimension: "operational", key: "credential_renewal", labelId: "connectors.cap.credential_renewal", defaultLabel: "Credential renewal" },
];

/** Localized capability-column label. */
function colLabel(intl: IntlShape, c: CapabilityColumn): string {
  return intl.formatMessage({ id: c.labelId, defaultMessage: c.defaultLabel });
}

// Capability key -> column, so the capability filter renders the exact same
// localized label as the gallery chips and matrix headers (no second source of
// truth to drift out of sync, and no titleCase mangling of "SSO"/"SCIM").
const CAP_BY_KEY = new Map<string, CapabilityColumn>(
  [...USER_FACING, ...OPERATIONAL].map((c) => [c.key as string, c]),
);

/** Localized label for a capability facet value, reusing the column labels. */
function capabilityFacetLabel(intl: IntlShape, value: string): string {
  const col = CAP_BY_KEY.get(value);
  return col ? colLabel(intl, col) : titleCase(value);
}

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

// Plain-language label for a connection status, paired with the dot tone above.
function connectorStatusLabel(
  intl: IntlShape,
  status: string | undefined,
): string {
  switch (status) {
    case "active":
      return intl.formatMessage({
        id: "connectors.status.active",
        defaultMessage: "Connected",
      });
    case "degraded":
      return intl.formatMessage({
        id: "connectors.status.degraded",
        defaultMessage: "Needs attention",
      });
    case "error":
      return intl.formatMessage({
        id: "connectors.status.error",
        defaultMessage: "Connection error",
      });
    case "pending":
      return intl.formatMessage({
        id: "connectors.status.pending",
        defaultMessage: "Connecting\u2026",
      });
    default:
      return status
        ? titleCase(status)
        : intl.formatMessage({
            id: "connectors.status.connected",
            defaultMessage: "Connected",
          });
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
          <option value="">
            {intl.formatMessage({
              id: "connectors.filter.allTiers",
              defaultMessage: "All tiers",
            })}
          </option>
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
          <option value="">
            {intl.formatMessage({
              id: "connectors.filter.allCategories",
              defaultMessage: "All categories",
            })}
          </option>
          {(facets.data?.categories ?? []).map((c) => (
            <option key={c} value={c}>
              {categoryLabel(c)}
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
          <option value="">
            {intl.formatMessage({
              id: "connectors.filter.allCapabilities",
              defaultMessage: "All capabilities",
            })}
          </option>
          {capabilityOptions.map((o) => (
            <option key={o.value} value={o.value}>
              {capabilityFacetLabel(intl, o.value)}
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
  const intl = useIntl();
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
                  {categoryLabel(entry.category)}
                </span>
              </div>
              <Badge tone={tierTone(entry.tier)}>{entry.tier}</Badge>
            </div>
            <div className="connector-card__caps">
              {caps.slice(0, 6).map((c) => (
                <Badge key={c.key} tone="neutral">
                  {colLabel(intl, c)}
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
                  {connectorStatusLabel(intl, entry.status)}
                </Badge>
              ) : (
                <span className="muted" style={{ fontSize: 12.5 }}>
                  {intl.formatMessage({
                    id: "connectors.notConnected",
                    defaultMessage: "Not connected",
                  })}
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
                {entry.connected
                  ? intl.formatMessage({
                      id: "connectors.configure",
                      defaultMessage: "Configure",
                    })
                  : intl.formatMessage({
                      id: "connectors.setUp",
                      defaultMessage: "Set up",
                    })}
              </button>
            </div>
          </Card>
        );
      })}
    </div>
  );
}

function CapabilityMatrix({ rows }: { rows: ConnectorCatalogueEntry[] }) {
  const intl = useIntl();
  const navigate = useNavigate();
  const columns: CapabilityColumn[] = [...USER_FACING, ...OPERATIONAL];
  const openSetup = (provider: string) =>
    navigate({
      to: "/connectors/$provider/setup",
      params: { provider },
    });
  return (
    <div className="matrix-scroll">
      <table
        className="table matrix"
        aria-label={intl.formatMessage({
          id: "connectors.matrix.caption",
          defaultMessage: "Connector capability matrix",
        })}
      >
        <thead>
          <tr>
            <th scope="col" className="matrix__rowhead">
              {intl.formatMessage({
                id: "connectors.matrix.connector",
                defaultMessage: "Connector",
              })}
            </th>
            {columns.map((c) => (
              <th key={c.key} scope="col" className="matrix__cap">
                <span>{colLabel(intl, c)}</span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((entry) => (
            <tr
              key={entry.provider}
              className="matrix__row"
              onClick={() => openSetup(entry.provider)}
            >
              <th scope="row" className="matrix__rowhead">
                <button
                  type="button"
                  className="link-button matrix__name"
                  onClick={(e) => {
                    e.stopPropagation();
                    openSetup(entry.provider);
                  }}
                >
                  {entry.display_name}
                </button>
                <Badge tone={tierTone(entry.tier)}>{entry.tier}</Badge>
              </th>
              {columns.map((c) => {
                const supported =
                  c.dimension === "user_facing"
                    ? entry.user_facing[c.key]
                    : entry.operational[c.key];
                const label = colLabel(intl, c);
                return (
                  <td key={c.key} className="matrix__cell">
                    <span
                      className={`matrix__dot ${
                        supported ? "matrix__dot--ok" : "matrix__dot--no"
                      }`}
                      role="img"
                      aria-label={
                        supported
                          ? intl.formatMessage(
                              {
                                id: "connectors.matrix.supported",
                                defaultMessage: "{cap}: supported",
                              },
                              { cap: label },
                            )
                          : intl.formatMessage(
                              {
                                id: "connectors.matrix.notSupported",
                                defaultMessage: "{cap}: not supported",
                              },
                              { cap: label },
                            )
                      }
                    />
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
