import { useMemo, useState, type ReactNode } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import {
  PageHeader,
  Card,
  Stat,
  Badge,
  StatusBadge,
  AsyncBoundary,
} from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState, EmptyIllustration } from "@/components/EmptyState";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/Toast";
import { Icon } from "@/components/Icon";
import { formatRelative } from "@/lib/format";
import { useHasPermission, Perm } from "@/lib/permissions";
import { ApiError } from "@/api/access";
import {
  useDiscoverySummary,
  useDiscoveredAssets,
  useDiscoveredAccounts,
  useDiscoveryScans,
  useIgnoreAsset,
  useDispositionAccount,
  type DiscoveredAsset,
  type DiscoveredAccount,
  type DiscoveryScan,
  type AccountDisposition,
} from "@/api/discovery";
import { OnboardAssetModal } from "./discovery/OnboardAssetModal";
import { RunDiscoveryModal } from "./discovery/RunDiscoveryModal";
import { AutoOnboardingPolicyEditor } from "./discovery/AutoOnboardingPolicyEditor";

type Tab = "assets" | "accounts" | "scans" | "policy";

const SOURCE_LABELS: Record<string, string> = {
  agent_sweep: "Agent network",
  connector_inventory: "Cloud connector",
  db_accounts: "Database",
};

function statusTone(status: string): "ok" | "warn" | "danger" | "neutral" {
  switch (status) {
    case "managed":
      return "ok";
    case "unmanaged":
      return "warn";
    case "orphan":
      return "danger";
    default:
      return "neutral";
  }
}

export function Discovery() {
  const intl = useIntl();
  const canWrite = useHasPermission(Perm.PamTargetWrite);
  const [tab, setTab] = useState<Tab>("assets");
  const [running, setRunning] = useState(false);

  const summaryQ = useDiscoverySummary();

  return (
    <>
      <PageHeader
        title={intl.formatMessage({
          id: "discovery.title",
          defaultMessage: "Discovery & onboarding",
        })}
        subtitle={intl.formatMessage({
          id: "discovery.subtitle",
          defaultMessage:
            "Find the hosts, databases and accounts in your environment, see what is managed versus exposed, and onboard them in one click.",
        })}
        actions={
          canWrite ? (
            <button
              className="btn btn--primary"
              onClick={() => setRunning(true)}
            >
              <Icon name="search" size={16} />{" "}
              <FormattedMessage
                id="discovery.runButton"
                defaultMessage="Run discovery"
              />
            </button>
          ) : undefined
        }
      />

      <AsyncBoundary
        isLoading={summaryQ.isLoading}
        error={summaryQ.error}
        data={summaryQ.data}
        onRetry={summaryQ.refetch}
        loading={<div className="grid grid--stats" aria-busy="true" />}
      >
        {(s) => (
          <div className="grid grid--stats">
            <Card>
              <Stat
                label={intl.formatMessage({
                  id: "discovery.stat.total",
                  defaultMessage: "Discovered assets",
                })}
                value={s.total_assets}
              />
            </Card>
            <Card>
              <Stat
                label={intl.formatMessage({
                  id: "discovery.stat.unmanaged",
                  defaultMessage: "Unmanaged",
                })}
                value={s.unmanaged_assets}
                delta={
                  s.recommended_now > 0 ? (
                    <span style={{ color: "var(--warn)" }}>
                      <FormattedMessage
                        id="discovery.stat.recommended"
                        defaultMessage="{n} recommended to onboard"
                        values={{ n: s.recommended_now }}
                      />
                    </span>
                  ) : undefined
                }
              />
            </Card>
            <Card>
              <Stat
                label={intl.formatMessage({
                  id: "discovery.stat.managed",
                  defaultMessage: "Managed",
                })}
                value={s.managed_assets}
              />
            </Card>
            <Card>
              <Stat
                label={intl.formatMessage({
                  id: "discovery.stat.orphans",
                  defaultMessage: "Orphan accounts",
                })}
                value={s.orphan_accounts}
              />
            </Card>
          </div>
        )}
      </AsyncBoundary>

      <div
        className="pill-tabs"
        role="tablist"
        aria-label={intl.formatMessage({
          id: "discovery.tabs",
          defaultMessage: "Discovery views",
        })}
        style={{ marginTop: 20, marginBottom: 16 }}
      >
        <button
          role="tab"
          aria-selected={tab === "assets"}
          className={tab === "assets" ? "active" : ""}
          onClick={() => setTab("assets")}
        >
          <FormattedMessage id="discovery.tab.assets" defaultMessage="Assets" />
        </button>
        <button
          role="tab"
          aria-selected={tab === "accounts"}
          className={tab === "accounts" ? "active" : ""}
          onClick={() => setTab("accounts")}
        >
          <FormattedMessage
            id="discovery.tab.accounts"
            defaultMessage="Accounts"
          />
        </button>
        <button
          role="tab"
          aria-selected={tab === "scans"}
          className={tab === "scans" ? "active" : ""}
          onClick={() => setTab("scans")}
        >
          <FormattedMessage
            id="discovery.tab.scans"
            defaultMessage="Scan history"
          />
        </button>
        <button
          role="tab"
          aria-selected={tab === "policy"}
          className={tab === "policy" ? "active" : ""}
          onClick={() => setTab("policy")}
        >
          <FormattedMessage
            id="discovery.tab.policy"
            defaultMessage="Auto-onboarding"
          />
        </button>
      </div>

      {tab === "assets" && (
        <AssetsTab canWrite={canWrite} onRunDiscovery={() => setRunning(true)} />
      )}
      {tab === "accounts" && <AccountsTab canWrite={canWrite} />}
      {tab === "scans" && <ScansTab />}
      {tab === "policy" &&
        (canWrite ? (
          <AutoOnboardingPolicyEditor />
        ) : (
          <Card>
            <EmptyState
              illustration={<EmptyIllustration kind="policy" />}
              title={intl.formatMessage({
                id: "discovery.policy.readonly.title",
                defaultMessage: "Read-only access",
              })}
              description={intl.formatMessage({
                id: "discovery.policy.readonly.desc",
                defaultMessage:
                  "You can browse the inventory, but editing the auto-onboarding policy requires the PAM target write permission.",
              })}
            />
          </Card>
        ))}

      {running && <RunDiscoveryModal onClose={() => setRunning(false)} />}
    </>
  );
}

// ---------------------------------------------------------------------------
// Assets
// ---------------------------------------------------------------------------

const SOURCES = ["agent_sweep", "connector_inventory", "db_accounts"];
const STATUSES = ["unmanaged", "managed", "orphan", "ignored"];

function AssetsTab({
  canWrite,
  onRunDiscovery,
}: {
  canWrite: boolean;
  onRunDiscovery: () => void;
}) {
  const intl = useIntl();
  const [source, setSource] = useState("");
  const [status, setStatus] = useState("");
  const [protocol, setProtocol] = useState("");
  const [active, setActive] = useState<DiscoveredAsset | null>(null);
  const [onboarding, setOnboarding] = useState<DiscoveredAsset | null>(null);

  const filters = useMemo(
    () => ({ source, status, protocol }),
    [source, status, protocol],
  );
  const assetsQ = useDiscoveredAssets(filters);

  // Protocol facet derived from the current result set so the filter only
  // offers protocols actually present.
  const protocols = useMemo(() => {
    const set = new Set<string>();
    (assetsQ.data ?? []).forEach((a) => a.protocol && set.add(a.protocol));
    return Array.from(set).sort();
  }, [assetsQ.data]);

  const columns: Column<DiscoveredAsset>[] = [
    {
      header: intl.formatMessage({
        id: "discovery.col.asset",
        defaultMessage: "Asset",
      }),
      cell: (a) => (
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <b>{a.name || a.address}</b>
          <span className="muted" style={{ fontSize: 12 }}>
            <code>{a.address}</code>
          </span>
        </div>
      ),
    },
    {
      header: intl.formatMessage({
        id: "discovery.col.protocol",
        defaultMessage: "Protocol",
      }),
      cell: (a) =>
        a.protocol ? <Badge tone="info">{a.protocol}</Badge> : <>—</>,
    },
    {
      header: intl.formatMessage({
        id: "discovery.col.source",
        defaultMessage: "Source",
      }),
      cell: (a) => (
        <span className="muted">{SOURCE_LABELS[a.source] ?? a.source}</span>
      ),
    },
    {
      header: intl.formatMessage({
        id: "discovery.col.status",
        defaultMessage: "Status",
      }),
      cell: (a) => (
        <Badge tone={statusTone(a.status)} dot>
          {a.status}
        </Badge>
      ),
    },
    {
      header: intl.formatMessage({
        id: "discovery.col.lastSeen",
        defaultMessage: "Last seen",
      }),
      cell: (a) => (
        <span className="muted">{formatRelative(a.last_seen_at)}</span>
      ),
    },
  ];

  return (
    <>
      <div
        className="filter-bar"
        style={{ display: "flex", gap: 12, marginBottom: 14, flexWrap: "wrap" }}
      >
        <label className="field" style={{ maxWidth: 200 }}>
          <span>
            <FormattedMessage
              id="discovery.filter.source"
              defaultMessage="Source"
            />
          </span>
          <select value={source} onChange={(e) => setSource(e.target.value)}>
            <option value="">
              {intl.formatMessage({
                id: "discovery.filter.all",
                defaultMessage: "All",
              })}
            </option>
            {SOURCES.map((s) => (
              <option key={s} value={s}>
                {SOURCE_LABELS[s] ?? s}
              </option>
            ))}
          </select>
        </label>
        <label className="field" style={{ maxWidth: 200 }}>
          <span>
            <FormattedMessage
              id="discovery.filter.status"
              defaultMessage="Status"
            />
          </span>
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">
              {intl.formatMessage({
                id: "discovery.filter.all",
                defaultMessage: "All",
              })}
            </option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <label className="field" style={{ maxWidth: 200 }}>
          <span>
            <FormattedMessage
              id="discovery.filter.protocol"
              defaultMessage="Protocol"
            />
          </span>
          <select
            value={protocol}
            onChange={(e) => setProtocol(e.target.value)}
          >
            <option value="">
              {intl.formatMessage({
                id: "discovery.filter.all",
                defaultMessage: "All",
              })}
            </option>
            {protocols.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </label>
      </div>

      <AsyncBoundary
        isLoading={assetsQ.isLoading}
        error={assetsQ.error}
        data={assetsQ.data}
        onRetry={assetsQ.refetch}
        isEmpty={(rows) => rows.length === 0}
        empty={
          source || status || protocol ? (
            <EmptyState
              illustration={<EmptyIllustration kind="search" />}
              title={intl.formatMessage({
                id: "discovery.assets.noMatch",
                defaultMessage: "No assets match these filters",
              })}
              description={intl.formatMessage({
                id: "discovery.assets.noMatch.desc",
                defaultMessage: "Try clearing a filter to widen the search.",
              })}
            />
          ) : (
            <EmptyState
              illustration={<EmptyIllustration kind="search" />}
              title={intl.formatMessage({
                id: "discovery.assets.empty",
                defaultMessage: "No assets discovered yet",
              })}
              description={intl.formatMessage({
                id: "discovery.assets.empty.desc",
                defaultMessage:
                  "Run your first discovery sweep to find hosts and databases in your environment. Nothing is changed until you choose to onboard.",
              })}
              action={
                canWrite ? (
                  <button
                    className="btn btn--primary btn--sm"
                    onClick={onRunDiscovery}
                  >
                    <FormattedMessage
                      id="discovery.runButton"
                      defaultMessage="Run discovery"
                    />
                  </button>
                ) : undefined
              }
            />
          )
        }
      >
        {(rows) => (
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(a) => a.id}
            onRowClick={(a) => setActive(a)}
          />
        )}
      </AsyncBoundary>

      {active && (
        <AssetDetailModal
          asset={active}
          canWrite={canWrite}
          onClose={() => setActive(null)}
          onOnboard={() => {
            setOnboarding(active);
            setActive(null);
          }}
        />
      )}
      {onboarding && (
        <OnboardAssetModal
          asset={onboarding}
          onClose={() => setOnboarding(null)}
          onDone={() => setOnboarding(null)}
        />
      )}
    </>
  );
}

function AssetDetailModal({
  asset,
  canWrite,
  onClose,
  onOnboard,
}: {
  asset: DiscoveredAsset;
  canWrite: boolean;
  onClose: () => void;
  onOnboard: () => void;
}) {
  const intl = useIntl();
  const toast = useToast();
  const ignoreMut = useIgnoreAsset();

  const ignore = async () => {
    try {
      await ignoreMut.mutateAsync(asset.id);
      toast.success(
        intl.formatMessage({
          id: "discovery.ignore.success",
          defaultMessage: "Asset ignored",
        }),
      );
      onClose();
    } catch (err) {
      toast.error(
        intl.formatMessage({
          id: "discovery.ignore.error",
          defaultMessage: "Could not ignore asset",
        }),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  const rows: Array<[string, ReactNode]> = [
    [
      intl.formatMessage({ id: "discovery.detail.address", defaultMessage: "Address" }),
      <code key="addr">{asset.address}</code>,
    ],
    [
      intl.formatMessage({ id: "discovery.col.protocol", defaultMessage: "Protocol" }),
      asset.protocol || "—",
    ],
    [
      intl.formatMessage({ id: "discovery.col.source", defaultMessage: "Source" }),
      SOURCE_LABELS[asset.source] ?? asset.source,
    ],
    [
      intl.formatMessage({ id: "discovery.detail.externalId", defaultMessage: "External ID" }),
      <code key="eid">{asset.external_id}</code>,
    ],
    [
      intl.formatMessage({ id: "discovery.detail.firstSeen", defaultMessage: "First seen" }),
      formatRelative(asset.first_seen_at),
    ],
    [
      intl.formatMessage({ id: "discovery.col.lastSeen", defaultMessage: "Last seen" }),
      formatRelative(asset.last_seen_at),
    ],
  ];

  const canOnboard = canWrite && asset.status !== "managed";

  return (
    <Modal
      title={asset.name || asset.address}
      onClose={onClose}
      footer={
        <>
          <button className="btn btn--ghost" onClick={onClose}>
            <FormattedMessage id="common.close" defaultMessage="Close" />
          </button>
          {canWrite && asset.status !== "ignored" && asset.status !== "managed" && (
            <button
              className="btn"
              disabled={ignoreMut.isPending}
              onClick={ignore}
            >
              <FormattedMessage
                id="discovery.detail.ignore"
                defaultMessage="Ignore"
              />
            </button>
          )}
          {canOnboard && (
            <button className="btn btn--primary" onClick={onOnboard}>
              <FormattedMessage
                id="discovery.detail.onboard"
                defaultMessage="Onboard"
              />
            </button>
          )}
        </>
      }
    >
      <div style={{ marginBottom: 12 }}>
        <Badge tone={statusTone(asset.status)} dot>
          {asset.status}
        </Badge>{" "}
        {asset.policy_matched && (
          <Badge tone="info">
            <FormattedMessage
              id="discovery.detail.policyMatched"
              defaultMessage="Policy matched"
            />
          </Badge>
        )}
      </div>
      <dl className="detail-grid">
        {rows.map(([k, v]) => (
          <div key={k} style={{ display: "flex", gap: 8, padding: "4px 0" }}>
            <dt
              className="muted"
              style={{ width: 130, flexShrink: 0 }}
            >
              {k}
            </dt>
            <dd style={{ margin: 0 }}>{v}</dd>
          </div>
        ))}
      </dl>
      {asset.status === "managed" && (
        <div className="callout callout--ok" style={{ marginTop: 12 }} role="note">
          <FormattedMessage
            id="discovery.detail.managed"
            defaultMessage="This asset is already a managed PAM target."
          />
        </div>
      )}
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

function AccountsTab({ canWrite }: { canWrite: boolean }) {
  const intl = useIntl();
  const toast = useToast();
  const accountsQ = useDiscoveredAccounts();
  const dispositionMut = useDispositionAccount();

  const disposition = async (
    a: DiscoveredAccount,
    status: AccountDisposition,
  ) => {
    try {
      await dispositionMut.mutateAsync({ id: a.id, status });
      toast.success(
        intl.formatMessage({
          id: "discovery.account.dispositioned",
          defaultMessage: "Account updated",
        }),
      );
    } catch (err) {
      toast.error(
        intl.formatMessage({
          id: "discovery.account.error",
          defaultMessage: "Could not update account",
        }),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  const columns: Column<DiscoveredAccount>[] = [
    {
      header: intl.formatMessage({
        id: "discovery.col.account",
        defaultMessage: "Account",
      }),
      cell: (a) => (
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <b>{a.username}</b>
          {a.superuser && (
            <span style={{ fontSize: 12 }}>
              <Badge tone="danger">
                <FormattedMessage
                  id="discovery.account.superuser"
                  defaultMessage="Superuser"
                />
              </Badge>
            </span>
          )}
        </div>
      ),
    },
    {
      header: intl.formatMessage({
        id: "discovery.col.canLogin",
        defaultMessage: "Login",
      }),
      cell: (a) => (
        <Badge tone={a.can_login ? "warn" : "neutral"}>
          {a.can_login
            ? intl.formatMessage({
                id: "discovery.account.canLogin",
                defaultMessage: "Can log in",
              })
            : intl.formatMessage({
                id: "discovery.account.noLogin",
                defaultMessage: "No login",
              })}
        </Badge>
      ),
    },
    {
      header: intl.formatMessage({
        id: "discovery.col.status",
        defaultMessage: "Status",
      }),
      cell: (a) => <StatusBadge status={a.status} />,
    },
    {
      header: intl.formatMessage({
        id: "discovery.col.lastSeen",
        defaultMessage: "Last seen",
      }),
      cell: (a) => (
        <span className="muted">{formatRelative(a.last_seen_at)}</span>
      ),
    },
    {
      header: "",
      cell: (a) =>
        canWrite && a.status !== "ignored" ? (
          <button
            className="btn btn--sm btn--ghost"
            disabled={dispositionMut.isPending}
            onClick={(e) => {
              e.stopPropagation();
              void disposition(a, "ignored");
            }}
          >
            <FormattedMessage
              id="discovery.account.ignore"
              defaultMessage="Ignore"
            />
          </button>
        ) : null,
    },
  ];

  return (
    <AsyncBoundary
      isLoading={accountsQ.isLoading}
      error={accountsQ.error}
      data={accountsQ.data}
      onRetry={accountsQ.refetch}
      isEmpty={(rows) => rows.length === 0}
      empty={
        <EmptyState
          illustration={<EmptyIllustration kind="inbox" />}
          title={intl.formatMessage({
            id: "discovery.accounts.empty",
            defaultMessage: "No discovered accounts",
          })}
          description={intl.formatMessage({
            id: "discovery.accounts.empty.desc",
            defaultMessage:
              "Enumerate database accounts on a Postgres or MySQL target to surface roles that exist in the database but aren't governed yet.",
          })}
        />
      }
    >
      {(rows) => (
        <DataTable columns={columns} rows={rows} rowKey={(a) => a.id} />
      )}
    </AsyncBoundary>
  );
}

// ---------------------------------------------------------------------------
// Scan history
// ---------------------------------------------------------------------------

function scanStatusTone(status: string): "ok" | "warn" | "danger" | "neutral" {
  switch (status) {
    case "completed":
      return "ok";
    case "running":
      return "warn";
    case "failed":
      return "danger";
    default:
      return "neutral";
  }
}

function ScansTab() {
  const intl = useIntl();
  const scansQ = useDiscoveryScans();

  const columns: Column<DiscoveryScan>[] = [
    {
      header: intl.formatMessage({
        id: "discovery.col.source",
        defaultMessage: "Source",
      }),
      cell: (s) => (
        <span>{s.source ? SOURCE_LABELS[s.source] ?? s.source : "—"}</span>
      ),
    },
    {
      header: intl.formatMessage({
        id: "discovery.scan.trigger",
        defaultMessage: "Trigger",
      }),
      cell: (s) => <Badge tone="neutral">{s.trigger}</Badge>,
    },
    {
      header: intl.formatMessage({
        id: "discovery.col.status",
        defaultMessage: "Status",
      }),
      cell: (s) => (
        <Badge tone={scanStatusTone(s.status)} dot>
          {s.status}
        </Badge>
      ),
    },
    {
      header: intl.formatMessage({
        id: "discovery.scan.results",
        defaultMessage: "Results",
      }),
      cell: (s) => (
        <span className="muted" style={{ fontSize: 12 }}>
          <FormattedMessage
            id="discovery.scan.resultsValue"
            defaultMessage="{assets} assets ({new} new), {accounts} accounts, {onboarded} onboarded"
            values={{
              assets: s.assets_found,
              new: s.assets_new,
              accounts: s.accounts_found,
              onboarded: s.onboarded_count,
            }}
          />
        </span>
      ),
    },
    {
      header: intl.formatMessage({
        id: "discovery.scan.started",
        defaultMessage: "Started",
      }),
      cell: (s) => (
        <span className="muted">{formatRelative(s.started_at)}</span>
      ),
    },
  ];

  return (
    <AsyncBoundary
      isLoading={scansQ.isLoading}
      error={scansQ.error}
      data={scansQ.data}
      onRetry={scansQ.refetch}
      isEmpty={(rows) => rows.length === 0}
      empty={
        <EmptyState
          illustration={<EmptyIllustration kind="search" />}
          title={intl.formatMessage({
            id: "discovery.scans.empty",
            defaultMessage: "No scans run yet",
          })}
          description={intl.formatMessage({
            id: "discovery.scans.empty.desc",
            defaultMessage:
              "Every manual and scheduled discovery run is recorded here with its results.",
          })}
        />
      }
    >
      {(rows) => (
        <DataTable columns={columns} rows={rows} rowKey={(s) => s.id} />
      )}
    </AsyncBoundary>
  );
}
