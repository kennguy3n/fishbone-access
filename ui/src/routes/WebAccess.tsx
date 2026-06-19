// WebAccess is the clientless browser-access surface: an operator picks a
// target they hold a live JIT lease for and opens a fully governed privileged
// session — an interactive SSH terminal or a SQL console — entirely in the
// browser, with no client to install. Launching mints a one-shot PAM connect
// token (the same broker the native CLI uses) and hands it to the web-access
// WebSocket bridge, which redeems the lease, opens the upstream, and streams
// the session with command policy, recording and audit all firing server-side.

import { useMemo, useState } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import {
  PageHeader,
  Card,
  Badge,
  AsyncBoundary,
} from "@/components/ui";
import { EmptyState } from "@/components/EmptyState";
import { HelpTooltip } from "@/components/HelpTooltip";
import { Icon } from "@/components/Icon";
import { useToast } from "@/components/Toast";
import {
  usePamTargets,
  usePamLeases,
  useMintConnectToken,
  useMe,
  type PamTarget,
  type PamLease,
  type WebAccessKind,
} from "@/api/access";
import { formatRelative } from "@/lib/format";
import { TerminalSession } from "./webaccess/TerminalSession";
import { DbSession } from "./webaccess/DbSession";
import { protocolLabel } from "./discovery/labels";

/** Protocols this clientless surface can drive, mapped to a bridge endpoint. */
const PROTOCOL_KIND: Record<string, WebAccessKind> = {
  ssh: "ssh",
  postgres: "db",
  mysql: "db",
};

interface Launchable {
  target: PamTarget;
  lease: PamLease;
  kind: WebAccessKind;
}

interface ActiveSession {
  rawToken: string;
  target: PamTarget;
  kind: WebAccessKind;
}

export function WebAccess() {
  const intl = useIntl();
  const toast = useToast();
  const me = useMe();
  const targets = usePamTargets();
  // Poll leases so a freshly approved lease appears (and an expired one drops
  // out) without a manual refresh while the operator is on this page.
  const leases = usePamLeases(
    { active_only: true },
    { refetchInterval: 15_000 },
  );
  const mint = useMintConnectToken();
  const [active, setActive] = useState<ActiveSession | null>(null);

  const subject = me.data?.user_id;

  // Join my live leases to their targets and keep only the protocols the
  // browser can drive. The server is the authority on whether a lease is
  // really connectable; this is the friendly pre-filter.
  const launchable = useMemo<Launchable[]>(() => {
    const byId = new Map((targets.data ?? []).map((t) => [t.id, t]));
    return (leases.data ?? [])
      .filter(
        (l) =>
          (l.state === "active" || l.state === "approved") &&
          (!subject || l.subject === subject),
      )
      .map((l) => {
        const target = byId.get(l.target_id);
        if (!target) return null;
        const kind = PROTOCOL_KIND[target.protocol];
        if (!kind) return null;
        return { target, lease: l, kind };
      })
      .filter((x): x is Launchable => x !== null);
  }, [targets.data, leases.data, subject]);

  const launch = async (item: Launchable) => {
    try {
      const res = await mint.mutateAsync({
        target_id: item.target.id,
        lease_id: item.lease.id,
      });
      setActive({
        rawToken: res.raw_token,
        target: item.target,
        kind: item.kind,
      });
    } catch (err) {
      const message =
        err instanceof Error
          ? err.message
          : intl.formatMessage({
              id: "webaccess.launch.errorGeneric",
              defaultMessage: "Could not start the session.",
            });
      toast.error(
        intl.formatMessage({
          id: "webaccess.launch.error",
          defaultMessage: "Could not start the session",
        }),
        message,
      );
    }
  };

  if (active) {
    return (
      <>
        <PageHeader
          title={active.target.name}
          subtitle={intl.formatMessage({
            id: "webaccess.session.subtitle",
            defaultMessage:
              "Live clientless session — recorded and policy-governed.",
          })}
          actions={
            <button
              className="btn btn--ghost btn--sm"
              onClick={() => setActive(null)}
            >
              <Icon name="chevron-down" size={14} />{" "}
              <FormattedMessage
                id="webaccess.backToTargets"
                defaultMessage="Back to targets"
              />
            </button>
          }
        />
        {active.kind === "ssh" ? (
          <TerminalSession
            rawToken={active.rawToken}
            onExit={() => setActive(null)}
          />
        ) : (
          <DbSession
            rawToken={active.rawToken}
            onExit={() => setActive(null)}
          />
        )}
      </>
    );
  }

  return (
    <>
      <PageHeader
        title={intl.formatMessage({
          id: "webaccess.title",
          defaultMessage: "Web access",
        })}
        subtitle={intl.formatMessage({
          id: "webaccess.subtitle",
          defaultMessage:
            "Open a privileged SSH or database session in your browser — no client to install. Every session is recorded, policy-checked, and audited.",
        })}
      />
      <AsyncBoundary
        isLoading={targets.isLoading || leases.isLoading}
        error={targets.error ?? leases.error}
        data={launchable}
        onRetry={() => {
          targets.refetch();
          leases.refetch();
        }}
        isEmpty={(rows) => rows.length === 0}
        empty={
          <EmptyState
            title={intl.formatMessage({
              id: "webaccess.empty.title",
              defaultMessage: "No connectable targets",
            })}
            description={intl.formatMessage({
              id: "webaccess.empty.description",
              defaultMessage:
                "You need an active JIT lease to a SSH, PostgreSQL, or MySQL target to open a browser session. Request a lease, then come back here.",
            })}
          />
        }
      >
        {(rows) => (
          <div className="webaccess-grid">
            {rows.map((item) => (
              <LaunchCard
                key={item.lease.id}
                item={item}
                busy={mint.isPending}
                onLaunch={() => launch(item)}
              />
            ))}
          </div>
        )}
      </AsyncBoundary>
    </>
  );
}

function LaunchCard({
  item,
  busy,
  onLaunch,
}: {
  item: Launchable;
  busy: boolean;
  onLaunch: () => void;
}) {
  const { target, lease, kind } = item;
  return (
    <Card className="webaccess-card">
      <div className="webaccess-card__head">
        <div className="webaccess-card__icon" aria-hidden>
          <Icon name={kind === "ssh" ? "troubleshoot" : "registry"} size={20} />
        </div>
        <div className="webaccess-card__title">
          <strong>{target.name}</strong>
          <span className="muted">{target.address}</span>
        </div>
        <Badge tone="info">{protocolLabel(target.protocol)}</Badge>
      </div>

      <dl className="webaccess-card__meta">
        <div>
          <dt>
            <FormattedMessage id="webaccess.card.account" defaultMessage="Account" />
          </dt>
          <dd>{target.username || "—"}</dd>
        </div>
        <div>
          <dt>
            <FormattedMessage
              id="webaccess.card.leaseExpires"
              defaultMessage="Lease expires"
            />
            <HelpTooltip>
              <FormattedMessage
                id="webaccess.card.leaseExpires.help"
                defaultMessage="Your session ends automatically when the lease window closes."
              />
            </HelpTooltip>
          </dt>
          <dd>{lease.expires_at ? formatRelative(lease.expires_at) : "—"}</dd>
        </div>
      </dl>

      <button
        className="btn btn--primary webaccess-card__launch"
        onClick={onLaunch}
        disabled={busy}
      >
        {kind === "ssh" ? (
          <FormattedMessage
            id="webaccess.card.openTerminal"
            defaultMessage="Open terminal"
          />
        ) : (
          <FormattedMessage
            id="webaccess.card.openConsole"
            defaultMessage="Open console"
          />
        )}
      </button>
    </Card>
  );
}
