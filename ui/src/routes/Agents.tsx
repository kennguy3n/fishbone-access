import { useMemo, useState } from "react";
import { useIntl } from "react-intl";
import {
  PageHeader,
  Card,
  Stat,
  Badge,
  StatusBadge,
  AsyncBoundary,
} from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { Modal } from "@/components/Modal";
import { HelpTooltip } from "@/components/HelpTooltip";
import { useToast } from "@/components/Toast";
import {
  useAgents,
  useMintAgentToken,
  useRevokeAgent,
  useAgentReachable,
  useAgentBoundTargets,
  useBindAgentTarget,
  useUnbindAgentTarget,
  usePamTargets,
  type AgentView,
  type AgentHealth,
  type MintAgentTokenResult,
  type PamTarget,
  ApiError,
} from "@/api/access";
import { runtimeConfig } from "@/lib/runtime-config";
import { formatRelative, formatDateTime } from "@/lib/format";
import type { Tone } from "@/lib/format";

// Map an agent's derived health to a badge tone. Online is positive, stale is a
// soft warning (a beat was missed but the cert is still valid), offline is
// neutral (expected for an agent that isn't running), revoked is danger.
const HEALTH_TONE: Record<AgentHealth, Tone> = {
  online: "ok",
  stale: "warn",
  offline: "neutral",
  revoked: "danger",
};

export function Agents() {
  const intl = useIntl();
  const toast = useToast();
  const agents = useAgents({ refetchInterval: 15_000 });
  const mint = useMintAgentToken();

  const [enrollOpen, setEnrollOpen] = useState(false);
  const [name, setName] = useState("");
  const [minted, setMinted] = useState<MintAgentTokenResult | null>(null);
  const [manage, setManage] = useState<AgentView | null>(null);

  const stats = useMemo(() => {
    const rows = agents.data ?? [];
    return {
      total: rows.length,
      online: rows.filter((a) => a.health === "online").length,
      offline: rows.filter(
        (a) => a.health === "offline" || a.health === "stale",
      ).length,
      revoked: rows.filter((a) => a.health === "revoked").length,
    };
  }, [agents.data]);

  const submitEnroll = async () => {
    const trimmed = name.trim();
    if (!trimmed) return;
    try {
      const res = await mint.mutateAsync({ name: trimmed });
      setMinted(res);
      setEnrollOpen(false);
      setName("");
    } catch (err) {
      toast.error(
        intl.formatMessage({
          id: "agents.enroll.error",
          defaultMessage: "Could not create enrollment token",
        }),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  const columns: Column<AgentView>[] = [
    {
      header: intl.formatMessage({ id: "agents.col.agent", defaultMessage: "Agent" }),
      cell: (v) => (
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <b>{v.agent.name}</b>
          <span className="muted" style={{ fontSize: 12 }}>
            {v.agent.platform ? <code>{v.agent.platform}</code> : "—"}
            {v.agent.agent_version ? ` · ${v.agent.agent_version}` : ""}
          </span>
        </div>
      ),
    },
    {
      header: intl.formatMessage({ id: "agents.col.health", defaultMessage: "Health" }),
      cell: (v) => (
        <Badge tone={HEALTH_TONE[v.health]} dot>
          {intl.formatMessage(
            {
              id: "agents.health.label",
              defaultMessage:
                "{health, select, online {Online} stale {Stale} revoked {Revoked} other {Offline}}",
            },
            { health: v.health },
          )}
        </Badge>
      ),
    },
    {
      header: intl.formatMessage({ id: "agents.col.lastSeen", defaultMessage: "Last seen" }),
      cell: (v) => (
        <span title={formatDateTime(v.agent.last_seen_at)}>
          {v.agent.last_seen_at ? formatRelative(v.agent.last_seen_at) : "—"}
        </span>
      ),
    },
    {
      header: intl.formatMessage({ id: "agents.col.certExpiry", defaultMessage: "Cert expiry" }),
      cell: (v) => (
        <span className="muted" style={{ fontSize: 12 }}>
          {formatRelative(v.agent.cert_not_after)}
        </span>
      ),
    },
    {
      header: "",
      width: 120,
      cell: (v) => (
        <button
          className="btn btn--sm btn--ghost"
          onClick={(e) => {
            e.stopPropagation();
            setManage(v);
          }}
          disabled={v.health === "revoked"}
        >
          {intl.formatMessage({ id: "agents.action.manage", defaultMessage: "Manage" })}
        </button>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title={intl.formatMessage({
          id: "agents.title",
          defaultMessage: "Connector agents",
        })}
        subtitle={intl.formatMessage({
          id: "agents.subtitle",
          defaultMessage:
            "Reach private targets with zero inbound exposure. Run one lightweight agent inside your network; it dials out to ShieldNet over mTLS, and the gateway brokers SSH and database sessions back through that tunnel — no firewall ports, no VPN.",
        })}
        actions={
          <button className="btn btn--primary" onClick={() => setEnrollOpen(true)}>
            {intl.formatMessage({ id: "agents.enroll.cta", defaultMessage: "Enroll agent" })}
          </button>
        }
      />

      <div className="grid grid--stats" style={{ marginBottom: 20 }}>
        <Stat
          label={intl.formatMessage({ id: "agents.stat.total", defaultMessage: "Agents" })}
          value={stats.total}
        />
        <Stat
          label={intl.formatMessage({ id: "agents.stat.online", defaultMessage: "Online" })}
          value={stats.online}
        />
        <Stat
          label={intl.formatMessage({ id: "agents.stat.offline", defaultMessage: "Offline" })}
          value={stats.offline}
        />
        <Stat
          label={intl.formatMessage({ id: "agents.stat.revoked", defaultMessage: "Revoked" })}
          value={stats.revoked}
        />
      </div>

      <Card>
        <AsyncBoundary
          isLoading={agents.isLoading}
          error={agents.error}
          data={agents.data}
          onRetry={() => void agents.refetch()}
          isEmpty={(rows) => rows.length === 0}
          empty={
            <EmptyState
              title={intl.formatMessage({
                id: "agents.empty.title",
                defaultMessage: "No connector agents yet",
              })}
              description={intl.formatMessage({
                id: "agents.empty.desc",
                defaultMessage:
                  "Enroll an agent to broker access to targets that live inside a private network. The agent connects outbound only, so you never expose an inbound port.",
              })}
              action={
                <button className="btn btn--primary" onClick={() => setEnrollOpen(true)}>
                  {intl.formatMessage({ id: "agents.enroll.cta", defaultMessage: "Enroll agent" })}
                </button>
              }
            />
          }
        >
          {(rows) => (
            <DataTable
              columns={columns}
              rows={rows}
              rowKey={(v) => v.agent.id}
              onRowClick={(v) => v.health !== "revoked" && setManage(v)}
            />
          )}
        </AsyncBoundary>
      </Card>

      {enrollOpen && (
        <EnrollModal
          name={name}
          setName={setName}
          pending={mint.isPending}
          onClose={() => {
            setEnrollOpen(false);
            setName("");
          }}
          onSubmit={submitEnroll}
        />
      )}

      {minted && <TokenModal minted={minted} onClose={() => setMinted(null)} />}

      {manage && (
        <ManageModal agent={manage.agent} onClose={() => setManage(null)} />
      )}
    </>
  );
}

function EnrollModal({
  name,
  setName,
  pending,
  onClose,
  onSubmit,
}: {
  name: string;
  setName: (v: string) => void;
  pending: boolean;
  onClose: () => void;
  onSubmit: () => void;
}) {
  const intl = useIntl();
  const valid = name.trim().length > 0;
  return (
    <Modal
      title={intl.formatMessage({ id: "agents.enroll.title", defaultMessage: "Enroll a connector agent" })}
      onClose={onClose}
      footer={
        <>
          <button className="btn btn--ghost" onClick={onClose}>
            {intl.formatMessage({ id: "common.cancel", defaultMessage: "Cancel" })}
          </button>
          <button
            className="btn btn--primary"
            disabled={!valid || pending}
            onClick={onSubmit}
          >
            {pending
              ? intl.formatMessage({ id: "agents.enroll.creating", defaultMessage: "Creating…" })
              : intl.formatMessage({ id: "agents.enroll.create", defaultMessage: "Create enrollment token" })}
          </button>
        </>
      }
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <label className="field">
          <span className="field__label">
            {intl.formatMessage({ id: "agents.field.name", defaultMessage: "Agent name" })}
            <HelpTooltip>
              {intl.formatMessage({
                id: "agents.field.name.help",
                defaultMessage:
                  "A label you'll recognise — usually where the agent runs, e.g. \"office-lan\" or \"aws-vpc-prod\".",
              })}
            </HelpTooltip>
          </span>
          <input
            value={name}
            autoFocus
            placeholder={intl.formatMessage({
              id: "agents.field.name.ph",
              defaultMessage: "office-lan",
            })}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && name.trim()) onSubmit();
            }}
          />
        </label>
        <p className="muted" style={{ fontSize: 13, margin: 0 }}>
          {intl.formatMessage({
            id: "agents.enroll.note",
            defaultMessage:
              "We'll generate a one-time enrollment token. It is shown once, expires shortly, and can enroll exactly one agent.",
          })}
        </p>
      </div>
    </Modal>
  );
}

function TokenModal({
  minted,
  onClose,
}: {
  minted: MintAgentTokenResult;
  onClose: () => void;
}) {
  const intl = useIntl();
  const toast = useToast();
  const apiBase = runtimeConfig().apiBaseUrl || window.location.origin;
  const command = [
    `ACCESS_AGENT_API_URL=${apiBase}`,
    `ACCESS_AGENT_TOKEN=${minted.token}`,
    `ACCESS_AGENT_REACHABLE=10.0.0.0/24`,
    `access-target-agent`,
  ].join(" \\\n  ");

  const copy = async (value: string, label: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toast.success(label);
    } catch {
      toast.error(
        intl.formatMessage({ id: "agents.copy.fail", defaultMessage: "Copy failed" }),
      );
    }
  };

  return (
    <Modal
      title={intl.formatMessage({ id: "agents.token.title", defaultMessage: "Agent enrollment token" })}
      onClose={onClose}
      footer={
        <button className="btn btn--primary" onClick={onClose}>
          {intl.formatMessage({ id: "agents.token.done", defaultMessage: "Done" })}
        </button>
      }
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <div className="callout callout--info" role="alert">
          {intl.formatMessage(
            {
              id: "agents.token.warning",
              defaultMessage:
                "Copy this now — the token is shown only once and expires {expires}.",
            },
            { expires: formatRelative(minted.expires_at) },
          )}
        </div>

        <label className="field">
          <span className="field__label">
            {intl.formatMessage({ id: "agents.token.label", defaultMessage: "Enrollment token" })}
          </span>
          <div style={{ display: "flex", gap: 8 }}>
            <input readOnly value={minted.token} />
            <button
              className="btn btn--sm"
              onClick={() =>
                copy(
                  minted.token,
                  intl.formatMessage({ id: "agents.token.copied", defaultMessage: "Token copied" }),
                )
              }
            >
              {intl.formatMessage({ id: "common.copy", defaultMessage: "Copy" })}
            </button>
          </div>
        </label>

        <div className="field">
          <span className="field__label">
            {intl.formatMessage({ id: "agents.token.run", defaultMessage: "Run the agent" })}
            <HelpTooltip>
              {intl.formatMessage({
                id: "agents.token.run.help",
                defaultMessage:
                  "Run this on any one host inside the network you want to reach. Set ACCESS_AGENT_REACHABLE to the CIDRs or hosts that host can reach.",
              })}
            </HelpTooltip>
          </span>
          <pre className="code-block" style={{ margin: 0 }}>
            <code>{command}</code>
          </pre>
          <div style={{ marginTop: 8 }}>
            <button
              className="btn btn--sm"
              onClick={() =>
                copy(
                  command,
                  intl.formatMessage({ id: "agents.token.cmdCopied", defaultMessage: "Command copied" }),
                )
              }
            >
              {intl.formatMessage({ id: "agents.token.copyCmd", defaultMessage: "Copy command" })}
            </button>
          </div>
        </div>
      </div>
    </Modal>
  );
}

function ManageModal({
  agent,
  onClose,
}: {
  agent: AgentView["agent"];
  onClose: () => void;
}) {
  const intl = useIntl();
  const toast = useToast();
  const reachable = useAgentReachable(agent.id);
  const bound = useAgentBoundTargets(agent.id);
  const targets = usePamTargets();
  const bind = useBindAgentTarget(agent.id);
  const unbind = useUnbindAgentTarget(agent.id);
  const revoke = useRevokeAgent();
  const [selected, setSelected] = useState("");
  const [confirmRevoke, setConfirmRevoke] = useState(false);

  // Targets eligible to bind: not already routed via an agent.
  const bindable = useMemo<PamTarget[]>(
    () => (targets.data ?? []).filter((t) => !t.via_agent_id),
    [targets.data],
  );

  const doBind = async () => {
    if (!selected) return;
    try {
      await bind.mutateAsync(selected);
      setSelected("");
      toast.success(
        intl.formatMessage({ id: "agents.bind.ok", defaultMessage: "Target bound to agent" }),
      );
    } catch (err) {
      toast.error(
        intl.formatMessage({ id: "agents.bind.fail", defaultMessage: "Could not bind target" }),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  const doUnbind = async (targetId: string) => {
    try {
      await unbind.mutateAsync(targetId);
      toast.success(
        intl.formatMessage({ id: "agents.unbind.ok", defaultMessage: "Target unbound" }),
      );
    } catch (err) {
      toast.error(
        intl.formatMessage({ id: "agents.unbind.fail", defaultMessage: "Could not unbind target" }),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  const doRevoke = async () => {
    try {
      await revoke.mutateAsync(agent.id);
      toast.success(
        intl.formatMessage({ id: "agents.revoke.ok", defaultMessage: "Agent revoked" }),
      );
      onClose();
    } catch (err) {
      toast.error(
        intl.formatMessage({ id: "agents.revoke.fail", defaultMessage: "Could not revoke agent" }),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  return (
    <Modal
      title={agent.name}
      onClose={onClose}
      footer={
        confirmRevoke ? (
          <>
            <span className="muted" style={{ marginRight: "auto", fontSize: 13 }}>
              {intl.formatMessage({
                id: "agents.revoke.confirm",
                defaultMessage:
                  "Revoke this agent? Its tunnel is dropped and bound targets become unreachable until rebound.",
              })}
            </span>
            <button className="btn btn--ghost" onClick={() => setConfirmRevoke(false)}>
              {intl.formatMessage({ id: "common.cancel", defaultMessage: "Cancel" })}
            </button>
            <button className="btn btn--danger" disabled={revoke.isPending} onClick={doRevoke}>
              {intl.formatMessage({ id: "agents.revoke.cta", defaultMessage: "Revoke agent" })}
            </button>
          </>
        ) : (
          <>
            <button className="btn btn--ghost" onClick={() => setConfirmRevoke(true)}>
              {intl.formatMessage({ id: "agents.revoke.cta", defaultMessage: "Revoke agent" })}
            </button>
            <button className="btn btn--primary" onClick={onClose}>
              {intl.formatMessage({ id: "common.close", defaultMessage: "Close" })}
            </button>
          </>
        )
      }
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <StatusBadge status={agent.status} />
          {agent.platform && <Badge tone="neutral">{agent.platform}</Badge>}
          {agent.agent_version && <Badge tone="neutral">{agent.agent_version}</Badge>}
          <span className="muted" style={{ fontSize: 12 }}>
            {intl.formatMessage(
              { id: "agents.manage.lastSeen", defaultMessage: "Last seen {when}" },
              {
                when: agent.last_seen_at ? formatRelative(agent.last_seen_at) : "—",
              },
            )}
          </span>
        </div>

        <section>
          <h4 style={{ margin: "4px 0 8px" }}>
            {intl.formatMessage({ id: "agents.bound.title", defaultMessage: "Bound targets" })}
            <HelpTooltip>
              {intl.formatMessage({
                id: "agents.bound.help",
                defaultMessage:
                  "Targets routed through this agent's tunnel. The gateway reaches these over the agent instead of dialing them directly.",
              })}
            </HelpTooltip>
          </h4>
          {(bound.data ?? []).length === 0 ? (
            <p className="muted" style={{ fontSize: 13, margin: 0 }}>
              {intl.formatMessage({
                id: "agents.bound.none",
                defaultMessage: "No targets are routed through this agent yet.",
              })}
            </p>
          ) : (
            <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 8 }}>
              {(bound.data ?? []).map((t) => (
                <li
                  key={t.id}
                  style={{ display: "flex", alignItems: "center", gap: 8, justifyContent: "space-between" }}
                >
                  <span>
                    <b>{t.name}</b>{" "}
                    <span className="muted" style={{ fontSize: 12 }}>
                      <code>{t.address}</code> · {t.protocol}
                    </span>
                  </span>
                  <button
                    className="btn btn--sm btn--ghost"
                    disabled={unbind.isPending}
                    onClick={() => doUnbind(t.id)}
                  >
                    {intl.formatMessage({ id: "agents.unbind.cta", defaultMessage: "Unbind" })}
                  </button>
                </li>
              ))}
            </ul>
          )}

          <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
            <select
              value={selected}
              onChange={(e) => setSelected(e.target.value)}
              aria-label={intl.formatMessage({
                id: "agents.bind.select",
                defaultMessage: "Select a target to route via this agent",
              })}
            >
              <option value="">
                {intl.formatMessage({
                  id: "agents.bind.placeholder",
                  defaultMessage: "Route a target via this agent…",
                })}
              </option>
              {bindable.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} ({t.address})
                </option>
              ))}
            </select>
            <button
              className="btn btn--primary btn--sm"
              disabled={!selected || bind.isPending}
              onClick={doBind}
            >
              {intl.formatMessage({ id: "agents.bind.cta", defaultMessage: "Bind" })}
            </button>
          </div>
          {bindable.length === 0 && (
            <p className="muted" style={{ fontSize: 12, marginTop: 6 }}>
              {intl.formatMessage({
                id: "agents.bind.noneAvailable",
                defaultMessage:
                  "Every target is already routed directly or via an agent. Register a target on the PAM targets page first.",
              })}
            </p>
          )}
        </section>

        <section>
          <h4 style={{ margin: "4px 0 8px" }}>
            {intl.formatMessage({ id: "agents.reach.title", defaultMessage: "Reachable network" })}
            <HelpTooltip>
              {intl.formatMessage({
                id: "agents.reach.help",
                defaultMessage:
                  "The destinations the agent advertised it can reach (from ACCESS_AGENT_REACHABLE) plus the targets you've bound. The gateway fails closed if a target isn't covered.",
              })}
            </HelpTooltip>
          </h4>
          {(reachable.data ?? []).length === 0 ? (
            <p className="muted" style={{ fontSize: 13, margin: 0 }}>
              {intl.formatMessage({
                id: "agents.reach.none",
                defaultMessage: "The agent hasn't reported any reachable destinations yet.",
              })}
            </p>
          ) : (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {(reachable.data ?? []).map((r) => (
                <Badge key={r.id} tone="info">
                  <code>{r.pattern}</code> · {r.kind}
                </Badge>
              ))}
            </div>
          )}
        </section>
      </div>
    </Modal>
  );
}
