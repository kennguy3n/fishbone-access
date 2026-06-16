import { useState } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import { Modal } from "@/components/Modal";
import { Badge } from "@/components/ui";
import { HelpTooltip } from "@/components/HelpTooltip";
import { useToast } from "@/components/Toast";
import {
  ApiError,
  useAgents,
  useConnectors,
  usePamTargets,
} from "@/api/access";
import {
  useImportAgentReachable,
  useScanConnectorInventory,
  useScanDBAccounts,
} from "@/api/discovery";

type Mode = "agent" | "connector" | "db";

// DB protocols whose targets we can enumerate internal roles/users on.
const DB_PROTOCOLS = new Set(["postgres", "mysql"]);

/**
 * The "Run discovery" launcher. Three real sources, each honest about what it
 * does: import an agent's self-reported reachable targets, enumerate a cloud
 * connector's asset inventory (AWS/Azure), or enumerate DB-internal accounts on
 * a registered Postgres/MySQL target. Active network probing runs in the
 * gateway/workflow-engine (where the agent relay lives), not from this surface.
 */
export function RunDiscoveryModal({ onClose }: { onClose: () => void }) {
  const intl = useIntl();
  const toast = useToast();
  const [mode, setMode] = useState<Mode>("agent");

  const agentsQ = useAgents();
  const connectorsQ = useConnectors();
  const targetsQ = usePamTargets();

  const agents = agentsQ.data ?? [];
  // Only configured (connected) connector instances carry an instance id we
  // can scan; AWS + Azure are the providers with a real inventory API.
  const connectors = (connectorsQ.data ?? []).filter(
    (c) => c.connected && c.connector_id,
  );
  const dbTargets = (targetsQ.data ?? []).filter((t) =>
    DB_PROTOCOLS.has(t.protocol.toLowerCase()),
  );

  const [agentId, setAgentId] = useState("");
  const [connectorId, setConnectorId] = useState("");
  const [targetId, setTargetId] = useState("");

  const importAgent = useImportAgentReachable();
  const scanConnector = useScanConnectorInventory();
  const scanDB = useScanDBAccounts();

  const pending =
    importAgent.isPending || scanConnector.isPending || scanDB.isPending;

  const run = async () => {
    try {
      if (mode === "agent") {
        if (!agentId) return;
        const r = await importAgent.mutateAsync(agentId);
        toast.success(
          intl.formatMessage(
            {
              id: "discovery.run.agent.success",
              defaultMessage:
                "Imported {found} reachable {found, plural, one {target} other {targets}} ({added} new)",
            },
            { found: r.assets_found, added: r.assets_new },
          ),
        );
      } else if (mode === "connector") {
        if (!connectorId) return;
        const r = await scanConnector.mutateAsync(connectorId);
        toast.success(
          intl.formatMessage(
            {
              id: "discovery.run.connector.success",
              defaultMessage:
                "Connector inventory found {found} {found, plural, one {asset} other {assets}} ({added} new)",
            },
            { found: r.assets_found, added: r.assets_new },
          ),
        );
      } else {
        if (!targetId) return;
        const r = await scanDB.mutateAsync(targetId);
        toast.success(
          intl.formatMessage(
            {
              id: "discovery.run.db.success",
              defaultMessage:
                "Enumerated {found} database {found, plural, one {account} other {accounts}}",
            },
            { found: r.accounts_found },
          ),
        );
      }
      onClose();
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? err.status === 422
            ? intl.formatMessage({
                id: "discovery.run.unsupported",
                defaultMessage:
                  "This connector has no asset inventory API, so there is nothing to enumerate.",
              })
            : err.message
          : undefined;
      toast.error(
        intl.formatMessage({
          id: "discovery.run.error",
          defaultMessage: "Discovery run failed",
        }),
        msg,
      );
    }
  };

  const canRun =
    (mode === "agent" && !!agentId) ||
    (mode === "connector" && !!connectorId) ||
    (mode === "db" && !!targetId);

  return (
    <Modal
      title={intl.formatMessage({
        id: "discovery.run.title",
        defaultMessage: "Run discovery",
      })}
      onClose={onClose}
      footer={
        <>
          <button className="btn btn--ghost" onClick={onClose}>
            <FormattedMessage id="common.cancel" defaultMessage="Cancel" />
          </button>
          <button
            className="btn btn--primary"
            disabled={!canRun || pending}
            onClick={run}
          >
            <FormattedMessage
              id="discovery.run.confirm"
              defaultMessage="Run discovery"
            />
          </button>
        </>
      }
    >
      <div
        className="pill-tabs"
        role="tablist"
        aria-label={intl.formatMessage({
          id: "discovery.run.source",
          defaultMessage: "Discovery source",
        })}
        style={{ marginBottom: 16 }}
      >
        <button
          role="tab"
          aria-selected={mode === "agent"}
          className={mode === "agent" ? "active" : ""}
          onClick={() => setMode("agent")}
        >
          <FormattedMessage
            id="discovery.run.tab.agent"
            defaultMessage="Agent network"
          />
        </button>
        <button
          role="tab"
          aria-selected={mode === "connector"}
          className={mode === "connector" ? "active" : ""}
          onClick={() => setMode("connector")}
        >
          <FormattedMessage
            id="discovery.run.tab.connector"
            defaultMessage="Cloud connector"
          />
        </button>
        <button
          role="tab"
          aria-selected={mode === "db"}
          className={mode === "db" ? "active" : ""}
          onClick={() => setMode("db")}
        >
          <FormattedMessage
            id="discovery.run.tab.db"
            defaultMessage="Database accounts"
          />
        </button>
      </div>

      {mode === "agent" && (
        <>
          <p className="muted" style={{ marginTop: 0 }}>
            <FormattedMessage
              id="discovery.run.agent.desc"
              defaultMessage="Import the reachable hosts a connector agent advertises from inside the customer network. Active port sweeps run on a schedule in the workflow engine."
            />
          </p>
          <label className="field">
            <span>
              <FormattedMessage
                id="discovery.run.agent.label"
                defaultMessage="Connector agent"
              />
            </span>
            <select
              value={agentId}
              onChange={(e) => setAgentId(e.target.value)}
            >
              <option value="">
                {intl.formatMessage({
                  id: "discovery.run.select",
                  defaultMessage: "Select…",
                })}
              </option>
              {agents.map((a) => (
                <option key={a.agent.id} value={a.agent.id}>
                  {a.agent.name}
                </option>
              ))}
            </select>
          </label>
          {agents.length === 0 && (
            <p className="muted" style={{ fontSize: 12 }}>
              <FormattedMessage
                id="discovery.run.agent.none"
                defaultMessage="No connector agents enrolled yet. Enrol an agent under Privileged access → Connector agents."
              />
            </p>
          )}
        </>
      )}

      {mode === "connector" && (
        <>
          <p className="muted" style={{ marginTop: 0 }}>
            <FormattedMessage
              id="discovery.run.connector.desc"
              defaultMessage="Enumerate cloud assets using a connector's own credentials. AWS (EC2 + RDS) and Azure (VMs + SQL) expose a real inventory API."
            />{" "}
            <HelpTooltip>
              <FormattedMessage
                id="discovery.run.connector.help"
                defaultMessage="Only connectors with a genuine inventory API can enumerate assets. Connectors without one are intentionally not listed rather than faked."
              />
            </HelpTooltip>
          </p>
          <label className="field">
            <span>
              <FormattedMessage
                id="discovery.run.connector.label"
                defaultMessage="Connector"
              />
            </span>
            <select
              value={connectorId}
              onChange={(e) => setConnectorId(e.target.value)}
            >
              <option value="">
                {intl.formatMessage({
                  id: "discovery.run.select",
                  defaultMessage: "Select…",
                })}
              </option>
              {connectors.map((c) => (
                <option key={c.connector_id} value={c.connector_id}>
                  {c.display_name}
                </option>
              ))}
            </select>
          </label>
          {connectors.length === 0 && (
            <p className="muted" style={{ fontSize: 12 }}>
              <FormattedMessage
                id="discovery.run.connector.none"
                defaultMessage="No connected connectors. Connect AWS or Azure under Connectors to enumerate their inventory."
              />
            </p>
          )}
        </>
      )}

      {mode === "db" && (
        <>
          <p className="muted" style={{ marginTop: 0 }}>
            <FormattedMessage
              id="discovery.run.db.desc"
              defaultMessage="Enumerate database-internal roles/users on a registered Postgres or MySQL target and reconcile them against the credentials ShieldNet manages."
            />
          </p>
          <label className="field">
            <span>
              <FormattedMessage
                id="discovery.run.db.label"
                defaultMessage="Database target"
              />
            </span>
            <select
              value={targetId}
              onChange={(e) => setTargetId(e.target.value)}
            >
              <option value="">
                {intl.formatMessage({
                  id: "discovery.run.select",
                  defaultMessage: "Select…",
                })}
              </option>
              {dbTargets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} ({t.protocol})
                </option>
              ))}
            </select>
          </label>
          {dbTargets.length === 0 && (
            <p className="muted" style={{ fontSize: 12 }}>
              <FormattedMessage
                id="discovery.run.db.none"
                defaultMessage="No Postgres or MySQL targets registered yet. Register one under Privileged access → PAM targets."
              />
            </p>
          )}
          <div style={{ marginTop: 8 }}>
            <Badge tone="info">postgres</Badge> <Badge tone="info">mysql</Badge>
          </div>
        </>
      )}
    </Modal>
  );
}
