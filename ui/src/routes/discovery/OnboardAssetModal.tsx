import { useMemo, useState } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import { Modal } from "@/components/Modal";
import { Badge } from "@/components/ui";
import { HelpTooltip } from "@/components/HelpTooltip";
import { useToast } from "@/components/Toast";
import { ApiError, useAgents } from "@/api/access";
import {
  useOnboardAsset,
  type DiscoveredAsset,
  type OnboardAssetInput,
} from "@/api/discovery";

// Protocols that take an interactive credential we can seal. Mirrors the PAM
// target registration form; an onboarded asset becomes a real PAMTarget.
const SECRET_PROTOCOLS = new Set([
  "ssh",
  "postgres",
  "mysql",
  "mssql",
  "mongodb",
  "redis",
  "rdp",
  "vnc",
]);

/**
 * Guided one-click onboard: promotes a DiscoveredAsset into a managed PAM
 * target. Pre-fills protocol/address/agent from the discovered spec, takes a
 * sealed credential, and reminds the operator of the safety boundary — creating
 * the target never grants standing access; access still flows through the
 * normal request/lease path.
 */
export function OnboardAssetModal({
  asset,
  onClose,
  onDone,
}: {
  asset: DiscoveredAsset;
  onClose: () => void;
  onDone: () => void;
}) {
  const intl = useIntl();
  const toast = useToast();
  const agentsQ = useAgents();
  const onboardMut = useOnboardAsset(asset.id);

  const [draft, setDraft] = useState<OnboardAssetInput>({
    name: asset.name || asset.address,
    protocol: asset.protocol || "ssh",
    address: asset.address,
    username: "",
    password: "",
    private_key: "",
    token: "",
    agent_id: asset.agent_id ?? "",
    require_mfa: true,
    lease_ttl_seconds: 3600,
  });

  const needsSecret = SECRET_PROTOCOLS.has((draft.protocol ?? "").toLowerCase());
  const hasSecret =
    !!draft.password?.trim() ||
    !!draft.private_key?.trim() ||
    !!draft.token?.trim();
  const valid = useMemo(
    () =>
      !!draft.name?.trim() &&
      !!draft.address?.trim() &&
      (!needsSecret || hasSecret),
    [draft.name, draft.address, needsSecret, hasSecret],
  );

  const agents = agentsQ.data ?? [];

  const submit = async () => {
    if (!valid) return;
    try {
      const result = await onboardMut.mutateAsync({
        ...draft,
        name: draft.name?.trim(),
        address: draft.address?.trim(),
        username: draft.username?.trim() || undefined,
        agent_id: draft.agent_id || undefined,
      });
      if (result._bindWarning) {
        // Partial success: the target was created and is usable via direct
        // dial, but binding it to the selected agent failed. Tell the operator
        // exactly that so they know it's onboarded and how to finish the bind.
        toast.info(
          intl.formatMessage({
            id: "discovery.onboard.bindWarning.title",
            defaultMessage: "Onboarded, but agent binding failed",
          }),
          intl.formatMessage({
            id: "discovery.onboard.bindWarning.detail",
            defaultMessage:
              "The PAM target was created and will use direct dial. You can re-bind it to an agent from the target's settings.",
          }),
        );
      } else {
        toast.success(
          intl.formatMessage({
            id: "discovery.onboard.success",
            defaultMessage: "Asset onboarded as a managed PAM target",
          }),
        );
      }
      onDone();
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? err.status === 403
            ? intl.formatMessage({
                id: "discovery.onboard.stepup",
                defaultMessage:
                  "Step-up MFA is required to onboard this asset. Re-authenticate and try again.",
              })
            : err.message
          : undefined;
      toast.error(
        intl.formatMessage({
          id: "discovery.onboard.error",
          defaultMessage: "Could not onboard asset",
        }),
        msg,
      );
    }
  };

  return (
    <Modal
      title={intl.formatMessage({
        id: "discovery.onboard.title",
        defaultMessage: "Onboard discovered asset",
      })}
      onClose={onClose}
      footer={
        <>
          <button className="btn btn--ghost" onClick={onClose}>
            <FormattedMessage id="common.cancel" defaultMessage="Cancel" />
          </button>
          <button
            className="btn btn--primary"
            disabled={!valid || onboardMut.isPending}
            onClick={submit}
          >
            <FormattedMessage
              id="discovery.onboard.confirm"
              defaultMessage="Create managed target"
            />
          </button>
        </>
      }
    >
      <div
        className="callout callout--info"
        style={{ marginBottom: 16 }}
        role="note"
      >
        <FormattedMessage
          id="discovery.onboard.boundary"
          defaultMessage="Onboarding registers this system as a managed PAM target with a sealed credential. It does not grant anyone standing access — operators still request a just-in-time lease, which is approved, time-boxed and fully recorded on the audit chain."
        />
      </div>

      <div className="field-row">
        <label className="field">
          <span>
            <FormattedMessage
              id="discovery.onboard.name"
              defaultMessage="Target name"
            />
          </span>
          <input
            value={draft.name ?? ""}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            placeholder="prod-db-primary"
          />
        </label>
        <label className="field">
          <span>
            <FormattedMessage
              id="discovery.onboard.protocol"
              defaultMessage="Protocol"
            />
          </span>
          <input
            value={draft.protocol ?? ""}
            onChange={(e) => setDraft({ ...draft, protocol: e.target.value })}
            readOnly
            aria-readonly="true"
          />
        </label>
      </div>

      <label className="field">
        <span>
          <FormattedMessage
            id="discovery.onboard.address"
            defaultMessage="Address"
          />
        </span>
        <input
          value={draft.address ?? ""}
          onChange={(e) => setDraft({ ...draft, address: e.target.value })}
          placeholder="10.0.0.12:22"
        />
      </label>

      <div className="field-row">
        <label className="field">
          <span>
            <FormattedMessage
              id="discovery.onboard.username"
              defaultMessage="Login username (optional)"
            />
          </span>
          <input
            value={draft.username ?? ""}
            onChange={(e) => setDraft({ ...draft, username: e.target.value })}
            placeholder="root, postgres…"
          />
        </label>
        <label className="field">
          <span>
            <FormattedMessage
              id="discovery.onboard.agent"
              defaultMessage="Reach via agent"
            />{" "}
            <HelpTooltip>
              <FormattedMessage
                id="discovery.onboard.agent.help"
                defaultMessage="Bind the target to a connector agent so the gateway reaches it through the agent's outbound tunnel — no inbound exposure of the customer network."
              />
            </HelpTooltip>
          </span>
          <select
            value={draft.agent_id ?? ""}
            onChange={(e) => setDraft({ ...draft, agent_id: e.target.value })}
          >
            <option value="">
              {intl.formatMessage({
                id: "discovery.onboard.agent.none",
                defaultMessage: "Direct (no agent)",
              })}
            </option>
            {agents.map((a) => (
              <option key={a.agent.id} value={a.agent.id}>
                {a.agent.name}
              </option>
            ))}
          </select>
        </label>
      </div>

      {needsSecret && (
        <>
          <label className="field">
            <span>
              <FormattedMessage
                id="discovery.onboard.password"
                defaultMessage="Password (one secret required)"
              />
            </span>
            <input
              type="password"
              value={draft.password ?? ""}
              onChange={(e) => setDraft({ ...draft, password: e.target.value })}
            />
          </label>
          <label className="field">
            <span>
              <FormattedMessage
                id="discovery.onboard.privateKey"
                defaultMessage="Private key (alternative secret)"
              />
            </span>
            <textarea
              rows={3}
              value={draft.private_key ?? ""}
              placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
              onChange={(e) =>
                setDraft({ ...draft, private_key: e.target.value })
              }
            />
          </label>
        </>
      )}

      <div className="field-row">
        <label className="field">
          <span>
            <FormattedMessage
              id="discovery.onboard.leaseTtl"
              defaultMessage="Lease TTL (seconds)"
            />
          </span>
          <input
            type="number"
            min={0}
            value={draft.lease_ttl_seconds ?? 0}
            onChange={(e) =>
              setDraft({
                ...draft,
                lease_ttl_seconds: Number(e.target.value) || 0,
              })
            }
          />
        </label>
        <label
          className="field"
          style={{ flexDirection: "row", alignItems: "center", gap: 8 }}
        >
          <input
            type="checkbox"
            checked={!!draft.require_mfa}
            style={{ width: "auto" }}
            onChange={(e) =>
              setDraft({ ...draft, require_mfa: e.target.checked })
            }
          />
          <span>
            <FormattedMessage
              id="discovery.onboard.requireMfa"
              defaultMessage="Require step-up MFA to open a session"
            />
          </span>
        </label>
      </div>

      <div style={{ marginTop: 8 }}>
        <Badge tone="info">{asset.source}</Badge>{" "}
        <span className="muted" style={{ fontSize: 12 }}>
          <FormattedMessage
            id="discovery.onboard.discoveredVia"
            defaultMessage="Discovered via {source}"
            values={{ source: asset.source }}
          />
        </span>
      </div>
    </Modal>
  );
}
