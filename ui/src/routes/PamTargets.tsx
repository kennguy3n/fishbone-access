import { useId, useState } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import { useNavigate } from "@tanstack/react-router";
import { PageHeader, Badge, AsyncBoundary } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState, EmptyIllustration } from "@/components/EmptyState";
import { Modal } from "@/components/Modal";
import { HelpTooltip } from "@/components/HelpTooltip";
import { useToast } from "@/components/Toast";
import {
  usePamTargets,
  useCreatePamTarget,
  type PamTarget,
  type CreatePamTargetInput,
  ApiError,
} from "@/api/access";
import { formatRelative } from "@/lib/format";
import { stashRequestTarget } from "./pamHandoff";
import "./pam-a11y.css";

// Protocols the gateway proxies. Kept in sync with internal/models PAM protocol
// constants so an operator only ever registers a target the gateway can serve.
const PROTOCOLS = [
  "ssh",
  "postgres",
  "mysql",
  "mssql",
  "mongodb",
  "redis",
  "k8s-exec",
  "rdp",
  "vnc",
  "http",
] as const;

// Friendly display names for the wire protocol identifiers, so a non-expert
// reads "PostgreSQL" rather than "postgres". The stored value stays the
// gateway's protocol id.
const PROTOCOL_LABELS: Record<string, string> = {
  ssh: "SSH",
  postgres: "PostgreSQL",
  mysql: "MySQL",
  mssql: "SQL Server",
  mongodb: "MongoDB",
  redis: "Redis",
  "k8s-exec": "Kubernetes exec",
  rdp: "Remote Desktop (RDP)",
  vnc: "VNC",
  http: "HTTP",
};
const protocolLabel = (p: string) => PROTOCOL_LABELS[p] ?? p;

// Render a per-target lease cap as a human duration ("1h", "30m") rather than
// raw seconds, falling back to a plain-language note when no cap is set.
function formatLeaseCap(seconds: number): string | null {
  if (!seconds || seconds <= 0) return null;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  const parts: string[] = [];
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}m`);
  if (s && !h) parts.push(`${s}s`);
  return parts.join(" ") || `${seconds}s`;
}

const emptyDraft: CreatePamTargetInput = {
  name: "",
  protocol: "ssh",
  address: "",
  username: "",
  require_mfa: false,
  lease_ttl_seconds: 3600,
  secret: {},
};

export function PamTargets() {
  const intl = useIntl();
  const navigate = useNavigate();
  const toast = useToast();
  const { data, isLoading, error, refetch } = usePamTargets();
  const createMut = useCreatePamTarget();
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<CreatePamTargetInput>(emptyDraft);
  // Errors are surfaced only after a submit attempt, so the form does not nag
  // while the operator is still filling it in.
  const [attempted, setAttempted] = useState(false);

  const nameErrId = useId();
  const addressErrId = useId();
  const secretHintId = useId();
  const secretErrId = useId();
  const ttlHintId = useId();

  const hasSecret =
    !!draft.secret.password?.trim() ||
    !!draft.secret.private_key?.trim() ||
    !!draft.secret.token?.trim();
  const nameMissing = !draft.name.trim();
  const addressMissing = !draft.address.trim();
  const valid = !nameMissing && !addressMissing && hasSecret;

  // When the "add a credential" error is showing, point the credential inputs at
  // it (alongside the hint) so assistive tech ties the error to the fields, not
  // only via its role="alert".
  const secretDescribedBy =
    attempted && !hasSecret ? `${secretHintId} ${secretErrId}` : secretHintId;

  const openModal = () => {
    setDraft(emptyDraft);
    setAttempted(false);
    setOpen(true);
  };

  const requestAccess = (t: PamTarget) => {
    // Hand the chosen target to the JIT-lease screen, where the request form
    // opens pre-filled. This keeps "found a system → ask for access" a single,
    // obvious path.
    stashRequestTarget(t.id);
    navigate({ to: "/pam/leases" });
  };

  const submit = async () => {
    setAttempted(true);
    if (!valid) return;
    try {
      await createMut.mutateAsync({
        ...draft,
        name: draft.name.trim(),
        address: draft.address.trim(),
        username: draft.username?.trim() || undefined,
      });
      toast.success(
        intl.formatMessage({
          id: "pam.targets.toastOk",
          defaultMessage: "Target registered",
        }),
        intl.formatMessage({
          id: "pam.targets.toastOkBody",
          defaultMessage: "You can now request just-in-time access to it.",
        }),
      );
      setOpen(false);
      setDraft(emptyDraft);
      setAttempted(false);
      refetch();
    } catch (err) {
      toast.error(
        intl.formatMessage({
          id: "pam.targets.toastErr",
          defaultMessage: "Could not register target",
        }),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  const columns: Column<PamTarget>[] = [
    {
      header: intl.formatMessage({
        id: "pam.targets.colTarget",
        defaultMessage: "Target",
      }),
      cell: (t) => (
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <b>{t.name}</b>
          <span className="muted" style={{ fontSize: 12 }}>
            <code>{t.address}</code>
            {t.username ? ` · ${t.username}` : ""}
          </span>
        </div>
      ),
    },
    {
      header: intl.formatMessage({
        id: "pam.targets.colProtocol",
        defaultMessage: "Protocol",
      }),
      cell: (t) => <Badge tone="info">{protocolLabel(t.protocol)}</Badge>,
    },
    {
      header: intl.formatMessage({
        id: "pam.targets.colMfa",
        defaultMessage: "Step-up MFA",
      }),
      cell: (t) => (
        <Badge tone={t.require_mfa ? "warn" : "neutral"}>
          {t.require_mfa ? (
            <FormattedMessage
              id="pam.targets.mfaRequired"
              defaultMessage="Required"
            />
          ) : (
            <FormattedMessage
              id="pam.targets.mfaNotRequired"
              defaultMessage="Not required"
            />
          )}
        </Badge>
      ),
    },
    {
      header: intl.formatMessage({
        id: "pam.targets.colLeaseCap",
        defaultMessage: "Max lease",
      }),
      cell: (t) => {
        const cap = formatLeaseCap(t.lease_ttl_seconds);
        return cap ? (
          cap
        ) : (
          <span className="muted">
            <FormattedMessage
              id="pam.targets.leaseCapDefault"
              defaultMessage="System default"
            />
          </span>
        );
      },
    },
    {
      header: intl.formatMessage({
        id: "pam.targets.colRotated",
        defaultMessage: "Secret rotated",
      }),
      cell: (t) => (
        <span className="muted">
          {t.secret_rotated_at ? (
            formatRelative(t.secret_rotated_at)
          ) : (
            <FormattedMessage
              id="pam.targets.neverRotated"
              defaultMessage="Never"
            />
          )}
        </span>
      ),
    },
    {
      header: intl.formatMessage({
        id: "pam.targets.colActions",
        defaultMessage: "Actions",
      }),
      width: 1,
      cell: (t) => (
        <button
          className="btn btn--sm"
          onClick={(e) => {
            e.stopPropagation();
            requestAccess(t);
          }}
        >
          <FormattedMessage
            id="pam.targets.requestAccess"
            defaultMessage="Request access"
          />
        </button>
      ),
    },
  ];

  return (
    <div className="pam-lane">
      <PageHeader
        title={intl.formatMessage({
          id: "pam.targets.title",
          defaultMessage: "Privileged targets",
        })}
        subtitle={intl.formatMessage({
          id: "pam.targets.subtitle",
          defaultMessage:
            "Privileged systems the gateway brokers access to. Credentials are sealed at rest and only decrypted into a live, lease-authorized session — they are never shown to operators.",
        })}
        actions={
          <button className="btn btn--primary" onClick={openModal}>
            <FormattedMessage
              id="pam.targets.register"
              defaultMessage="Register target"
            />
          </button>
        }
      />
      <AsyncBoundary
        isLoading={isLoading}
        error={error}
        data={data}
        onRetry={refetch}
        isEmpty={(rows) => rows.length === 0}
        empty={
          <EmptyState
            illustration={<EmptyIllustration kind="shield" />}
            title={intl.formatMessage({
              id: "pam.targets.emptyTitle",
              defaultMessage: "Register your first privileged target",
            })}
            description={intl.formatMessage({
              id: "pam.targets.emptyBody",
              defaultMessage:
                "Add an SSH host, database, Kubernetes cluster, or remote desktop. Once it's registered, your team can request time-boxed, fully recorded access to it — without ever handling the credentials.",
            })}
            action={
              <button className="btn btn--primary btn--sm" onClick={openModal}>
                <FormattedMessage
                  id="pam.targets.register"
                  defaultMessage="Register target"
                />
              </button>
            }
          />
        }
      >
        {(rows) => (
          <DataTable columns={columns} rows={rows} rowKey={(t) => t.id} />
        )}
      </AsyncBoundary>

      {open && (
        <Modal
          title={intl.formatMessage({
            id: "pam.targets.modalTitle",
            defaultMessage: "Register privileged target",
          })}
          onClose={() => setOpen(false)}
          footer={
            <>
              <button className="btn btn--ghost" onClick={() => setOpen(false)}>
                <FormattedMessage
                  id="pam.targets.cancel"
                  defaultMessage="Cancel"
                />
              </button>
              <button
                className="btn btn--primary"
                disabled={createMut.isPending}
                onClick={submit}
              >
                <FormattedMessage
                  id="pam.targets.register"
                  defaultMessage="Register target"
                />
              </button>
            </>
          }
        >
          <p className="callout callout--info" style={{ marginBottom: 4 }}>
            <FormattedMessage
              id="pam.targets.sealNote"
              defaultMessage="The credential you enter is sealed with envelope encryption and only decrypted inside a live, lease-authorized session. Operators never see it."
            />
          </p>

          <div className="field-row">
            <label className="field">
              <span>
                <FormattedMessage
                  id="pam.targets.fieldName"
                  defaultMessage="Name"
                />{" "}
                <span className="field__required" aria-hidden="true">
                  *
                </span>
              </span>
              <input
                value={draft.name}
                placeholder="prod-db-primary"
                aria-required="true"
                aria-invalid={attempted && nameMissing ? true : undefined}
                aria-describedby={attempted && nameMissing ? nameErrId : undefined}
                onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              />
              {attempted && nameMissing && (
                <span className="field__error" id={nameErrId} role="alert">
                  <FormattedMessage
                    id="pam.targets.errName"
                    defaultMessage="Give the target a name your team will recognize."
                  />
                </span>
              )}
            </label>
            <label className="field">
              <span>
                <FormattedMessage
                  id="pam.targets.fieldProtocol"
                  defaultMessage="Protocol"
                />
              </span>
              <select
                value={draft.protocol}
                onChange={(e) =>
                  setDraft({ ...draft, protocol: e.target.value })
                }
              >
                {PROTOCOLS.map((p) => (
                  <option key={p} value={p}>
                    {protocolLabel(p)}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <label className="field">
            <span>
              <FormattedMessage
                id="pam.targets.fieldAddress"
                defaultMessage="Address"
              />{" "}
              <span className="field__required" aria-hidden="true">
                *
              </span>
            </span>
            <input
              value={draft.address}
              placeholder="10.0.0.12:22"
              aria-required="true"
              aria-invalid={attempted && addressMissing ? true : undefined}
              aria-describedby={
                attempted && addressMissing ? addressErrId : undefined
              }
              onChange={(e) => setDraft({ ...draft, address: e.target.value })}
            />
            {attempted && addressMissing && (
              <span className="field__error" id={addressErrId} role="alert">
                <FormattedMessage
                  id="pam.targets.errAddress"
                  defaultMessage="Enter the host and port the gateway should reach, e.g. 10.0.0.12:22."
                />
              </span>
            )}
          </label>

          <div className="field-row">
            <label className="field">
              <span>
                <FormattedMessage
                  id="pam.targets.fieldUsername"
                  defaultMessage="Login username (optional)"
                />
              </span>
              <input
                value={draft.username}
                placeholder="root, postgres…"
                onChange={(e) =>
                  setDraft({ ...draft, username: e.target.value })
                }
              />
            </label>
            <label className="field">
              <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                <FormattedMessage
                  id="pam.targets.fieldLeaseCap"
                  defaultMessage="Max lease length (seconds)"
                />
                <HelpTooltip>
                  <FormattedMessage
                    id="pam.targets.leaseCapHelp"
                    defaultMessage="The longest a single lease against this target may last. Leave at 0 to use the system default. Shorter windows reduce standing risk."
                  />
                </HelpTooltip>
              </span>
              <input
                type="number"
                min={0}
                value={draft.lease_ttl_seconds}
                aria-describedby={ttlHintId}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    lease_ttl_seconds: Number(e.target.value) || 0,
                  })
                }
              />
              <span className="field__hint muted" id={ttlHintId}>
                <FormattedMessage
                  id="pam.targets.leaseCapHint"
                  defaultMessage="0 = use the system default."
                />
              </span>
            </label>
          </div>

          <div>
            <span className="field__label">
              <FormattedMessage
                id="pam.targets.credentialHeading"
                defaultMessage="Credential"
              />{" "}
              <span className="field__required" aria-hidden="true">
                *
              </span>
            </span>
            <p className="field__hint muted" id={secretHintId} style={{ marginTop: 0 }}>
              <FormattedMessage
                id="pam.targets.credentialHint"
                defaultMessage="Provide at least one: a password, an SSH private key, or a token."
              />
            </p>
            <label className="field">
              <span>
                <FormattedMessage
                  id="pam.targets.fieldPassword"
                  defaultMessage="Password"
                />
              </span>
              <input
                type="password"
                value={draft.secret.password ?? ""}
                aria-describedby={secretDescribedBy}
                aria-invalid={attempted && !hasSecret ? true : undefined}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    secret: { ...draft.secret, password: e.target.value },
                  })
                }
              />
            </label>
            <label className="field">
              <span>
                <FormattedMessage
                  id="pam.targets.fieldKey"
                  defaultMessage="SSH private key"
                />
              </span>
              <textarea
                rows={3}
                value={draft.secret.private_key ?? ""}
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                aria-describedby={secretDescribedBy}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    secret: { ...draft.secret, private_key: e.target.value },
                  })
                }
              />
            </label>
            <label className="field">
              <span>
                <FormattedMessage
                  id="pam.targets.fieldToken"
                  defaultMessage="Token"
                />
              </span>
              <input
                type="password"
                value={draft.secret.token ?? ""}
                aria-describedby={secretDescribedBy}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    secret: { ...draft.secret, token: e.target.value },
                  })
                }
              />
            </label>
            {attempted && !hasSecret && (
              <span className="field__error" id={secretErrId} role="alert">
                <FormattedMessage
                  id="pam.targets.errSecret"
                  defaultMessage="Add at least one credential so the gateway can authenticate to this target."
                />
              </span>
            )}
          </div>

          <label className="checkbox-inline field" style={{ marginTop: 12 }}>
            <input
              type="checkbox"
              checked={draft.require_mfa}
              style={{ width: "auto" }}
              onChange={(e) =>
                setDraft({ ...draft, require_mfa: e.target.checked })
              }
            />
            <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
              <FormattedMessage
                id="pam.targets.fieldMfa"
                defaultMessage="Require step-up MFA to open a session"
              />
              <HelpTooltip>
                <FormattedMessage
                  id="pam.targets.mfaHelp"
                  defaultMessage="When on, an operator must re-verify with multi-factor authentication right before connecting — even with an approved lease. Recommended for production and high-risk systems."
                />
              </HelpTooltip>
            </span>
          </label>
        </Modal>
      )}
    </div>
  );
}
