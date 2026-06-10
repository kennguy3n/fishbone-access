import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { PageHeader, Badge, AsyncBoundary } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/Toast";
import {
  usePamTargets,
  useCreatePamTarget,
  type PamTarget,
  type CreatePamTargetInput,
  ApiError,
} from "@/api/access";
import { formatRelative } from "@/lib/format";

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
  const navigate = useNavigate();
  const toast = useToast();
  const { data, isLoading, error, refetch } = usePamTargets();
  const createMut = useCreatePamTarget();
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<CreatePamTargetInput>(emptyDraft);

  const hasSecret =
    !!draft.secret.password?.trim() ||
    !!draft.secret.private_key?.trim() ||
    !!draft.secret.token?.trim();
  const valid = draft.name.trim() && draft.address.trim() && hasSecret;

  const submit = async () => {
    if (!valid) return;
    try {
      await createMut.mutateAsync({
        ...draft,
        name: draft.name.trim(),
        address: draft.address.trim(),
        username: draft.username?.trim() || undefined,
      });
      toast.success("Target registered");
      setOpen(false);
      setDraft(emptyDraft);
    } catch (err) {
      toast.error(
        "Could not register target",
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  const columns: Column<PamTarget>[] = [
    {
      header: "Target",
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
      header: "Protocol",
      cell: (t) => <Badge tone="info">{t.protocol}</Badge>,
    },
    {
      header: "Step-up MFA",
      cell: (t) => (
        <Badge tone={t.require_mfa ? "warn" : "neutral"}>
          {t.require_mfa ? "Required" : "Not required"}
        </Badge>
      ),
    },
    {
      header: "Lease TTL",
      cell: (t) =>
        t.lease_ttl_seconds > 0 ? `${t.lease_ttl_seconds}s` : "—",
    },
    {
      header: "Secret rotated",
      cell: (t) => (
        <span className="muted">{formatRelative(t.secret_rotated_at)}</span>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="PAM targets"
        subtitle="Privileged systems the gateway proxies. Credentials are sealed at rest and only ever decrypted into a live, lease-authorized session."
        actions={
          <button className="btn btn--primary" onClick={() => setOpen(true)}>
            Register target
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
            title="No targets registered"
            description="Register an SSH, database, Kubernetes, or remote-desktop target to broker just-in-time access to it."
            action={
              <button
                className="btn btn--primary btn--sm"
                onClick={() => setOpen(true)}
              >
                Register target
              </button>
            }
          />
        }
      >
        {(rows) => (
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(t) => t.id}
            onRowClick={() => navigate({ to: "/pam/leases" })}
          />
        )}
      </AsyncBoundary>

      {open && (
        <Modal
          title="Register PAM target"
          onClose={() => setOpen(false)}
          footer={
            <>
              <button className="btn btn--ghost" onClick={() => setOpen(false)}>
                Cancel
              </button>
              <button
                className="btn btn--primary"
                disabled={!valid || createMut.isPending}
                onClick={submit}
              >
                Register target
              </button>
            </>
          }
        >
          <div className="field-row">
            <label className="field">
              <span>Name (required)</span>
              <input
                value={draft.name}
                placeholder="prod-db-primary"
                onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              />
            </label>
            <label className="field">
              <span>Protocol</span>
              <select
                value={draft.protocol}
                onChange={(e) =>
                  setDraft({ ...draft, protocol: e.target.value })
                }
              >
                {PROTOCOLS.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <label className="field">
            <span>Address (required)</span>
            <input
              value={draft.address}
              placeholder="10.0.0.12:22"
              onChange={(e) => setDraft({ ...draft, address: e.target.value })}
            />
          </label>
          <div className="field-row">
            <label className="field">
              <span>Login username (optional)</span>
              <input
                value={draft.username}
                placeholder="root, postgres…"
                onChange={(e) =>
                  setDraft({ ...draft, username: e.target.value })
                }
              />
            </label>
            <label className="field">
              <span>Lease TTL (seconds)</span>
              <input
                type="number"
                min={0}
                value={draft.lease_ttl_seconds}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    lease_ttl_seconds: Number(e.target.value) || 0,
                  })
                }
              />
            </label>
          </div>
          <label className="field">
            <span>Password (one secret required)</span>
            <input
              type="password"
              value={draft.secret.password ?? ""}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  secret: { ...draft.secret, password: e.target.value },
                })
              }
            />
          </label>
          <label className="field">
            <span>Private key (alternative secret)</span>
            <textarea
              rows={3}
              value={draft.secret.private_key ?? ""}
              placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
              onChange={(e) =>
                setDraft({
                  ...draft,
                  secret: { ...draft.secret, private_key: e.target.value },
                })
              }
            />
          </label>
          <label className="field">
            <span>Token (alternative secret)</span>
            <input
              type="password"
              value={draft.secret.token ?? ""}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  secret: { ...draft.secret, token: e.target.value },
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
              checked={draft.require_mfa}
              style={{ width: "auto" }}
              onChange={(e) =>
                setDraft({ ...draft, require_mfa: e.target.checked })
              }
            />
            <span>Require step-up MFA to open a session</span>
          </label>
        </Modal>
      )}
    </>
  );
}
