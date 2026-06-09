import { useMemo, useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useIntl } from "react-intl";
import { PageHeader, Card, Badge, AsyncBoundary } from "@/components/ui";
import { useToast } from "@/components/Toast";
import {
  useConnectorCatalogueEntry,
  useRequestSetupPlan,
  useCreateConnector,
  type ConnectorSetupPlan,
} from "@/api/access";
import { titleCase } from "@/lib/format";

interface KV {
  key: string;
  value: string;
}

// Collapse the editable key/value rows into a plain object for the API,
// dropping rows with a blank key so an empty trailing row never posts a "":""
// pair. Values are sent as-is (strings); the backend coerces/validates per
// connector.
function kvToObject(rows: KV[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const r of rows) {
    const k = r.key.trim();
    if (k) out[k] = r.value;
  }
  return out;
}

export function ConnectorSetup() {
  const intl = useIntl();
  const navigate = useNavigate();
  const toast = useToast();
  const params = useParams({ strict: false }) as { provider?: string };
  const provider = params.provider ?? "";

  const { data: entry, isLoading, error, refetch } =
    useConnectorCatalogueEntry(provider);

  return (
    <>
      <PageHeader
        title={
          entry
            ? intl.formatMessage(
                {
                  id: "connectorSetup.title",
                  defaultMessage: "Set up {name}",
                },
                { name: entry.display_name },
              )
            : intl.formatMessage({
                id: "connectorSetup.titleGeneric",
                defaultMessage: "Set up connector",
              })
        }
        subtitle={intl.formatMessage({
          id: "connectorSetup.subtitle",
          defaultMessage:
            "Ask the setup assistant for a guided plan, then enter the connection details to create the connector. Nothing syncs until you create it.",
        })}
        actions={
          <button
            className="btn btn--ghost btn--sm"
            onClick={() => navigate({ to: "/connectors" })}
          >
            {intl.formatMessage({
              id: "connectorSetup.back",
              defaultMessage: "Back to connectors",
            })}
          </button>
        }
      />

      <AsyncBoundary
        isLoading={isLoading}
        error={error}
        data={entry}
        onRetry={refetch}
      >
        {(e) => (
          <div className="grid grid--2">
            <SetupAssistant provider={provider} category={e.category} />
            <ConfigureConnection
              provider={provider}
              defaultName={e.display_name}
              connected={e.connected}
              onCreated={() => {
                toast.success(
                  intl.formatMessage({
                    id: "connectorSetup.created",
                    defaultMessage: "Connector created",
                  }),
                );
                navigate({ to: "/connectors" });
              }}
            />
          </div>
        )}
      </AsyncBoundary>
    </>
  );
}

function SetupAssistant({
  provider,
  category,
}: {
  provider: string;
  category: string;
}) {
  const intl = useIntl();
  const [intent, setIntent] = useState("");
  const planMut = useRequestSetupPlan(provider);
  const plan = planMut.data?.plan;

  return (
    <Card
      title={intl.formatMessage({
        id: "connectorSetup.assistant.title",
        defaultMessage: "Setup assistant",
      })}
      subtitle={titleCase(category)}
    >
      <label className="field">
        <span className="field__label">
          {intl.formatMessage({
            id: "connectorSetup.assistant.intent",
            defaultMessage: "What are you trying to set up? (optional)",
          })}
        </span>
        <textarea
          rows={3}
          value={intent}
          placeholder={intl.formatMessage({
            id: "connectorSetup.assistant.intentPlaceholder",
            defaultMessage:
              "e.g. Sync engineering groups and enforce SSO for contractors",
          })}
          onChange={(e) => setIntent(e.target.value)}
        />
      </label>
      <button
        className="btn btn--primary btn--sm"
        disabled={planMut.isPending}
        onClick={() => planMut.mutate({ admin_intent: intent.trim() })}
      >
        {planMut.isPending
          ? intl.formatMessage({
              id: "connectorSetup.assistant.generating",
              defaultMessage: "Generating…",
            })
          : intl.formatMessage({
              id: "connectorSetup.assistant.generate",
              defaultMessage: "Generate setup plan",
            })}
      </button>

      {planMut.isError && (
        <p className="form-error" role="alert">
          {planMut.error.message}
        </p>
      )}

      {plan && <SetupPlanView plan={plan} />}
    </Card>
  );
}

function SetupPlanView({ plan }: { plan: ConnectorSetupPlan }) {
  const intl = useIntl();
  return (
    <div className="setup-plan">
      {plan.degraded ? (
        <div className="callout callout--info" role="status">
          {intl.formatMessage({
            id: "connectorSetup.plan.degraded",
            defaultMessage:
              "The setup assistant is unavailable right now, so this is the standard manual plan for this connector. You can still complete setup below.",
          })}
        </div>
      ) : (
        <div className="callout callout--ok" role="status">
          {intl.formatMessage({
            id: "connectorSetup.plan.aiGenerated",
            defaultMessage: "Generated by the setup assistant.",
          })}
        </div>
      )}

      {plan.explanation && <p className="muted">{plan.explanation}</p>}

      <ol className="setup-steps">
        {plan.steps.map((s) => (
          <li key={s.step} className="setup-step">
            <div className="setup-step__head">
              <span className="setup-step__num">{s.step}</span>
              <h4 className="setup-step__title">{s.title}</h4>
              {s.estimated_minutes ? (
                <span className="muted" style={{ fontSize: 12 }}>
                  ~{s.estimated_minutes}m
                </span>
              ) : null}
            </div>
            {s.description && <p>{s.description}</p>}
            {s.required_scopes && s.required_scopes.length > 0 && (
              <div className="setup-step__chips">
                {s.required_scopes.map((sc) => (
                  <Badge key={sc} tone="info">
                    {sc}
                  </Badge>
                ))}
              </div>
            )}
            {s.field_mappings && s.field_mappings.length > 0 && (
              <table className="table table--compact">
                <thead>
                  <tr>
                    <th>
                      {intl.formatMessage({
                        id: "connectorSetup.plan.source",
                        defaultMessage: "Source attribute",
                      })}
                    </th>
                    <th>
                      {intl.formatMessage({
                        id: "connectorSetup.plan.target",
                        defaultMessage: "Maps to",
                      })}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {s.field_mappings.map((m, i) => (
                    <tr key={`${m.source}-${i}`}>
                      <td>
                        <code>{m.source}</code>
                      </td>
                      <td>
                        <code>{m.target}</code>
                        {m.invert && (
                          <Badge tone="warn">
                            {intl.formatMessage({
                              id: "connectorSetup.plan.inverted",
                              defaultMessage: "inverted",
                            })}
                          </Badge>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {s.common_pitfalls && s.common_pitfalls.length > 0 && (
              <ul className="setup-step__pitfalls">
                {s.common_pitfalls.map((p, i) => (
                  <li key={i} className="muted">
                    {p}
                  </li>
                ))}
              </ul>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}

function ConfigureConnection({
  provider,
  defaultName,
  connected,
  onCreated,
}: {
  provider: string;
  defaultName: string;
  connected: boolean;
  onCreated: () => void;
}) {
  const intl = useIntl();
  const [displayName, setDisplayName] = useState(defaultName);
  const [config, setConfig] = useState<KV[]>([{ key: "", value: "" }]);
  const [secrets, setSecrets] = useState<KV[]>([{ key: "", value: "" }]);
  const createMut = useCreateConnector();

  // Client-side validation mirrors the backend contract (provider required;
  // every populated secret/config row needs a key). Surfacing it inline avoids
  // a round-trip for the obvious mistakes while the server stays authoritative.
  const validationError = useMemo(() => {
    if (!provider) return "Missing connector provider.";
    const danglingValue = (rows: KV[]) =>
      rows.some((r) => !r.key.trim() && r.value.trim());
    if (danglingValue(config))
      return "Every configuration value needs a field name.";
    if (danglingValue(secrets))
      return "Every secret value needs a field name.";
    return null;
  }, [provider, config, secrets]);

  const submit = () => {
    if (validationError) return;
    createMut.mutate(
      {
        provider,
        display_name: displayName.trim() || defaultName,
        config: kvToObject(config),
        secrets: kvToObject(secrets),
      },
      { onSuccess: onCreated },
    );
  };

  return (
    <Card
      title={intl.formatMessage({
        id: "connectorSetup.configure.title",
        defaultMessage: "Configure connection",
      })}
      subtitle={
        connected
          ? intl.formatMessage({
              id: "connectorSetup.configure.alreadyConnected",
              defaultMessage:
                "This provider is already connected. Creating another adds a second connection (e.g. a separate tenant or account).",
            })
          : undefined
      }
    >
      <label className="field">
        <span className="field__label">
          {intl.formatMessage({
            id: "connectorSetup.configure.displayName",
            defaultMessage: "Display name",
          })}
        </span>
        <input
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
        />
      </label>

      <KVEditor
        legend={intl.formatMessage({
          id: "connectorSetup.configure.config",
          defaultMessage: "Configuration",
        })}
        rows={config}
        onChange={setConfig}
        keyPlaceholder="tenant_id"
        valuePlaceholder="value"
      />

      <KVEditor
        legend={intl.formatMessage({
          id: "connectorSetup.configure.secrets",
          defaultMessage: "Secrets",
        })}
        hint={intl.formatMessage({
          id: "connectorSetup.configure.secretsHint",
          defaultMessage:
            "Sealed with this workspace's key on the server and never returned.",
        })}
        rows={secrets}
        onChange={setSecrets}
        keyPlaceholder="client_secret"
        valuePlaceholder="value"
        secret
      />

      {(validationError || createMut.isError) && (
        <p className="form-error" role="alert">
          {validationError ?? createMut.error?.message}
        </p>
      )}

      <button
        className="btn btn--primary"
        disabled={!!validationError || createMut.isPending}
        onClick={submit}
      >
        {createMut.isPending
          ? intl.formatMessage({
              id: "connectorSetup.configure.creating",
              defaultMessage: "Creating…",
            })
          : intl.formatMessage({
              id: "connectorSetup.configure.create",
              defaultMessage: "Create connector",
            })}
      </button>
    </Card>
  );
}

function KVEditor({
  legend,
  hint,
  rows,
  onChange,
  keyPlaceholder,
  valuePlaceholder,
  secret = false,
}: {
  legend: string;
  hint?: string;
  rows: KV[];
  onChange: (rows: KV[]) => void;
  keyPlaceholder: string;
  valuePlaceholder: string;
  secret?: boolean;
}) {
  const update = (i: number, patch: Partial<KV>) =>
    onChange(rows.map((r, idx) => (idx === i ? { ...r, ...patch } : r)));
  const remove = (i: number) => onChange(rows.filter((_, idx) => idx !== i));
  const add = () => onChange([...rows, { key: "", value: "" }]);

  return (
    <fieldset className="kv-editor">
      <legend className="field__label">{legend}</legend>
      {hint && (
        <p className="muted" style={{ fontSize: 12, margin: "0 0 8px" }}>
          {hint}
        </p>
      )}
      {rows.map((r, i) => (
        <div key={i} className="kv-editor__row">
          <input
            value={r.key}
            placeholder={keyPlaceholder}
            onChange={(e) => update(i, { key: e.target.value })}
          />
          <input
            value={r.value}
            type={secret ? "password" : "text"}
            placeholder={valuePlaceholder}
            onChange={(e) => update(i, { value: e.target.value })}
          />
          <button
            type="button"
            className="btn btn--ghost btn--sm"
            aria-label="Remove field"
            onClick={() => remove(i)}
            disabled={rows.length === 1}
          >
            ✕
          </button>
        </div>
      ))}
      <button type="button" className="btn btn--ghost btn--sm" onClick={add}>
        + Add field
      </button>
    </fieldset>
  );
}
