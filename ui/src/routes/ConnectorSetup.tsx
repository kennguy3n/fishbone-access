import { useMemo, useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useIntl } from "react-intl";
import {
  PageHeader,
  Card,
  Badge,
  AsyncBoundary,
  LoadingState,
} from "@/components/ui";
import { HelpTooltip } from "@/components/HelpTooltip";
import { useToast } from "@/components/Toast";
import {
  useConnectorCatalogueEntry,
  useConnectorSetupSchema,
  useRequestSetupPlan,
  useCreateConnector,
  type ConnectorSetupPlan,
  type ConnectorSetupSchema,
  type ConnectorSetupAuthMethod,
  type ConnectorSetupField,
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

// ConfigureConnection is the right-hand "connect" panel. When the provider has
// a curated setup schema it renders a guided, typed form (auth-method picker +
// labelled fields with "where do I find this?" help); otherwise — and when the
// operator opts into advanced mode — it falls back to the raw key/value editor.
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
  const { data: schema, isLoading } = useConnectorSetupSchema(provider);
  const [manual, setManual] = useState(false);

  if (isLoading) {
    return (
      <Card
        title={intl.formatMessage({
          id: "connectorSetup.configure.title",
          defaultMessage: "Configure connection",
        })}
      >
        <LoadingState />
      </Card>
    );
  }

  if (schema && !manual) {
    return (
      <GuidedConnectionForm
        provider={provider}
        schema={schema}
        defaultName={defaultName}
        connected={connected}
        onCreated={onCreated}
        onManual={() => setManual(true)}
      />
    );
  }

  return (
    <ManualConnectionForm
      provider={provider}
      defaultName={defaultName}
      connected={connected}
      onCreated={onCreated}
      onGuided={schema ? () => setManual(false) : undefined}
    />
  );
}

// GuidedConnectionForm renders a provider's curated setup schema: a one-line
// overview, an auth-method picker (when more than one method exists), the
// "how to get these credentials" checklist, and one typed, labelled input per
// field with inline help. It assembles the config/secrets payload by routing
// each field's value into the right bucket via the schema's `secret` flag, so a
// low-skill operator never has to know the underlying field keys.
function GuidedConnectionForm({
  provider,
  schema,
  defaultName,
  connected,
  onCreated,
  onManual,
}: {
  provider: string;
  schema: ConnectorSetupSchema;
  defaultName: string;
  connected: boolean;
  onCreated: () => void;
  onManual: () => void;
}) {
  const intl = useIntl();
  const [displayName, setDisplayName] = useState(defaultName);
  const [methodId, setMethodId] = useState<string>(() => {
    const recommended = schema.auth_methods.find((m) => m.recommended);
    return recommended?.id ?? schema.auth_methods[0]?.id ?? "";
  });
  // Values are keyed by field key and shared across methods, so a field common
  // to several methods (e.g. account_id) keeps its value when switching.
  const [values, setValues] = useState<Record<string, string>>({});
  const createMut = useCreateConnector();

  const method: ConnectorSetupAuthMethod | undefined = useMemo(
    () =>
      schema.auth_methods.find((m) => m.id === methodId) ??
      schema.auth_methods[0],
    [schema.auth_methods, methodId],
  );

  const missingRequired = useMemo(() => {
    if (!method) return [];
    return method.fields
      .filter((f) => f.required && !(values[f.key] ?? "").trim())
      .map((f) => f.label);
  }, [method, values]);

  const submit = () => {
    if (!method || missingRequired.length > 0) return;
    const config: Record<string, string> = {};
    const secrets: Record<string, string> = {};
    for (const f of method.fields) {
      const v = (values[f.key] ?? "").trim();
      if (!v) continue;
      if (f.secret) secrets[f.key] = v;
      else config[f.key] = v;
    }
    createMut.mutate(
      {
        provider,
        display_name: displayName.trim() || defaultName,
        config,
        secrets,
      },
      { onSuccess: onCreated },
    );
  };

  return (
    <Card
      title={intl.formatMessage(
        {
          id: "connectorSetup.guided.title",
          defaultMessage: "Connect {name}",
        },
        { name: schema.display_name },
      )}
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
      {schema.overview && <p className="muted">{schema.overview}</p>}

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

      {schema.auth_methods.length > 1 && (
        <fieldset className="auth-methods">
          <legend className="field__label">
            {intl.formatMessage({
              id: "connectorSetup.guided.authMethod",
              defaultMessage: "How do you want to authenticate?",
            })}
          </legend>
          {schema.auth_methods.map((m) => (
            <label key={m.id} className="auth-method">
              <input
                type="radio"
                name="auth-method"
                value={m.id}
                checked={method?.id === m.id}
                onChange={() => setMethodId(m.id)}
              />
              <span className="auth-method__body">
                <span className="auth-method__label">
                  {m.label}
                  {m.recommended && (
                    <Badge tone="ok">
                      {intl.formatMessage({
                        id: "connectorSetup.guided.recommended",
                        defaultMessage: "Recommended",
                      })}
                    </Badge>
                  )}
                </span>
                {m.description && (
                  <span className="muted auth-method__desc">
                    {m.description}
                  </span>
                )}
              </span>
            </label>
          ))}
        </fieldset>
      )}

      {method && (method.steps?.length || method.docs_url) ? (
        <div className="callout callout--info" role="note">
          {method.steps && method.steps.length > 0 && (
            <ol className="guided-steps">
              {method.steps.map((s, i) => (
                <li key={i}>{s}</li>
              ))}
            </ol>
          )}
          {method.docs_url && (
            <a
              className="guided-docs"
              href={method.docs_url}
              target="_blank"
              rel="noreferrer noopener"
            >
              {intl.formatMessage({
                id: "connectorSetup.guided.docs",
                defaultMessage: "Open provider documentation ↗",
              })}
            </a>
          )}
        </div>
      ) : null}

      {method?.fields.map((f) => (
        <GuidedFieldInput
          key={f.key}
          field={f}
          value={values[f.key] ?? ""}
          onChange={(v) => setValues((prev) => ({ ...prev, [f.key]: v }))}
        />
      ))}

      {(missingRequired.length > 0 || createMut.isError) && (
        <p className="form-error" role="alert">
          {createMut.isError
            ? createMut.error?.message
            : intl.formatMessage(
                {
                  id: "connectorSetup.guided.missing",
                  defaultMessage: "Fill in the required fields: {fields}.",
                },
                { fields: missingRequired.join(", ") },
              )}
        </p>
      )}

      <button
        className="btn btn--primary"
        disabled={missingRequired.length > 0 || createMut.isPending}
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

      <button type="button" className="link-button" onClick={onManual}>
        {intl.formatMessage({
          id: "connectorSetup.guided.manual",
          defaultMessage: "Enter fields manually (advanced)",
        })}
      </button>
    </Card>
  );
}

// GuidedFieldInput renders one schema field: a label (with a required marker),
// the "where do I find this?" help in a tooltip, and the input control the
// field's type maps to. Secret fields are masked; long credentials use a
// textarea.
function GuidedFieldInput({
  field,
  value,
  onChange,
}: {
  field: ConnectorSetupField;
  value: string;
  onChange: (v: string) => void;
}) {
  const intl = useIntl();
  const patternMismatch =
    !!field.pattern && value.trim() !== "" && !patternMatches(field.pattern, value.trim());

  return (
    <label className="field">
      <span className="field__label">
        {field.label}
        {field.required && <span className="field__required"> *</span>}
        {field.help && (
          <HelpTooltip>
            {field.help}
          </HelpTooltip>
        )}
      </span>
      {field.type === "textarea" ? (
        <textarea
          rows={5}
          value={value}
          placeholder={field.placeholder}
          onChange={(e) => onChange(e.target.value)}
        />
      ) : (
        <input
          type={
            field.type === "password"
              ? "password"
              : field.type === "email"
                ? "email"
                : field.type === "url"
                  ? "url"
                  : "text"
          }
          value={value}
          placeholder={field.placeholder}
          onChange={(e) => onChange(e.target.value)}
        />
      )}
      {patternMismatch && (
        <span className="field__hint muted">
          {intl.formatMessage({
            id: "connectorSetup.guided.patternMismatch",
            defaultMessage:
              "That doesn't look like the expected format — double-check it before creating.",
          })}
        </span>
      )}
    </label>
  );
}

// patternMatches compiles an advisory regex from the schema and tests the value
// against it. A malformed pattern never blocks the operator (the server is
// authoritative), so a bad regex is treated as "matches".
function patternMatches(pattern: string, value: string): boolean {
  try {
    return new RegExp(pattern).test(value);
  } catch {
    return true;
  }
}

function ManualConnectionForm({
  provider,
  defaultName,
  connected,
  onCreated,
  onGuided,
}: {
  provider: string;
  defaultName: string;
  connected: boolean;
  onCreated: () => void;
  onGuided?: () => void;
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
      {onGuided && (
        <button type="button" className="link-button" onClick={onGuided}>
          {intl.formatMessage({
            id: "connectorSetup.manual.guided",
            defaultMessage: "← Back to the guided form",
          })}
        </button>
      )}

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
