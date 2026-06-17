import { useState } from "react";
import { useIntl } from "react-intl";
import { PageHeader, Card, Badge } from "@/components/ui";
import { Icon } from "@/components/Icon";
import { LanguageSwitcher } from "@/components/LanguageSwitcher";
import { useMe } from "@/api/access";
import { SecurityCard } from "./SecurityCard";
import {
  getStoredChoice,
  resolveTheme,
  setTheme,
  type ThemeChoice,
} from "@/lib/theme";

const THEME_OPTIONS: { value: ThemeChoice; label: string; hint: string }[] = [
  { value: "light", label: "Light", hint: "Always use the light theme." },
  { value: "dark", label: "Dark", hint: "Always use the dark theme." },
  {
    value: "system",
    label: "System",
    hint: "Follow your operating system's appearance setting.",
  },
];

export function Settings() {
  const intl = useIntl();
  const [choice, setChoice] = useState<ThemeChoice>(() => getStoredChoice());
  const me = useMe();

  const select = (next: ThemeChoice) => {
    setChoice(next);
    setTheme(next);
  };

  const resolved = resolveTheme(choice);

  return (
    <>
      <PageHeader
        title={intl.formatMessage({
          id: "nav.settings",
          defaultMessage: "Settings",
        })}
        subtitle="Console preferences for this browser, and the identity this session is bound to."
      />
      <div className="grid grid--2">
        <Card
          title="Appearance"
          subtitle="Choose how the console looks. Your choice is saved in this browser."
        >
          <div className="theme-toggle" role="radiogroup" aria-label="Theme">
            {THEME_OPTIONS.map((opt) => {
              const active = choice === opt.value;
              return (
                <button
                  key={opt.value}
                  type="button"
                  role="radio"
                  aria-checked={active}
                  className={`theme-toggle__option${active ? " active" : ""}`}
                  onClick={() => select(opt.value)}
                >
                  <Icon
                    name={
                      opt.value === "dark"
                        ? "browser"
                        : opt.value === "light"
                          ? "dashboard"
                          : "settings"
                    }
                    size={18}
                  />
                  <b>{opt.label}</b>
                  <span className="muted">{opt.hint}</span>
                </button>
              );
            })}
          </div>
          <p className="muted" style={{ marginTop: 14, fontSize: 12 }}>
            {choice === "system" ? (
              <>
                Following your system preference — currently{" "}
                <b>{resolved === "dark" ? "dark" : "light"}</b>.
              </>
            ) : (
              <>
                Theme locked to <b>{choice}</b>.
              </>
            )}
          </p>
        </Card>

        <Card
          title="Language"
          subtitle="The console and the API responses are localized to your choice."
        >
          <LanguageSwitcher />
          <p className="muted" style={{ marginTop: 14, fontSize: 12 }}>
            Your selection is sent as the <code>Accept-Language</code> header on
            every API request, so the control plane localizes its responses to
            match.
          </p>
        </Card>

        <Card
          title="Session"
          subtitle="The identity and tenant this console session is bound to."
        >
          {me.isLoading ? (
            <p className="muted">Loading session…</p>
          ) : me.data ? (
            <dl className="kv">
              <div>
                <dt>User</dt>
                <dd>
                  <code>{me.data.user_id}</code>
                </dd>
              </div>
              <div>
                <dt>Tenant / workspace</dt>
                <dd>
                  <code>{me.data.tenant_id}</code>
                </dd>
              </div>
              <div>
                <dt>Roles</dt>
                <dd>
                  {me.data.roles.length ? (
                    me.data.roles.map((r) => (
                      <Badge key={r} tone="info">
                        {r}
                      </Badge>
                    ))
                  ) : (
                    <span className="muted">none</span>
                  )}
                </dd>
              </div>
              <div>
                <dt>MFA</dt>
                <dd>
                  <Badge tone={me.data.mfa_satisfied ? "ok" : "warn"}>
                    {me.data.mfa_satisfied ? "Satisfied" : "Not satisfied"}
                  </Badge>
                </dd>
              </div>
            </dl>
          ) : (
            <p className="muted">Session details unavailable.</p>
          )}
        </Card>

        <SecurityCard />
      </div>
    </>
  );
}
