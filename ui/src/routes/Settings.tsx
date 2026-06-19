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

const THEME_OPTIONS: {
  value: ThemeChoice;
  icon: "dashboard" | "browser" | "settings";
  labelId: string;
  label: string;
  hintId: string;
  hint: string;
}[] = [
  {
    value: "light",
    icon: "dashboard",
    labelId: "settings.theme.light",
    label: "Light",
    hintId: "settings.theme.light.hint",
    hint: "Always use the light theme.",
  },
  {
    value: "dark",
    icon: "browser",
    labelId: "settings.theme.dark",
    label: "Dark",
    hintId: "settings.theme.dark.hint",
    hint: "Always use the dark theme.",
  },
  {
    value: "system",
    icon: "settings",
    labelId: "settings.theme.system",
    label: "System",
    hintId: "settings.theme.system.hint",
    hint: "Match whatever your device is set to.",
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
        subtitle={intl.formatMessage({
          id: "settings.subtitle",
          defaultMessage:
            "Adjust how the console looks and behaves on this device, and review the account you're signed in as.",
        })}
      />
      <div className="grid grid--2">
        <Card
          title={intl.formatMessage({
            id: "settings.appearance.title",
            defaultMessage: "Appearance",
          })}
          subtitle={intl.formatMessage({
            id: "settings.appearance.subtitle",
            defaultMessage:
              "Choose how the console looks. We'll remember your choice on this device.",
          })}
        >
          <div
            className="theme-toggle"
            role="radiogroup"
            aria-label={intl.formatMessage({
              id: "settings.appearance.title",
              defaultMessage: "Appearance",
            })}
          >
            {THEME_OPTIONS.map((opt) => {
              const active = choice === opt.value;
              const label = intl.formatMessage({
                id: opt.labelId,
                defaultMessage: opt.label,
              });
              return (
                <button
                  key={opt.value}
                  type="button"
                  role="radio"
                  aria-checked={active}
                  aria-label={label}
                  className={`theme-toggle__option${active ? " active" : ""}`}
                  onClick={() => select(opt.value)}
                >
                  <Icon name={opt.icon} size={18} />
                  <b>{label}</b>
                  <span className="muted">
                    {intl.formatMessage({
                      id: opt.hintId,
                      defaultMessage: opt.hint,
                    })}
                  </span>
                </button>
              );
            })}
          </div>
          <p
            className="muted"
            style={{ marginTop: 14, fontSize: 12 }}
            aria-live="polite"
          >
            {choice === "system"
              ? intl.formatMessage(
                  {
                    id: "settings.theme.followingSystem",
                    defaultMessage:
                      "Matching your device — currently <b>{resolved}</b>.",
                  },
                  {
                    resolved:
                      resolved === "dark"
                        ? intl.formatMessage({
                            id: "settings.theme.darkWord",
                            defaultMessage: "dark",
                          })
                        : intl.formatMessage({
                            id: "settings.theme.lightWord",
                            defaultMessage: "light",
                          }),
                    b: (chunks) => <b>{chunks}</b>,
                  },
                )
              : intl.formatMessage(
                  {
                    id: "settings.theme.locked",
                    defaultMessage: "Set to <b>{choice}</b> on this device.",
                  },
                  {
                    choice:
                      choice === "dark"
                        ? intl.formatMessage({
                            id: "settings.theme.darkWord",
                            defaultMessage: "dark",
                          })
                        : intl.formatMessage({
                            id: "settings.theme.lightWord",
                            defaultMessage: "light",
                          }),
                    b: (chunks) => <b>{chunks}</b>,
                  },
                )}
          </p>
        </Card>

        <Card
          title={intl.formatMessage({
            id: "settings.language.title",
            defaultMessage: "Language",
          })}
          subtitle={intl.formatMessage({
            id: "settings.language.subtitle",
            defaultMessage:
              "Pick your language. The console and the answers it gets back are shown in your choice.",
          })}
        >
          <LanguageSwitcher />
          <p className="muted" style={{ marginTop: 14, fontSize: 12 }}>
            {intl.formatMessage({
              id: "settings.language.note",
              defaultMessage:
                "Your choice is applied across the console straight away, and the control plane tailors its responses to match.",
            })}
          </p>
        </Card>

        <Card
          title={intl.formatMessage({
            id: "settings.session.title",
            defaultMessage: "Your session",
          })}
          subtitle={intl.formatMessage({
            id: "settings.session.subtitle",
            defaultMessage:
              "The account and workspace this browser session is signed in to.",
          })}
        >
          {me.isLoading ? (
            <p className="muted">
              {intl.formatMessage({
                id: "settings.session.loading",
                defaultMessage: "Loading your session…",
              })}
            </p>
          ) : me.data ? (
            <dl className="kv">
              <div>
                <dt>
                  {intl.formatMessage({
                    id: "settings.session.user",
                    defaultMessage: "Signed in as",
                  })}
                </dt>
                <dd>
                  <code>{me.data.user_id}</code>
                </dd>
              </div>
              <div>
                <dt>
                  {intl.formatMessage({
                    id: "settings.session.tenant",
                    defaultMessage: "Workspace",
                  })}
                </dt>
                <dd>
                  <code>{me.data.tenant_id}</code>
                </dd>
              </div>
              <div>
                <dt>
                  {intl.formatMessage({
                    id: "settings.session.roles",
                    defaultMessage: "Roles",
                  })}
                </dt>
                <dd>
                  {me.data.roles.length ? (
                    me.data.roles.map((r) => (
                      <Badge key={r} tone="info">
                        {r}
                      </Badge>
                    ))
                  ) : (
                    <span className="muted">
                      {intl.formatMessage({
                        id: "settings.session.noRoles",
                        defaultMessage: "None assigned",
                      })}
                    </span>
                  )}
                </dd>
              </div>
              <div>
                <dt>
                  {intl.formatMessage({
                    id: "settings.session.mfa",
                    defaultMessage: "Extra verification (MFA)",
                  })}
                </dt>
                <dd>
                  <Badge tone={me.data.mfa_satisfied ? "ok" : "warn"}>
                    {me.data.mfa_satisfied
                      ? intl.formatMessage({
                          id: "settings.session.mfa.ok",
                          defaultMessage: "Verified",
                        })
                      : intl.formatMessage({
                          id: "settings.session.mfa.warn",
                          defaultMessage: "Not yet verified",
                        })}
                  </Badge>
                </dd>
              </div>
            </dl>
          ) : (
            <p className="muted">
              {intl.formatMessage({
                id: "settings.session.unavailable",
                defaultMessage:
                  "We couldn't load your session details right now. Refresh the page to try again.",
              })}
            </p>
          )}
        </Card>

        <SecurityCard />
      </div>
    </>
  );
}
