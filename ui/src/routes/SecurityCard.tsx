import { useState } from "react";
import { useIntl } from "react-intl";
import { Card, Badge, Spinner } from "@/components/ui";
import { HelpTooltip } from "@/components/HelpTooltip";
import {
  useMFAMethods,
  useBeginTOTPEnrollment,
  useFinishTOTPEnrollment,
  useDisableTOTP,
  useRegisterWebAuthn,
  useDeleteWebAuthnCredential,
  webAuthnSupported,
  type ApiError,
  type TOTPEnrollment,
  type WebAuthnCredentialView,
} from "@/api/access";

const errText = (err: ApiError | null): string | null =>
  err ? err.message : null;

/**
 * SecurityCard is the self-service step-up MFA surface: enrol/disable a TOTP
 * authenticator and register/remove WebAuthn (FIDO2) security keys. These are
 * the factors the high-risk actions (policy promote, PAM connect/takeover,
 * compliance export) demand via the X-MFA-Assertion header. The control plane
 * never returns key material, so this view only renders sanitized state.
 */
export function SecurityCard() {
  const intl = useIntl();
  const methods = useMFAMethods();

  return (
    <Card
      title={intl.formatMessage({
        id: "security.title",
        defaultMessage: "Extra verification for sensitive actions",
      })}
      subtitle={intl.formatMessage({
        id: "security.subtitle",
        defaultMessage:
          "Set up a second way to confirm it's you. We'll ask for it before high-risk actions like going live with a policy, connecting to a privileged system, or exporting compliance evidence.",
      })}
    >
      {methods.isLoading ? (
        <div
          className="state"
          role="status"
          aria-live="polite"
          style={{ padding: 24 }}
        >
          <Spinner />
          <p style={{ marginTop: 12 }}>
            {intl.formatMessage({
              id: "security.loading",
              defaultMessage: "Checking your verification methods…",
            })}
          </p>
        </div>
      ) : methods.isError ? (
        <p className="form-error" role="alert">
          {intl.formatMessage(
            {
              id: "security.loadError",
              defaultMessage:
                "We couldn't load your verification methods. Refresh to try again. ({detail})",
            },
            { detail: errText(methods.error) ?? "unknown error" },
          )}
        </p>
      ) : methods.data ? (
        <div style={{ display: "grid", gap: 20 }}>
          <TOTPSection
            configured={methods.data.totp.configured}
            verified={methods.data.totp.verified}
          />
          <WebAuthnSection
            configured={methods.data.webauthn.configured}
            credentials={methods.data.webauthn.credentials}
          />
        </div>
      ) : (
        <p className="muted">
          {intl.formatMessage({
            id: "security.unavailable",
            defaultMessage: "Verification status isn't available right now.",
          })}
        </p>
      )}
    </Card>
  );
}

function TOTPSection({
  configured,
  verified,
}: {
  configured: boolean;
  verified: boolean;
}) {
  const intl = useIntl();
  const begin = useBeginTOTPEnrollment();
  const finish = useFinishTOTPEnrollment();
  const disable = useDisableTOTP();

  const [enrollment, setEnrollment] = useState<TOTPEnrollment | null>(null);
  const [code, setCode] = useState("");

  const startEnroll = () => {
    setCode("");
    begin.mutate(undefined, { onSuccess: (e) => setEnrollment(e) });
  };

  const confirm = () => {
    finish.mutate(code.trim(), {
      onSuccess: () => {
        setEnrollment(null);
        setCode("");
      },
    });
  };

  return (
    <section>
      <header
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
        }}
      >
        <div>
          <b>
            {intl.formatMessage({
              id: "security.totp.name",
              defaultMessage: "Authenticator app",
            })}
          </b>{" "}
          <HelpTooltip
            title={intl.formatMessage({
              id: "security.totp.helpTitle",
              defaultMessage: "What's an authenticator app?",
            })}
          >
            {intl.formatMessage({
              id: "security.totp.help",
              defaultMessage:
                "A free phone app (like Google Authenticator, Microsoft Authenticator, or 1Password) that shows a fresh 6-digit code every 30 seconds. You enter the current code to prove it's you.",
            })}
          </HelpTooltip>{" "}
          {!configured ? (
            <Badge tone="warn">
              {intl.formatMessage({
                id: "security.badge.unavailable",
                defaultMessage: "Unavailable",
              })}
            </Badge>
          ) : verified ? (
            <Badge tone="ok">
              {intl.formatMessage({
                id: "security.badge.on",
                defaultMessage: "On",
              })}
            </Badge>
          ) : (
            <Badge tone="info">
              {intl.formatMessage({
                id: "security.badge.notSetUp",
                defaultMessage: "Not set up",
              })}
            </Badge>
          )}
        </div>
        {configured && verified && !enrollment ? (
          <button
            type="button"
            className="btn btn--danger btn--sm"
            disabled={disable.isPending}
            onClick={() => disable.mutate()}
          >
            {disable.isPending
              ? intl.formatMessage({
                  id: "security.totp.disabling",
                  defaultMessage: "Turning off…",
                })
              : intl.formatMessage({
                  id: "security.totp.disable",
                  defaultMessage: "Turn off",
                })}
          </button>
        ) : configured && !enrollment ? (
          <button
            type="button"
            className="btn btn--primary btn--sm"
            disabled={begin.isPending}
            onClick={startEnroll}
          >
            {begin.isPending
              ? intl.formatMessage({
                  id: "security.totp.starting",
                  defaultMessage: "Starting…",
                })
              : verified
                ? intl.formatMessage({
                    id: "security.totp.reEnrol",
                    defaultMessage: "Set up again",
                  })
                : intl.formatMessage({
                    id: "security.totp.setUp",
                    defaultMessage: "Set up",
                  })}
          </button>
        ) : null}
      </header>

      {!configured ? (
        <p className="muted" style={{ fontSize: 12, marginTop: 6 }}>
          {intl.formatMessage({
            id: "security.totp.notConfigured",
            defaultMessage:
              "Your administrator hasn't enabled authenticator-app verification for this workspace yet.",
          })}
        </p>
      ) : !verified ? (
        <p className="muted" style={{ fontSize: 12, marginTop: 6 }}>
          {intl.formatMessage({
            id: "security.totp.notSetUpHint",
            defaultMessage:
              "Set this up once so you're ready when a sensitive action asks you to confirm it's you.",
          })}
        </p>
      ) : null}

      {enrollment ? (
        <div className="field" style={{ marginTop: 12 }}>
          <p className="muted" style={{ fontSize: 12 }}>
            {intl.formatMessage({
              id: "security.totp.enrollHelp",
              defaultMessage:
                "In your authenticator app, add a new account using the secret below, then enter the 6-digit code it shows to confirm. For your safety, this secret is shown only once.",
            })}
          </p>
          <label className="field">
            <span>
              {intl.formatMessage({
                id: "security.totp.secret",
                defaultMessage: "Setup secret",
              })}
            </span>
            <input
              readOnly
              value={enrollment.secret}
              aria-label={intl.formatMessage({
                id: "security.totp.secret",
                defaultMessage: "Setup secret",
              })}
            />
          </label>
          <label className="field">
            <span>
              {intl.formatMessage({
                id: "security.totp.uri",
                defaultMessage: "Setup link (for apps that accept it)",
              })}
            </span>
            <input readOnly value={enrollment.otpauth_url} />
          </label>
          <label className="field">
            <span>
              {intl.formatMessage({
                id: "security.totp.code",
                defaultMessage: "6-digit code from your app",
              })}
            </span>
            <input
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              placeholder="123456"
              value={code}
              onChange={(e) =>
                setCode(e.target.value.replace(/\D/g, "").slice(0, 6))
              }
            />
          </label>
          <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
            <button
              type="button"
              className="btn btn--primary btn--sm"
              disabled={finish.isPending || code.trim().length !== 6}
              onClick={confirm}
            >
              {finish.isPending
                ? intl.formatMessage({
                    id: "security.totp.confirming",
                    defaultMessage: "Confirming…",
                  })
                : intl.formatMessage({
                    id: "security.totp.confirm",
                    defaultMessage: "Confirm",
                  })}
            </button>
            <button
              type="button"
              className="btn btn--ghost btn--sm"
              onClick={() => {
                setEnrollment(null);
                setCode("");
              }}
            >
              {intl.formatMessage({
                id: "security.cancel",
                defaultMessage: "Cancel",
              })}
            </button>
          </div>
          {finish.isError ? (
            <p className="form-error" role="alert" style={{ fontSize: 12 }}>
              {intl.formatMessage(
                {
                  id: "security.totp.confirmError",
                  defaultMessage:
                    "That code didn't match — it changes every 30 seconds, so check your app and enter the current one. ({detail})",
                },
                { detail: errText(finish.error) ?? "unknown error" },
              )}
            </p>
          ) : null}
        </div>
      ) : null}

      {begin.isError ? (
        <p className="form-error" role="alert" style={{ fontSize: 12 }}>
          {intl.formatMessage(
            {
              id: "security.totp.beginError",
              defaultMessage:
                "We couldn't start setup just now. Please try again. ({detail})",
            },
            { detail: errText(begin.error) ?? "unknown error" },
          )}
        </p>
      ) : null}
      {disable.isError ? (
        <p className="form-error" role="alert" style={{ fontSize: 12 }}>
          {intl.formatMessage(
            {
              id: "security.totp.disableError",
              defaultMessage:
                "We couldn't turn this off just now. Please try again. ({detail})",
            },
            { detail: errText(disable.error) ?? "unknown error" },
          )}
        </p>
      ) : null}
    </section>
  );
}

function WebAuthnSection({
  configured,
  credentials,
}: {
  configured: boolean;
  credentials: WebAuthnCredentialView[];
}) {
  const intl = useIntl();
  const register = useRegisterWebAuthn();
  const remove = useDeleteWebAuthnCredential();
  const [name, setName] = useState("");

  const supported = webAuthnSupported();

  const add = () => {
    register.mutate(
      name.trim() ||
        intl.formatMessage({
          id: "security.webauthn.defaultName",
          defaultMessage: "Security key",
        }),
      {
        onSuccess: () => setName(""),
      },
    );
  };

  return (
    <section>
      <header style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <b>
          {intl.formatMessage({
            id: "security.webauthn.name",
            defaultMessage: "Security keys & passkeys",
          })}
        </b>
        <HelpTooltip
          title={intl.formatMessage({
            id: "security.webauthn.helpTitle",
            defaultMessage: "What's a security key or passkey?",
          })}
        >
          {intl.formatMessage({
            id: "security.webauthn.help",
            defaultMessage:
              "A physical key you tap (like a YubiKey), or a passkey built into your phone or laptop that unlocks with your fingerprint or face. It's the strongest, phishing-resistant way to prove it's you.",
          })}
        </HelpTooltip>
        {configured ? (
          <Badge tone={credentials.length ? "ok" : "info"}>
            {intl.formatMessage(
              {
                id: "security.webauthn.count",
                defaultMessage:
                  "{count, plural, =0 {None yet} one {# registered} other {# registered}}",
              },
              { count: credentials.length },
            )}
          </Badge>
        ) : (
          <Badge tone="warn">
            {intl.formatMessage({
              id: "security.badge.unavailable",
              defaultMessage: "Unavailable",
            })}
          </Badge>
        )}
      </header>

      {!configured ? (
        <p className="muted" style={{ fontSize: 12, marginTop: 6 }}>
          {intl.formatMessage({
            id: "security.webauthn.notConfigured",
            defaultMessage:
              "Your administrator hasn't enabled security keys for this workspace yet.",
          })}
        </p>
      ) : (
        <>
          {credentials.length ? (
            <ul
              className="kv"
              style={{ marginTop: 10, listStyle: "none", padding: 0 }}
            >
              {credentials.map((c) => (
                <li
                  key={c.id}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    gap: 12,
                    padding: "6px 0",
                  }}
                >
                  <span>
                    <b>{c.friendly_name}</b>
                    {c.clone_warning ? (
                      <Badge tone="warn">
                        {intl.formatMessage({
                          id: "security.webauthn.cloneWarning",
                          defaultMessage: "Check this key",
                        })}
                      </Badge>
                    ) : null}
                    <br />
                    <span className="muted" style={{ fontSize: 12 }}>
                      {intl.formatMessage(
                        {
                          id: "security.webauthn.added",
                          defaultMessage: "Added {date}",
                        },
                        { date: new Date(c.created_at).toLocaleDateString() },
                      )}
                      {c.last_used_at
                        ? intl.formatMessage(
                            {
                              id: "security.webauthn.lastUsed",
                              defaultMessage: " · last used {date}",
                            },
                            {
                              date: new Date(
                                c.last_used_at,
                              ).toLocaleDateString(),
                            },
                          )
                        : intl.formatMessage({
                            id: "security.webauthn.neverUsed",
                            defaultMessage: " · not used yet",
                          })}
                    </span>
                  </span>
                  <button
                    type="button"
                    className="btn btn--danger btn--sm"
                    disabled={remove.isPending}
                    onClick={() => remove.mutate(c.id)}
                    aria-label={intl.formatMessage(
                      {
                        id: "security.webauthn.removeNamed",
                        defaultMessage: "Remove {name}",
                      },
                      { name: c.friendly_name },
                    )}
                  >
                    {intl.formatMessage({
                      id: "security.webauthn.remove",
                      defaultMessage: "Remove",
                    })}
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted" style={{ fontSize: 12, marginTop: 6 }}>
              {intl.formatMessage({
                id: "security.webauthn.empty",
                defaultMessage:
                  "No security keys or passkeys yet. Add one below for the strongest protection.",
              })}
            </p>
          )}

          <div
            className="field-row"
            style={{ marginTop: 10, alignItems: "end" }}
          >
            <label className="field" style={{ flex: 1 }}>
              <span>
                {intl.formatMessage({
                  id: "security.webauthn.nameLabel",
                  defaultMessage: "Give your key a name",
                })}
              </span>
              <input
                placeholder={intl.formatMessage({
                  id: "security.webauthn.namePlaceholder",
                  defaultMessage: "e.g. My YubiKey",
                })}
                value={name}
                disabled={!supported}
                onChange={(e) => setName(e.target.value)}
              />
            </label>
            <button
              type="button"
              className="btn btn--primary btn--sm"
              disabled={!supported || register.isPending}
              onClick={add}
            >
              {register.isPending
                ? intl.formatMessage({
                    id: "security.webauthn.touch",
                    defaultMessage: "Follow your device's prompt…",
                  })
                : intl.formatMessage({
                    id: "security.webauthn.add",
                    defaultMessage: "Add a key or passkey",
                  })}
            </button>
          </div>
          {!supported ? (
            <p className="muted" style={{ fontSize: 12 }}>
              {intl.formatMessage({
                id: "security.webauthn.unsupported",
                defaultMessage:
                  "This browser can't add security keys. Try a current version of Chrome, Edge, Safari, or Firefox.",
              })}
            </p>
          ) : null}
          {register.isError ? (
            <p className="form-error" role="alert" style={{ fontSize: 12 }}>
              {intl.formatMessage(
                {
                  id: "security.webauthn.addError",
                  defaultMessage:
                    "We couldn't add that key. Make sure it's plugged in or nearby, then try again. ({detail})",
                },
                { detail: errText(register.error) ?? "unknown error" },
              )}
            </p>
          ) : null}
          {remove.isError ? (
            <p className="form-error" role="alert" style={{ fontSize: 12 }}>
              {intl.formatMessage(
                {
                  id: "security.webauthn.removeError",
                  defaultMessage:
                    "We couldn't remove that key just now. Please try again. ({detail})",
                },
                { detail: errText(remove.error) ?? "unknown error" },
              )}
            </p>
          ) : null}
        </>
      )}
    </section>
  );
}
