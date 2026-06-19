import { useEffect, useId, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useIntl } from "react-intl";
import { useAuth } from "@/auth/auth-context";
import "./lane-a1.css";

export function Login() {
  const intl = useIntl();
  const { authMode, loginWithToken, loginWithOidc, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const errorId = useId();
  const helpId = useId();

  // Redirect away from the login screen once authenticated. Navigation is a
  // side effect, so it must run in an effect rather than during render.
  useEffect(() => {
    if (isAuthenticated) {
      navigate({ to: "/" });
    }
  }, [isAuthenticated, navigate]);

  const onJwtSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const trimmed = token.trim();
    if (!trimmed) {
      setError(
        intl.formatMessage({
          id: "login.error.empty",
          defaultMessage: "Paste your sign-in token to continue.",
        }),
      );
      return;
    }
    // On success the isAuthenticated effect handles the redirect; on failure
    // we surface feedback instead of bouncing to "/" and silently back.
    if (!loginWithToken(trimmed)) {
      setError(
        intl.formatMessage({
          id: "login.error.invalid",
          defaultMessage:
            "That token isn't valid anymore — it may have expired. Paste a current sign-in token and try again.",
        }),
      );
    }
  };

  const onOidc = async () => {
    setError(null);
    try {
      await loginWithOidc();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : intl.formatMessage({
              id: "login.error.oidc",
              defaultMessage:
                "We couldn't start single sign-on. Please try again, or contact your administrator if it keeps happening.",
            }),
      );
    }
  };

  return (
    <div className="login lane-a1">
      <div className="login__card">
        <div className="login__brand">
          <span
            className="sidebar__logo"
            style={{ width: 36, height: 36 }}
            aria-hidden
          >
            S
          </span>
          <div>
            <div style={{ fontWeight: 700, fontSize: 18 }}>ShieldNet Access</div>
            <div className="muted" style={{ fontSize: 12 }}>
              {intl.formatMessage({
                id: "login.tagline",
                defaultMessage: "Security made simple — sign in to continue.",
              })}
            </div>
          </div>
        </div>

        {authMode === "oidc" ? (
          <>
            <p className="muted">
              {intl.formatMessage({
                id: "login.oidc.prompt",
                defaultMessage:
                  "Sign in with your organization account. We'll take you to your identity provider, then bring you right back.",
              })}
            </p>
            <button
              className="btn btn--primary"
              style={{ width: "100%", justifyContent: "center" }}
              onClick={onOidc}
            >
              {intl.formatMessage({
                id: "login.oidc.button",
                defaultMessage: "Continue with single sign-on",
              })}
            </button>
          </>
        ) : (
          <form onSubmit={onJwtSubmit} noValidate>
            <label className="field">
              <span>
                {intl.formatMessage({
                  id: "login.jwt.label",
                  defaultMessage: "Sign-in token (development)",
                })}
              </span>
              <textarea
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="eyJhbGciOiJIUzI1NiI..."
                rows={4}
                autoComplete="off"
                spellCheck={false}
                aria-describedby={`${helpId}${error ? ` ${errorId}` : ""}`}
                aria-invalid={error ? true : undefined}
              />
            </label>
            <button
              className="btn btn--primary"
              type="submit"
              style={{ width: "100%", justifyContent: "center" }}
            >
              {intl.formatMessage({
                id: "login.jwt.button",
                defaultMessage: "Sign in",
              })}
            </button>
            <p
              id={helpId}
              className="muted"
              style={{ fontSize: 12, marginTop: 12 }}
            >
              {intl.formatMessage({
                id: "login.jwt.help",
                defaultMessage:
                  "This development sign-in accepts a signed token issued by the control plane. In production, this screen uses your organization's single sign-on instead.",
              })}
            </p>
          </form>
        )}
        {error && (
          <p id={errorId} className="error-text" role="alert">
            {error}
          </p>
        )}
      </div>
    </div>
  );
}
