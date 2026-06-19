import { useEffect, useRef, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useIntl } from "react-intl";
import { completeOidcLogin } from "@/auth/oidc";
import { useAuth } from "@/auth/auth-context";
import { LoadingState, ErrorState } from "@/components/ui";

export function OidcCallback() {
  const intl = useIntl();
  const { setSession } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<unknown>(null);
  const ran = useRef(false);

  useEffect(() => {
    if (ran.current) return;
    ran.current = true;
    completeOidcLogin(window.location.search)
      .then(({ accessToken }) => {
        // setSession rejects a malformed/expired token. The PKCE material is
        // already consumed (cleared in completeOidcLogin's finally), so this
        // callback can't be retried — surface an error instead of bouncing to
        // "/" and silently back to the login screen.
        if (setSession(accessToken)) {
          navigate({ to: "/" });
        } else {
          // setSession only rejects a token it can't decode as a JWT or that
          // is already expired. The common real-world cause is an IdP issuing
          // an opaque access token — which the JWT-bearer API can't use
          // either — so the message points operators at token format/audience.
          setError(
            new Error(
              intl.formatMessage({
                id: "oidc.error.tokenFormat",
                defaultMessage:
                  "Your sign-in completed, but your identity provider returned a token this console can't read. This usually means its token format or audience needs adjusting. Ask your administrator to check the single sign-on settings, then try again.",
              }),
            ),
          );
        }
      })
      .catch(setError);
  }, [setSession, navigate, intl]);

  if (error) {
    return (
      <div className="login">
        <div className="login__card">
          <ErrorState error={error} />
          <button
            className="btn"
            style={{ width: "100%", justifyContent: "center" }}
            onClick={() => navigate({ to: "/login" })}
          >
            {intl.formatMessage({
              id: "oidc.backToSignIn",
              defaultMessage: "Back to sign in",
            })}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="login">
      <div className="login__card">
        <LoadingState
          label={intl.formatMessage({
            id: "oidc.completing",
            defaultMessage: "Finishing your sign-in…",
          })}
        />
      </div>
    </div>
  );
}
