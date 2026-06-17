import { useState } from "react";
import { Card, Badge, Spinner } from "@/components/ui";
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
  const methods = useMFAMethods();

  return (
    <Card
      title="Security — step-up MFA"
      subtitle="Factors you re-assert to authorize high-risk actions (policy promotion, privileged connect, compliance export)."
    >
      {methods.isLoading ? (
        <Spinner />
      ) : methods.isError ? (
        <p className="muted">
          Could not load MFA status: {errText(methods.error)}
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
        <p className="muted">MFA status unavailable.</p>
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
          <b>Authenticator app (TOTP)</b>{" "}
          {!configured ? (
            <Badge tone="warn">Unavailable</Badge>
          ) : verified ? (
            <Badge tone="ok">Enabled</Badge>
          ) : (
            <Badge tone="info">Not set up</Badge>
          )}
        </div>
        {configured && verified && !enrollment ? (
          <button
            type="button"
            className="btn btn--danger btn--sm"
            disabled={disable.isPending}
            onClick={() => disable.mutate()}
          >
            {disable.isPending ? "Disabling…" : "Disable"}
          </button>
        ) : configured && !enrollment ? (
          <button
            type="button"
            className="btn btn--primary btn--sm"
            disabled={begin.isPending}
            onClick={startEnroll}
          >
            {begin.isPending ? "Starting…" : verified ? "Re-enrol" : "Set up"}
          </button>
        ) : null}
      </header>

      {!configured ? (
        <p className="muted" style={{ fontSize: 12, marginTop: 6 }}>
          TOTP step-up is not configured on this control plane.
        </p>
      ) : null}

      {enrollment ? (
        <div className="field" style={{ marginTop: 12 }}>
          <p className="muted" style={{ fontSize: 12 }}>
            Scan this in your authenticator app, or enter the secret manually,
            then confirm the 6-digit code. The secret is shown only once.
          </p>
          <label className="field">
            <span>Secret</span>
            <input readOnly value={enrollment.secret} />
          </label>
          <label className="field">
            <span>otpauth URI</span>
            <input readOnly value={enrollment.otpauth_url} />
          </label>
          <label className="field">
            <span>6-digit code</span>
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
              {finish.isPending ? "Confirming…" : "Confirm"}
            </button>
            <button
              type="button"
              className="btn btn--ghost btn--sm"
              onClick={() => {
                setEnrollment(null);
                setCode("");
              }}
            >
              Cancel
            </button>
          </div>
          {finish.isError ? (
            <p className="muted" style={{ color: "var(--danger)", fontSize: 12 }}>
              {errText(finish.error)}
            </p>
          ) : null}
        </div>
      ) : null}

      {begin.isError ? (
        <p className="muted" style={{ color: "var(--danger)", fontSize: 12 }}>
          {errText(begin.error)}
        </p>
      ) : null}
      {disable.isError ? (
        <p className="muted" style={{ color: "var(--danger)", fontSize: 12 }}>
          {errText(disable.error)}
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
  const register = useRegisterWebAuthn();
  const remove = useDeleteWebAuthnCredential();
  const [name, setName] = useState("");

  const supported = webAuthnSupported();

  const add = () => {
    register.mutate(name.trim() || "Security key", {
      onSuccess: () => setName(""),
    });
  };

  return (
    <section>
      <header style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <b>Security keys (WebAuthn / FIDO2)</b>
        {configured ? (
          <Badge tone={credentials.length ? "ok" : "info"}>
            {credentials.length} registered
          </Badge>
        ) : (
          <Badge tone="warn">Unavailable</Badge>
        )}
      </header>

      {!configured ? (
        <p className="muted" style={{ fontSize: 12, marginTop: 6 }}>
          WebAuthn step-up is not configured on this control plane.
        </p>
      ) : (
        <>
          {credentials.length ? (
            <ul className="kv" style={{ marginTop: 10, listStyle: "none", padding: 0 }}>
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
                      <Badge tone="warn">clone warning</Badge>
                    ) : null}
                    <br />
                    <span className="muted" style={{ fontSize: 12 }}>
                      added {new Date(c.created_at).toLocaleDateString()}
                      {c.last_used_at
                        ? ` · last used ${new Date(c.last_used_at).toLocaleDateString()}`
                        : " · never used"}
                    </span>
                  </span>
                  <button
                    type="button"
                    className="btn btn--danger btn--sm"
                    disabled={remove.isPending}
                    onClick={() => remove.mutate(c.id)}
                  >
                    Remove
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted" style={{ fontSize: 12, marginTop: 6 }}>
              No security keys registered yet.
            </p>
          )}

          <div className="field-row" style={{ marginTop: 10, alignItems: "end" }}>
            <label className="field" style={{ flex: 1 }}>
              <span>Name a new key</span>
              <input
                placeholder="YubiKey 5C"
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
              {register.isPending ? "Touch your key…" : "Add security key"}
            </button>
          </div>
          {!supported ? (
            <p className="muted" style={{ fontSize: 12 }}>
              This browser does not support WebAuthn.
            </p>
          ) : null}
          {register.isError ? (
            <p className="muted" style={{ color: "var(--danger)", fontSize: 12 }}>
              {errText(register.error)}
            </p>
          ) : null}
          {remove.isError ? (
            <p className="muted" style={{ color: "var(--danger)", fontSize: 12 }}>
              {errText(remove.error)}
            </p>
          ) : null}
        </>
      )}
    </section>
  );
}
