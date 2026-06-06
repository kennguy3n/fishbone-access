package zoom

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ssoTestServer wires a httptest.Server + ZoomAccessConnector with
// the token override that other zoom tests use so we never need to
// mock the /oauth/token leg.
func ssoTestServer(t *testing.T, handler http.HandlerFunc) *ZoomAccessConnector {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) {
		return "fake-token", nil
	}
	return c
}

func TestCheckSSOEnforcement_SSOOnly_Enforced(t *testing.T) {
	c := ssoTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/accounts/acc-1/settings") {
			t.Errorf("path=%q; want /accounts/acc-1/settings", r.URL.Path)
		}
		if r.URL.Query().Get("option") != "security" {
			t.Errorf("option=%q; want security", r.URL.Query().Get("option"))
		}
		_, _ = w.Write([]byte(`{"login_types":["sso"]}`))
	})
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if !enforced {
		t.Error("enforced=false; want true when only SSO is allowed")
	}
	if !strings.Contains(strings.ToLower(details), "requires") {
		t.Errorf("details=%q; want to mention 'requires'", details)
	}
}

func TestCheckSSOEnforcement_PasswordAllowed_NotEnforced(t *testing.T) {
	c := ssoTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"login_types":["sso","password"]}`))
	})
	enforced, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Error("enforced=true; want false when password sign-in is enabled")
	}
}

func TestCheckSSOEnforcement_NewSchema_Enforced(t *testing.T) {
	c := ssoTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"sign_in":{"methods":["saml"]}}`))
	})
	enforced, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if !enforced {
		t.Error("enforced=false; want true on saml-only new-schema response")
	}
}

func TestCheckSSOEnforcement_EmptyResponse_NotEnforced(t *testing.T) {
	c := ssoTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Error("enforced=true; want false when no methods are surfaced")
	}
	if !strings.Contains(strings.ToLower(details), "did not surface") {
		t.Errorf("details=%q; want to mention 'did not surface'", details)
	}
}

func TestCheckSSOEnforcement_PasswordOnly_NotEnforced(t *testing.T) {
	c := ssoTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"login_types":["password"]}`))
	})
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Error("enforced=true; want false when only password is allowed")
	}
	if !strings.Contains(strings.ToLower(details), "does not advertise sso") {
		t.Errorf("details=%q; want to mention 'does not advertise SSO' so callers don't claim SSO is available", details)
	}
}

func TestCheckSSOEnforcement_UnrecognizedMethods_NotEnforced(t *testing.T) {
	// e.g. ["google"] — neither SSO/SAML nor password/email. The
	// boolean must stay false, and the details string must NOT
	// falsely claim "password login alongside SSO" because in this
	// case neither is advertised.
	c := ssoTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"login_types":["google"]}`))
	})
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Error("enforced=true; want false for unrecognized-only methods")
	}
	if strings.Contains(strings.ToLower(details), "alongside sso") {
		t.Errorf("details=%q; must not claim 'password login alongside SSO' when neither was advertised", details)
	}
	if !strings.Contains(strings.ToLower(details), "cannot be confirmed") {
		t.Errorf("details=%q; want to mention enforcement cannot be confirmed", details)
	}
}

func TestCheckSSOEnforcement_AccountIDIsPathEscaped(t *testing.T) {
	// AccountID is operator-configured today and rarely contains
	// special characters, but the path-building code must still
	// run it through url.PathEscape so a forward slash or space
	// can never silently retarget the request at a different
	// resource. We assert the *escaped* literal "acc%2F1%20space"
	// appears in the request path — if a future refactor drops
	// the escape, the literal '/' would split the segment and
	// this test would fail.
	var seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{"login_types":["sso"]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) {
		return "fake-token", nil
	}
	cfg := map[string]interface{}{"account_id": "acc/1 space"}
	if _, _, err := c.CheckSSOEnforcement(context.Background(), cfg, validSecrets()); err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if !strings.Contains(seenPath, "/accounts/acc%2F1%20space/settings") {
		t.Errorf("escaped path=%q; want to contain /accounts/acc%%2F1%%20space/settings", seenPath)
	}
}

func TestCheckSSOEnforcement_HTTPFailure(t *testing.T) {
	c := ssoTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	if _, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets()); err == nil {
		t.Fatal("err=nil; want non-nil on 403")
	}
}

func TestCheckSSOEnforcement_MalformedBody(t *testing.T) {
	c := ssoTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{not valid json`))
	})
	if _, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets()); err == nil {
		t.Fatal("err=nil; want non-nil on malformed body")
	}
}

func TestCheckSSOEnforcement_TokenError(t *testing.T) {
	c := New()
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) {
		return "", errSimulated{}
	}
	if _, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets()); err == nil {
		t.Fatal("err=nil; want non-nil when token acquisition fails")
	}
}

type errSimulated struct{}

func (errSimulated) Error() string { return "simulated token error" }
