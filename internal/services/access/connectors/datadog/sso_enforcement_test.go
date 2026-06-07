package datadog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func datadogSSOConfig() map[string]interface{} { return map[string]interface{}{} }
func datadogSSOSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "k", "application_key": "ak"}
}

func ssoSrv(t *testing.T, payload string, status int) *DatadogAccessConnector {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/api/v1/org") {
			t.Errorf("path=%q; want suffix /api/v1/org", r.URL.Path)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(payload))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	return c
}

func TestDatadog_CheckSSOEnforcement_StrictMode_Enforced(t *testing.T) {
	c := ssoSrv(t, `{"org":{"settings":{"saml":{"enabled":true},"saml_strict_mode":{"enabled":true}}}}`, http.StatusOK)
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), datadogSSOConfig(), datadogSSOSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if !enforced {
		t.Errorf("enforced=false; want true (saml + strict)")
	}
	if !strings.Contains(strings.ToLower(details), "strict") {
		t.Errorf("details=%q; want mention of strict", details)
	}
}

func TestDatadog_CheckSSOEnforcement_NoStrict_NotEnforced(t *testing.T) {
	c := ssoSrv(t, `{"org":{"settings":{"saml":{"enabled":true},"saml_strict_mode":{"enabled":false}}}}`, http.StatusOK)
	enforced, _, err := c.CheckSSOEnforcement(context.Background(), datadogSSOConfig(), datadogSSOSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Errorf("enforced=true; want false when strict mode is off")
	}
}

func TestDatadog_CheckSSOEnforcement_NoSAML_NotEnforced(t *testing.T) {
	c := ssoSrv(t, `{"org":{"settings":{"saml":{"enabled":false}}}}`, http.StatusOK)
	enforced, _, err := c.CheckSSOEnforcement(context.Background(), datadogSSOConfig(), datadogSSOSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Errorf("enforced=true; want false when SAML is disabled")
	}
}

func TestDatadog_CheckSSOEnforcement_HTTPError_Surfaces(t *testing.T) {
	c := ssoSrv(t, `{"errors":["forbidden"]}`, http.StatusForbidden)
	_, _, err := c.CheckSSOEnforcement(context.Background(), datadogSSOConfig(), datadogSSOSecrets())
	if err == nil {
		t.Fatal("err=nil; want non-nil on 403")
	}
}

func TestDatadog_SatisfiesSSOEnforcementCheckerInterface(_ *testing.T) {
	var _ access.SSOEnforcementChecker = (*DatadogAccessConnector)(nil)
}
