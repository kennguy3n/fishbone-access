package jira

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// recordingDoer is a fake httpDoer that captures the outbound request URL and
// returns a canned response without performing any network I/O.
type recordingDoer struct {
	gotURL string
	resp   *http.Response
}

func (d *recordingDoer) Do(req *http.Request) (*http.Response, error) {
	d.gotURL = req.URL.String()
	return d.resp, nil
}

// TestJira_CheckSSOEnforcement_UsesAdminGateway is a regression guard for the
// host-selection bug where CheckSSOEnforcement built the authentication-policies
// URL from baseURL() — the per-site product gateway
// (https://api.atlassian.com/ex/jira/{cloudID}) — instead of adminBaseURL(),
// the Atlassian admin gateway (https://api.atlassian.com). The
// /admin/v1/orgs/{orgID}/... endpoints live only on the admin gateway, so the
// /ex/jira/{cloudID} prefix made the probe 404 in production. The other
// CheckSSOEnforcement tests mask this because they set urlOverride, which
// collapses baseURL() and adminBaseURL() onto the same test server. This test
// deliberately leaves urlOverride empty and asserts the exact request URL via a
// fake doer, so the two gateways differ.
func TestJira_CheckSSOEnforcement_UsesAdminGateway(t *testing.T) {
	doer := &recordingDoer{
		resp: &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"data":[]}`)),
		},
	}
	c := New()
	c.httpClient = func() httpDoer { return doer }
	// urlOverride intentionally left empty so baseURL() and adminBaseURL() differ.
	if _, _, err := c.CheckSSOEnforcement(context.Background(), jiraSSOConfig(), jiraSSOSecrets()); err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	const want = "https://api.atlassian.com/admin/v1/orgs/org-1/authentication-policies"
	if doer.gotURL != want {
		t.Fatalf("request URL = %q; want %q (must use the Atlassian admin gateway, not the per-site /ex/jira/{cloudID} product gateway)", doer.gotURL, want)
	}
}

// TestJira_CheckSSOEnforcement_RequiresOrgID is a regression guard for the bug
// where a missing org_id silently fell back to cfg.CloudID. CloudID is a
// per-site product identifier (/ex/jira/{cloudID}); org_id is the distinct
// Atlassian organization identifier the admin API keys on
// (/admin/v1/orgs/{orgID}/...). Substituting CloudID produced a misleading 404
// that callers would map to "unknown" rather than surfacing the real
// misconfiguration. The connector must instead return a clear error and issue
// no request at all. The fake doer asserts no HTTP call is made.
func TestJira_CheckSSOEnforcement_RequiresOrgID(t *testing.T) {
	doer := &recordingDoer{
		resp: &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"data":[]}`)),
		},
	}
	c := New()
	c.httpClient = func() httpDoer { return doer }
	cfg := map[string]interface{}{"cloud_id": "cid-1", "site_url": "https://acme.atlassian.net"} // no org_id
	enforced, _, err := c.CheckSSOEnforcement(context.Background(), cfg, jiraSSOSecrets())
	if err == nil {
		t.Fatal("err = nil; want an error when org_id is absent (cloud_id must not be used as the admin org id)")
	}
	if !strings.Contains(err.Error(), "org_id") {
		t.Fatalf("err = %v; want mention of org_id", err)
	}
	if enforced {
		t.Fatal("enforced = true; must never report enforced on a misconfiguration error")
	}
	if doer.gotURL != "" {
		t.Fatalf("issued request to %q; want no request when org_id is missing", doer.gotURL)
	}
}

func jiraSSOConfig() map[string]interface{} {
	return map[string]interface{}{"cloud_id": "cid-1", "site_url": "https://acme.atlassian.net", "org_id": "org-1"}
}
func jiraSSOSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "tok", "email": "admin@acme.com"}
}

func TestJira_CheckSSOEnforcement_Enforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/admin/v1/orgs/org-1/authentication-policies") {
			t.Errorf("path=%q; want suffix /admin/v1/orgs/org-1/authentication-policies", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"p1","attributes":{"name":"Default","ssoOnly":true}}]}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), jiraSSOConfig(), jiraSSOSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if !enforced {
		t.Fatalf("enforced=false; want true (details=%q)", details)
	}
}

func TestJira_CheckSSOEnforcement_NotEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"p1","attributes":{"name":"Default","ssoOnly":false}}]}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	enforced, _, err := c.CheckSSOEnforcement(context.Background(), jiraSSOConfig(), jiraSSOSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Fatal("enforced=true; want false")
	}
}

func TestJira_CheckSSOEnforcement_HTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if _, _, err := c.CheckSSOEnforcement(context.Background(), jiraSSOConfig(), jiraSSOSecrets()); err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
}

func TestJira_SatisfiesSSOEnforcementCheckerInterface(t *testing.T) {
	var _ interface {
		CheckSSOEnforcement(context.Context, map[string]interface{}, map[string]interface{}) (bool, string, error)
	} = New()
}
