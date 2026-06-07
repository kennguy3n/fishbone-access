package snyk

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted")
}

func validConfig() map[string]interface{} { return map[string]interface{}{"org_id": "abc-org"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "snAAAA1234bbbbCCCC"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing org_id")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing token")
	}
}

func TestValidate_PureLocal(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestRegistryIntegration(t *testing.T) {
	if got, _ := access.GetAccessConnector(ProviderName); got == nil {
		t.Fatal("not registered")
	}
}

func TestSync_PaginatesUsers(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.HasPrefix(r.Header.Get("Authorization"), "token ") {
			t.Errorf("expected token auth, got %q", r.Header.Get("Authorization"))
		}
		if calls == 1 {
			body := fmt.Sprintf(`{"data":[{"id":"u1","type":"org_member","attributes":{"email":"a@b.com","name":"Alice","role":"admin"}}],"links":{"next":"%s/rest/orgs/abc-org/members?version=%s&starting_after=u1&limit=100"}}`, "", apiVersion)
			_, _ = w.Write([]byte(body))
			return
		}
		if r.URL.Query().Get("starting_after") != "u1" {
			t.Errorf("starting_after = %q", r.URL.Query().Get("starting_after"))
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"u2","type":"org_member","attributes":{"email":"b@b.com","name":"Bob","role":"member"}}],"links":{}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d", len(got))
	}
	if calls < 2 {
		t.Fatalf("expected pagination, calls = %d", calls)
	}
}

func TestConnect_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("Connect err = %v; want 401", err)
	}
}

func TestGetCredentialsMetadata_RedactsToken(t *testing.T) {
	md, err := New().GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	short, _ := md["token_short"].(string)
	if short == "" || strings.Contains(short, "AAAA1234") {
		t.Errorf("token_short = %q", short)
	}
}

// ---------- advanced capability tests ----------

func TestProvisionAccess_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "m-1"}); err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
}

func TestProvisionAccess_Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "m-1"}); err != nil {
		t.Fatalf("ProvisionAccess idempotent: %v", err)
	}
}

func TestProvisionAccess_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "m-1"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestRevokeAccess_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "m-1"}); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
}

func TestRevokeAccess_Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "m-1"}); err != nil {
		t.Fatalf("RevokeAccess idempotent: %v", err)
	}
}

func TestRevokeAccess_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "m-1"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestListEntitlements_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"attributes":{"role":"admin"}}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d, want 1", len(got))
	}
}

func TestListEntitlements_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d, want 0", len(got))
	}
}

// A transient upstream failure (5xx) must surface as an error so the
// caller can retry, rather than being swallowed as "no access".
func TestListEntitlements_TransientErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err == nil {
		t.Fatalf("expected error on 500, got nil (entitlements=%#v)", got)
	}
	if got != nil {
		t.Fatalf("expected nil entitlements on error, got %#v", got)
	}
}

// The Snyk REST API rejects any request to /rest/ that omits the
// `version` query parameter, so every advanced capability must send it
// (matching Connect/SyncIdentities/FetchAccessAuditLogs).
func TestAdvancedCapabilities_SendVersionParam(t *testing.T) {
	cases := []struct {
		name string
		call func(c *SnykAccessConnector) error
	}{
		{"provision", func(c *SnykAccessConnector) error {
			return c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "m-1"})
		}},
		{"revoke", func(c *SnykAccessConnector) error {
			return c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "m-1"})
		}},
		{"list", func(c *SnykAccessConnector) error {
			_, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotVersion string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotVersion = r.URL.Query().Get("version")
				_, _ = w.Write([]byte(`{"data":{"attributes":{"role":"admin"}}}`))
			}))
			t.Cleanup(srv.Close)
			c := New()
			c.urlOverride = srv.URL
			c.httpClient = func() httpDoer { return srv.Client() }
			if err := tc.call(c); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if gotVersion != apiVersion {
				t.Errorf("%s: version param = %q, want %q", tc.name, gotVersion, apiVersion)
			}
		})
	}
}

// PATCH provisioning commonly returns 204/201; any 2xx is success.
func TestProvisionAccess_Accepts2xx(t *testing.T) {
	for _, code := range []int{http.StatusCreated, http.StatusNoContent} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		c := New()
		c.urlOverride = srv.URL
		c.httpClient = func() httpDoer { return srv.Client() }
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "m-1"}); err != nil {
			t.Errorf("status %d: ProvisionAccess: %v", code, err)
		}
		srv.Close()
	}
}
