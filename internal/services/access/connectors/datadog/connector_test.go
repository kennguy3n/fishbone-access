package datadog

import (
	"context"
	"encoding/json"
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

func validConfig() map[string]interface{} { return map[string]interface{}{"site": "datadoghq.com"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "ddAPI1234bbbbCCCC", "application_key": "ddAPP1234bbbbCCCC"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{"api_key": "x"}); err == nil {
		t.Error("missing app key")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{"application_key": "x"}); err == nil {
		t.Error("missing api key")
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
		if r.Header.Get("DD-API-KEY") == "" {
			t.Errorf("missing DD-API-KEY")
		}
		if r.Header.Get("DD-APPLICATION-KEY") == "" {
			t.Errorf("missing DD-APPLICATION-KEY")
		}
		if r.URL.Path != "/api/v2/users" {
			t.Errorf("path = %q", r.URL.Path)
		}
		page := r.URL.Query().Get("page[number]")
		if calls == 1 && page != "0" {
			t.Errorf("page = %q", page)
		}
		body := map[string]interface{}{"data": []map[string]interface{}{}, "meta": map[string]interface{}{"page": map[string]interface{}{"total_count": pageSize + 1}}}
		if calls == 1 {
			data := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				data = append(data, map[string]interface{}{
					"id":         fmt.Sprintf("u%d", i),
					"type":       "users",
					"attributes": map[string]interface{}{"email": fmt.Sprintf("u%d@x.com", i), "handle": fmt.Sprintf("u%d", i), "name": fmt.Sprintf("User %d", i), "disabled": false},
				})
			}
			body["data"] = data
		} else {
			body["data"] = []map[string]interface{}{{"id": "last", "type": "users", "attributes": map[string]interface{}{"email": "last@x.com", "handle": "last", "name": "Last", "disabled": true}}}
		}
		b, _ := json.Marshal(body)
		_, _ = w.Write(b)
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
	if len(got) != pageSize+1 {
		t.Fatalf("len = %d", len(got))
	}
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
	if got[len(got)-1].Status != "disabled" {
		t.Errorf("last status = %q", got[len(got)-1].Status)
	}
}

func TestConnect_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("Connect err = %v; want 403", err)
	}
}

func TestGetCredentialsMetadata_RedactsToken(t *testing.T) {
	md, err := New().GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	short, _ := md["api_key_short"].(string)
	if short == "" || strings.Contains(short, "API1234") {
		t.Errorf("api_key_short = %q", short)
	}
	short2, _ := md["application_key_short"].(string)
	if short2 == "" || strings.Contains(short2, "APP1234") {
		t.Errorf("application_key_short = %q", short2)
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
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "role-1"}); err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
}

func TestProvisionAccess_Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "role-1"}); err != nil {
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
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "role-1"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestRevokeAccess_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "role-1"}); err != nil {
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
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "role-1"}); err != nil {
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
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "role-1"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestListEntitlements_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"r1","attributes":{"name":"Admin"}}]}`))
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
		_, _ = w.Write([]byte(`{"data":[]}`))
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

// TestListEntitlements_MalformedBodyReturnsError guards against the
// error-swallowing regression where a 2xx response with an
// undecodable body returned (nil, nil) — silently reporting "no
// entitlements" instead of surfacing the decode failure. A truncated
// or malformed body must produce a non-nil error so an access review
// fails loud rather than recording a false "no access".
func TestListEntitlements_MalformedBodyReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data": "not-an-array"`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err == nil {
		t.Fatalf("expected decode error, got nil (entitlements=%v)", got)
	}
	if got != nil {
		t.Fatalf("expected nil entitlements on decode error, got %v", got)
	}
}

// TestProvisionRevoke_TrimWhitespaceCredentials guards against the
// regression where ProvisionAccess / RevokeAccess sent the raw
// secrets.APIKey / secrets.ApplicationKey without TrimSpace, while
// every other code path (newRequest, RevokeUserSessions) trims. A
// stored secret with an incidental trailing newline would then make
// provision/revoke fail auth while reads succeeded. The server asserts
// the auth headers arrive already trimmed.
func TestProvisionRevoke_TrimWhitespaceCredentials(t *testing.T) {
	const wantAPI = "ddAPI1234bbbbCCCC"
	const wantApp = "ddAPP1234bbbbCCCC"
	check := func(t *testing.T, r *http.Request) {
		if got := r.Header.Get("DD-API-KEY"); got != wantAPI {
			t.Errorf("DD-API-KEY = %q, want trimmed %q", got, wantAPI)
		}
		if got := r.Header.Get("DD-APPLICATION-KEY"); got != wantApp {
			t.Errorf("DD-APPLICATION-KEY = %q, want trimmed %q", got, wantApp)
		}
	}
	whitespaceSecrets := map[string]interface{}{
		"api_key":         "  " + wantAPI + "\n",
		"application_key": "\t" + wantApp + "  ",
	}
	t.Run("provision", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			check(t, r)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}))
		t.Cleanup(srv.Close)
		c := New()
		c.urlOverride = srv.URL
		c.httpClient = func() httpDoer { return srv.Client() }
		if err := c.ProvisionAccess(context.Background(), validConfig(), whitespaceSecrets, access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "role-1"}); err != nil {
			t.Fatalf("ProvisionAccess: %v", err)
		}
	})
	t.Run("revoke", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			check(t, r)
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(srv.Close)
		c := New()
		c.urlOverride = srv.URL
		c.httpClient = func() httpDoer { return srv.Client() }
		if err := c.RevokeAccess(context.Background(), validConfig(), whitespaceSecrets, access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "role-1"}); err != nil {
			t.Fatalf("RevokeAccess: %v", err)
		}
	})
}

func newDatadogTestConnector(t *testing.T, status int, body string) *DatadogAccessConnector {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return c
}

// TestProvisionAccess_StatusHandling pins the status classification for
// ProvisionAccess. Before the fix only 200/409 counted as success, so a
// 201 Created (a valid POST result) was reported as a hard failure, and
// 5xx/429 were not distinguished from permanent 4xx — preventing the
// worker from retrying transient errors with backoff.
func TestProvisionAccess_StatusHandling(t *testing.T) {
	grant := access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "role-1"}
	cases := []struct {
		name        string
		status      int
		body        string
		wantErr     bool
		wantTransit bool
	}{
		{"200 ok", http.StatusOK, `{}`, false, false},
		{"201 created", http.StatusCreated, `{}`, false, false},
		{"204 no content", http.StatusNoContent, ``, false, false},
		{"409 already member", http.StatusConflict, `{}`, false, false},
		{"400 already exists", http.StatusBadRequest, `{"errors":["user already exists"]}`, false, false},
		{"403 forbidden permanent", http.StatusForbidden, `{}`, true, false},
		{"500 transient", http.StatusInternalServerError, `{}`, true, true},
		{"429 transient", http.StatusTooManyRequests, `{}`, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newDatadogTestConnector(t, tc.status, tc.body)
			err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant)
			if tc.wantErr != (err != nil) {
				t.Fatalf("status %d: err = %v, wantErr = %v", tc.status, err, tc.wantErr)
			}
			if tc.wantErr && tc.wantTransit != strings.Contains(fmt.Sprint(err), "transient") {
				t.Fatalf("status %d: err = %v, wantTransient = %v", tc.status, err, tc.wantTransit)
			}
		})
	}
}

// TestRevokeAccess_StatusHandling pins the status classification for
// RevokeAccess: the full 2xx range and 404 (already gone) are idempotent
// successes, 5xx/429 are transient (retryable), and other 4xx are
// permanent failures.
func TestRevokeAccess_StatusHandling(t *testing.T) {
	grant := access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "role-1"}
	cases := []struct {
		name        string
		status      int
		body        string
		wantErr     bool
		wantTransit bool
	}{
		{"200 ok", http.StatusOK, `{}`, false, false},
		{"204 no content", http.StatusNoContent, ``, false, false},
		{"404 already gone", http.StatusNotFound, `{}`, false, false},
		{"410 does not exist", http.StatusGone, `{"errors":["does not exist"]}`, false, false},
		{"403 forbidden permanent", http.StatusForbidden, `{}`, true, false},
		{"502 transient", http.StatusBadGateway, `{}`, true, true},
		{"429 transient", http.StatusTooManyRequests, `{}`, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newDatadogTestConnector(t, tc.status, tc.body)
			err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant)
			if tc.wantErr != (err != nil) {
				t.Fatalf("status %d: err = %v, wantErr = %v", tc.status, err, tc.wantErr)
			}
			if tc.wantErr && tc.wantTransit != strings.Contains(fmt.Sprint(err), "transient") {
				t.Fatalf("status %d: err = %v, wantTransient = %v", tc.status, err, tc.wantTransit)
			}
		})
	}
}
