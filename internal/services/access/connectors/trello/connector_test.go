package trello

import (
	"context"
	"errors"
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

func validConfig() map[string]interface{} {
	return map[string]interface{}{"organization_id": "org123"}
}
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "trKey1234567890ABCD", "api_token": "trTokAAAA1111BBBB2222"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing org")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{"api_key": "k"}); err == nil {
		t.Error("missing token")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{"api_token": "t"}); err == nil {
		t.Error("missing key")
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
		if r.URL.Query().Get("key") == "" || r.URL.Query().Get("token") == "" {
			t.Errorf("missing key/token query params")
		}
		_, _ = w.Write([]byte(`[{"id":"u1","fullName":"Alice","username":"alice"},{"id":"u2","fullName":"Bob","username":"bob"}]`))
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
	if calls < 1 {
		t.Fatalf("expected at least one call, got %d", calls)
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
	if short == "" || strings.Contains(short, "AAAA1111") {
		t.Errorf("token_short = %q", short)
	}
	keyShort, _ := md["key_short"].(string)
	if keyShort == "" || strings.Contains(keyShort, "1234567890") {
		t.Errorf("key_short = %q", keyShort)
	}
}

// TestDoError_DoesNotLeakCredentials proves that when the underlying transport
// returns a *url.Error, the returned error string does not contain either the
// api_key or api_token. Trello requires query-string auth (no header
// equivalent for personal tokens), so this is the only line of defence.
func TestDoError_DoesNotLeakCredentials(t *testing.T) {
	c := New()
	c.urlOverride = "http://127.0.0.1:1" // unroutable, forces *url.Error
	c.httpClient = func() httpDoer { return &http.Client{Transport: http.DefaultTransport} }
	err := c.Connect(context.Background(), validConfig(), validSecrets())
	if err == nil {
		t.Fatal("expected error from unreachable host")
	}
	secrets := validSecrets()
	for _, field := range []string{"api_key", "api_token"} {
		v, _ := secrets[field].(string)
		if strings.Contains(err.Error(), v) {
			t.Errorf("%s leaked in error: %q", field, err.Error())
		}
	}
}

// ---------- advanced capability tests ----------

func newAdvancedTestConnector(srv *httptest.Server) *TrelloAccessConnector {
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return c
}

func TestProvisionAccess_HappyPath(t *testing.T) {
	var got struct{ method, path, query string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method = r.Method
		got.path = r.URL.Path
		got.query = r.URL.RawQuery
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "memb-1", ResourceExternalID: "board-1", Role: "normal",
	})
	if err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	if got.method != http.MethodPut {
		t.Errorf("method = %q", got.method)
	}
	if !strings.HasSuffix(got.path, "/boards/board-1/members/memb-1") {
		t.Errorf("path = %q", got.path)
	}
	if !strings.Contains(got.query, "type=normal") {
		t.Errorf("query missing type=normal: %s", got.query)
	}
	if !strings.Contains(got.query, "key=") || !strings.Contains(got.query, "token=") {
		t.Errorf("query missing auth: %s", got.query)
	}
}

func TestProvisionAccess_409Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "memb-1", ResourceExternalID: "board-1",
	})
	if err != nil {
		t.Fatalf("409 should be idempotent; got %v", err)
	}
}

func TestProvisionAccess_FailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "memb-1", ResourceExternalID: "board-1",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403; got %v", err)
	}
}

func TestRevokeAccess_HappyPath(t *testing.T) {
	var got struct{ method, path string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method = r.Method
		got.path = r.URL.Path
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "memb-1", ResourceExternalID: "board-1",
	})
	if err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if got.method != http.MethodDelete {
		t.Errorf("method = %q", got.method)
	}
}

func TestRevokeAccess_404Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "memb-1", ResourceExternalID: "board-1",
	}); err != nil {
		t.Fatalf("404 should be idempotent; got %v", err)
	}
}

func TestListEntitlements_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/members/memb-1/boards") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`[{"id":"b1","name":"B1"},{"id":"b2","name":"B2"}]`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "memb-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got len=%d", len(got))
	}
}

func TestProvisionRevoke_RejectMissing(t *testing.T) {
	c := New()
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{ResourceExternalID: "x"}); err == nil {
		t.Error("provision should require user id")
	}
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "u"}); err == nil {
		t.Error("revoke should require resource id")
	}
}
