package notion

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

func validSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "secret_1234567890abcdef"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), nil, validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_MissingToken(t *testing.T) {
	if err := New().Validate(context.Background(), nil, map[string]interface{}{}); err == nil {
		t.Error("missing api_token: want error")
	}
}

func TestValidate_PureLocal(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })
	if err := New().Validate(context.Background(), nil, validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestRegistryIntegration(t *testing.T) {
	if got, _ := access.GetAccessConnector(ProviderName); got == nil {
		t.Fatal("not registered")
	}
}

func TestSync_Paginates(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Notion-Version") == "" {
			t.Errorf("missing Notion-Version header")
		}
		page++
		if page == 1 {
			_, _ = w.Write([]byte(`{
				"results":[{"object":"user","id":"u1","type":"person","name":"Alice","person":{"email":"alice@uney.com"}}],
				"has_more":true,
				"next_cursor":"cur2"
			}`))
			return
		}
		if r.URL.Query().Get("start_cursor") != "cur2" {
			t.Errorf("start_cursor = %q", r.URL.Query().Get("start_cursor"))
		}
		_, _ = w.Write([]byte(`{
			"results":[{"object":"user","id":"u2","type":"bot","name":"Bot","bot":{"owner":{"type":"workspace"}}}],
			"has_more":false,
			"next_cursor":null
		}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), nil, validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d; want 2", len(got))
	}
	if got[1].Type != access.IdentityTypeServiceAccount {
		t.Errorf("bot type = %q", got[1].Type)
	}
}

func TestConnect_FailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), nil, validSecrets()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("Connect err = %v; want 401", err)
	}
}

func TestGetCredentialsMetadata(t *testing.T) {
	md, err := New().GetCredentialsMetadata(context.Background(), nil, validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if md["api_version"] != notionAPIVersion {
		t.Errorf("api_version = %v", md["api_version"])
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
	if err := c.ProvisionAccess(context.Background(), nil, validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "page-1"}); err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
}

func TestProvisionAccess_Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":[{"message":"already"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.ProvisionAccess(context.Background(), nil, validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "page-1"}); err != nil {
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
	if err := c.ProvisionAccess(context.Background(), nil, validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "page-1"}); err == nil {
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
	if err := c.RevokeAccess(context.Background(), nil, validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "page-1"}); err != nil {
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
	if err := c.RevokeAccess(context.Background(), nil, validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "page-1"}); err != nil {
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
	if err := c.RevokeAccess(context.Background(), nil, validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "page-1"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestListEntitlements_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"type":"person","name":"Alice"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), nil, validSecrets(), "u-1")
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
	got, err := c.ListEntitlements(context.Background(), nil, validSecrets(), "u-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d, want 0", len(got))
	}
}

func TestListEntitlements_PropagatesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"object":"error","status":500}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), nil, validSecrets(), "u-1")
	if err == nil {
		t.Fatal("expected HTTP error to propagate, got nil")
	}
	if got != nil {
		t.Fatalf("expected nil entitlements on error, got %+v", got)
	}
}
