package box

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

func validConfig() map[string]interface{} { return map[string]interface{}{} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "boxAAAA1234bbbbCCCC"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
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
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("expected Bearer auth")
		}
		offset := r.URL.Query().Get("offset")
		if calls == 1 && offset != "0" {
			t.Errorf("offset = %q", offset)
		}
		if calls == 2 && offset != fmt.Sprintf("%d", pageSize) {
			t.Errorf("offset = %q", offset)
		}
		if calls == 1 {
			entries := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				entries = append(entries, map[string]interface{}{
					"id":     fmt.Sprintf("u%d", i+1),
					"name":   fmt.Sprintf("User %d", i+1),
					"login":  fmt.Sprintf("e%d@x.com", i+1),
					"status": "active",
				})
			}
			b, _ := json.Marshal(map[string]interface{}{
				"total_count": pageSize + 1,
				"limit":       pageSize,
				"offset":      0,
				"entries":     entries,
			})
			_, _ = w.Write(b)
			return
		}
		b, _ := json.Marshal(map[string]interface{}{
			"total_count": pageSize + 1,
			"limit":       pageSize,
			"offset":      pageSize,
			"entries": []map[string]interface{}{
				{"id": "u999", "name": "Last User", "login": "last@x.com", "status": "inactive"},
			},
		})
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

func newAdvancedTestConnector(srv *httptest.Server) *BoxAccessConnector {
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return c
}

func TestProvisionAccess_HappyPath(t *testing.T) {
	var got struct{ method, path string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method = r.Method
		got.path = r.URL.Path
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "100", ResourceExternalID: "200", Role: "editor",
	}); err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	if got.method != http.MethodPost || !strings.HasSuffix(got.path, "/2.0/collaborations") {
		t.Errorf("call = %s %s", got.method, got.path)
	}
}

func TestProvisionAccess_409Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "100", ResourceExternalID: "200",
	}); err != nil {
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
		UserExternalID: "100", ResourceExternalID: "200",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403; got %v", err)
	}
}

func TestRevokeAccess_HappyPath(t *testing.T) {
	var deleted string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"entries":[{"id":"COLLAB1","role":"editor","accessible_by":{"id":"100","type":"user"}}]}`))
		case http.MethodDelete:
			deleted = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "100", ResourceExternalID: "200",
	}); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if !strings.HasSuffix(deleted, "/2.0/collaborations/COLLAB1") {
		t.Errorf("deleted = %q", deleted)
	}
}

func TestRevokeAccess_NoCollabIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"entries":[]}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "100", ResourceExternalID: "200",
	}); err != nil {
		t.Fatalf("missing collab should be idempotent; got %v", err)
	}
}

func TestListEntitlements_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/2.0/users/100/memberships") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"entries":[{"id":"m1","role":"admin","group":{"id":"g1","name":"G1"}}]}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "100")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 1 || got[0].ResourceExternalID != "g1" || got[0].Role != "admin" {
		t.Fatalf("got = %+v", got)
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

func TestBearerHeader_DedupesSchemeCaseInsensitively(t *testing.T) {
	cases := map[string]string{
		"abc123":        "Bearer abc123",
		"Bearer abc123": "Bearer abc123",
		"bearer abc123": "Bearer abc123",
		"BEARER abc123": "Bearer abc123",
		"  abc123  ":    "Bearer abc123",
	}
	for in, want := range cases {
		if got := bearerHeader(Secrets{AccessToken: in}); got != want {
			t.Errorf("bearerHeader(%q) = %q, want %q", in, got, want)
		}
	}
}

var _ = json.RawMessage(nil)
var _ = fmt.Sprintf
