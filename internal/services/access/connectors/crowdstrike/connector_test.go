package crowdstrike

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	return map[string]interface{}{"client_id": "csAAAA1234bbbbCCCC", "client_secret": "shAAAA1234DDDDeeee"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{"client_id": "x"}); err == nil {
		t.Error("missing client_secret")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{"client_secret": "x"}); err == nil {
		t.Error("missing client_id")
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
	queryCalls, entityCalls := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			_, _ = w.Write([]byte(`{"access_token":"deadbeef","expires_in":1800,"token_type":"bearer"}`))
		case "/user-management/queries/users/v1":
			queryCalls++
			if r.Header.Get("Authorization") != "Bearer deadbeef" {
				t.Errorf("expected bearer auth, got %q", r.Header.Get("Authorization"))
			}
			if queryCalls == 1 {
				ids := make([]string, 0, pageLimit)
				for i := 0; i < pageLimit; i++ {
					ids = append(ids, fmt.Sprintf("uuid-p1-%d", i))
				}
				resp, _ := json.Marshal(map[string]interface{}{
					"resources": ids,
					"meta": map[string]interface{}{
						"pagination": map[string]interface{}{"offset": 0, "limit": pageLimit, "total": pageLimit + 1},
					},
				})
				_, _ = w.Write(resp)
				return
			}
			_, _ = fmt.Fprintf(w, `{"resources":["uuid-p2-0"],"meta":{"pagination":{"offset":%d,"limit":%d,"total":%d}}}`, pageLimit, pageLimit, pageLimit+1)
		case "/user-management/entities/users/GET/v1":
			entityCalls++
			body, _ := io.ReadAll(r.Body)
			var req struct {
				IDs []string `json:"ids"`
			}
			_ = json.Unmarshal(body, &req)
			users := make([]map[string]interface{}, 0, len(req.IDs))
			for i, id := range req.IDs {
				users = append(users, map[string]interface{}{
					"uuid":       id,
					"uid":        fmt.Sprintf("u%d@x.com", i),
					"first_name": fmt.Sprintf("First%d", i),
					"last_name":  "Last",
					"status":     "active",
				})
			}
			resp, _ := json.Marshal(map[string]interface{}{"resources": users})
			_, _ = w.Write(resp)
		default:
			http.NotFound(w, r)
		}
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
	if len(got) != pageLimit+1 {
		t.Fatalf("len = %d", len(got))
	}
	if queryCalls < 2 {
		t.Fatalf("expected pagination, queryCalls = %d", queryCalls)
	}
	if entityCalls < 2 {
		t.Fatalf("expected hydrate per page, entityCalls = %d", entityCalls)
	}
}

func TestConnect_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"code":401,"message":"invalid client"}]}`))
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
	id, _ := md["client_id_short"].(string)
	sec, _ := md["client_secret_short"].(string)
	if id == "" || strings.Contains(id, "AAAA1234") || sec == "" || strings.Contains(sec, "AAAA1234") {
		t.Errorf("redaction failed: id=%q sec=%q", id, sec)
	}
}

// ---------- advanced capability tests ----------

func csHandler(inner http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			_, _ = w.Write([]byte(`{"access_token":"test-tok","expires_in":1800,"token_type":"bearer"}`))
			return
		}
		inner(w, r)
	}
}

func TestProvisionAccess_HappyPath(t *testing.T) {
	srv := httptest.NewServer(csHandler(func(w http.ResponseWriter, r *http.Request) {
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
	srv := httptest.NewServer(csHandler(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":[{"message":"already"}]}`))
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
	srv := httptest.NewServer(csHandler(func(w http.ResponseWriter, r *http.Request) {
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
	srv := httptest.NewServer(csHandler(func(w http.ResponseWriter, r *http.Request) {
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
	srv := httptest.NewServer(csHandler(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":[{"message":"already"}]}`))
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
	srv := httptest.NewServer(csHandler(func(w http.ResponseWriter, r *http.Request) {
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
	srv := httptest.NewServer(csHandler(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"resources":["admin","reader"]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
}

func TestListEntitlements_Empty(t *testing.T) {
	srv := httptest.NewServer(csHandler(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"resources":[]}`))
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
