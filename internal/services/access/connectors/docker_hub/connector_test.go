package docker_hub

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

func validConfig() map[string]interface{} { return map[string]interface{}{"organization": "acme"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"username": "alice1234bbbbCCCC", "password": "passwordAAAA1234bbbbCCCC"}
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
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{"username": "x"}); err == nil {
		t.Error("missing pw")
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
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/users/login" {
			if r.Method != http.MethodPost {
				t.Errorf("login method = %s", r.Method)
			}
			_, _ = w.Write([]byte(`{"token":"jwt-test-token"}`))
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "JWT ") {
			t.Errorf("expected JWT auth, got %q", r.Header.Get("Authorization"))
		}
		if !strings.HasPrefix(r.URL.Path, "/v2/orgs/acme/members") {
			t.Errorf("path = %q", r.URL.Path)
		}
		calls++
		body := map[string]interface{}{
			"count":   2,
			"results": []map[string]interface{}{},
		}
		if calls == 1 {
			body["next"] = srv.URL + "/v2/orgs/acme/members?page=2&page_size=" + fmt.Sprintf("%d", pageSize)
			body["results"] = []map[string]interface{}{{"id": "u1", "username": "alice", "email": "alice@x.com", "role": "owner"}}
		} else {
			body["next"] = ""
			body["results"] = []map[string]interface{}{{"id": "u2", "username": "bob", "email": "bob@x.com", "role": "member"}}
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
	if len(got) != 2 {
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
	short, _ := md["password_short"].(string)
	if short == "" || strings.Contains(short, "AAAA1234") {
		t.Errorf("password_short = %q", short)
	}
}
