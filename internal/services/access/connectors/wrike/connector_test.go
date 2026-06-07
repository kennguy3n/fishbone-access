package wrike

import (
	"context"
	"encoding/json"
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

func validConfig() map[string]interface{} { return map[string]interface{}{"host": "app-us2.wrike.com"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "wrkAAAA1234bbbbCCCC"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing token")
	}
}

func TestValidate_RejectsInvalidHost(t *testing.T) {
	c := New()
	for _, bad := range []string{"-bad.example", "bad-.com", "bad/uri", "bad evil"} {
		if err := c.Validate(context.Background(), map[string]interface{}{"host": bad}, validSecrets()); err == nil {
			t.Errorf("expected error for host %q", bad)
		}
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
		if r.URL.Path != "/api/v4/contacts" {
			t.Errorf("path = %q", r.URL.Path)
		}
		token := r.URL.Query().Get("nextPageToken")
		body := map[string]interface{}{}
		if calls == 1 {
			if token != "" {
				t.Errorf("first call token = %q", token)
			}
			body["data"] = []map[string]interface{}{
				{"id": "c1", "firstName": "Alice", "lastName": "A", "type": "Person", "profiles": []map[string]interface{}{{"email": "a@x.com"}}},
			}
			body["nextPageToken"] = "tok2"
		} else {
			if token != "tok2" {
				t.Errorf("second call token = %q", token)
			}
			body["data"] = []map[string]interface{}{
				{"id": "g1", "firstName": "DevOps", "type": "Group"},
			}
			body["nextPageToken"] = ""
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
	if len(got) != 2 || calls != 2 {
		t.Fatalf("got=%d calls=%d", len(got), calls)
	}
	if got[1].Type != access.IdentityTypeGroup {
		t.Errorf("type = %q", got[1].Type)
	}
}

func TestConnect_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
