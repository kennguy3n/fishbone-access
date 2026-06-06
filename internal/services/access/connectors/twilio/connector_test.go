package twilio

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
	return map[string]interface{}{
		"account_sid": "ACAAAA1234567890bbbbCCCCdddd0000",
		"auth_token":  "auth_AAAA1234bbbbCCCC",
	}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing creds")
	}
	if err := New().Validate(context.Background(), validConfig(), map[string]interface{}{"account_sid": "AC..."}); err == nil {
		t.Error("missing auth_token")
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
		user, pwd, ok := r.BasicAuth()
		if !ok || user == "" || pwd == "" {
			t.Errorf("expected basic auth; got user=%q pwd-empty=%v ok=%v", user, pwd == "", ok)
		}
		if !strings.Contains(r.URL.Path, "/Accounts/AC") {
			t.Errorf("expected sid in path; got %q", r.URL.Path)
		}
		page := r.URL.Query().Get("Page")
		if calls == 1 && page != "0" {
			t.Errorf("Page = %q", page)
		}
		if calls == 2 && page != "1" {
			t.Errorf("Page = %q", page)
		}
		var users []map[string]interface{}
		if calls == 1 {
			for i := 0; i < pageSize; i++ {
				users = append(users, map[string]interface{}{
					"sid":           fmt.Sprintf("US%016d", i),
					"friendly_name": fmt.Sprintf("U%d", i),
				})
			}
		} else {
			users = []map[string]interface{}{{"sid": "USlast", "friendly_name": "Last"}}
		}
		body := map[string]interface{}{"users": users}
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
	if len(got) != pageSize+1 || calls != 2 {
		t.Fatalf("got=%d calls=%d", len(got), calls)
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
		t.Fatalf("Metadata: %v", err)
	}
	for _, k := range []string{"account_sid_short", "auth_token_short"} {
		got, _ := md[k].(string)
		if !strings.Contains(got, "...") {
			t.Errorf("%s redaction failed: %q", k, got)
		}
		if strings.Contains(got, "AAAA1234bbbb") {
			t.Errorf("%s leaked token: %q", k, got)
		}
	}
}
