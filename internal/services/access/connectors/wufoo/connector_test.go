package wufoo

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

func validConfig() map[string]interface{} { return map[string]interface{}{"subdomain": "acme"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "ABCD1234EFGH5678"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing api_key")
	}
	if err := New().Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing subdomain")
	}
}

func TestValidate_RejectsBadSubdomain(t *testing.T) {
	bad := []string{"-bad", "bad-", "with.dot", "with_underscore", "with space", strings.Repeat("a", 64)}
	for _, b := range bad {
		if err := New().Validate(context.Background(), map[string]interface{}{"subdomain": b}, validSecrets()); err == nil {
			t.Errorf("expected error for %q", b)
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
		user, pwd, ok := r.BasicAuth()
		if !ok || user == "" || pwd != "" {
			t.Errorf("expected basic auth user-only; got user=%q pwd=%q ok=%v", user, pwd, ok)
		}
		var arr []map[string]interface{}
		if calls == 1 {
			for i := 0; i < pageSize; i++ {
				arr = append(arr, map[string]interface{}{
					"UserID":    i + 1,
					"User":      fmt.Sprintf("u%d", i),
					"Email":     fmt.Sprintf("u%d@x.com", i),
					"FirstName": "F",
					"LastName":  "L",
				})
			}
		} else {
			arr = []map[string]interface{}{{"UserID": 9999, "User": "last", "Email": "last@x.com"}}
		}
		body := map[string]interface{}{"Users": arr}
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
	got, _ := md["api_key_short"].(string)
	if !strings.Contains(got, "...") || strings.Contains(got, "1234EFGH") {
		t.Errorf("redaction failed: %q", got)
	}
}
