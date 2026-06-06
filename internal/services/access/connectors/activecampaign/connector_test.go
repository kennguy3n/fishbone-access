package activecampaign

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

func validConfig() map[string]interface{} { return map[string]interface{}{"account": "acmecorp"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "ac_AAAA1234bbbbCCCC"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing api_key")
	}
	if err := c.Validate(context.Background(), map[string]interface{}{"account": "bad acct"}, validSecrets()); err == nil {
		t.Error("invalid account")
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
		if r.Header.Get("Api-Token") == "" {
			t.Errorf("expected Api-Token header")
		}
		if r.URL.Path != "/api/3/users" {
			t.Errorf("path = %q", r.URL.Path)
		}
		offset := r.URL.Query().Get("offset")
		body := map[string]interface{}{}
		if calls == 1 {
			if offset != "0" {
				t.Errorf("offset = %q", offset)
			}
			items := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				items = append(items, map[string]interface{}{"id": fmt.Sprintf("%d", i+1), "username": fmt.Sprintf("u%d", i), "email": fmt.Sprintf("u%d@x.com", i), "firstName": "U", "lastName": fmt.Sprintf("%d", i)})
			}
			body["users"] = items
		} else {
			if offset != fmt.Sprintf("%d", pageSize) {
				t.Errorf("offset = %q", offset)
			}
			body["users"] = []map[string]interface{}{{"id": "999", "username": "last", "email": "last@x.com", "firstName": "L", "lastName": "ast"}}
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
	c := New()
	md, err := c.GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	got, _ := md["key_short"].(string)
	if !strings.Contains(got, "...") || strings.Contains(got, "1234bbbb") {
		t.Errorf("redaction failed: %q", got)
	}
}
