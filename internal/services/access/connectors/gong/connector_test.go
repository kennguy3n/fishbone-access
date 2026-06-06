package gong

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

func validConfig() map[string]interface{} { return map[string]interface{}{} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"access_key": "gngAAAA1234bbbbCCCC", "secret_key": "secAAAA1234bbbbCCCC"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{"access_key": "x"}); err == nil {
		t.Error("missing secret_key")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{"secret_key": "x"}); err == nil {
		t.Error("missing access_key")
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
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("expected Basic auth")
		}
		if r.URL.Path != "/v2/users" {
			t.Errorf("path = %q", r.URL.Path)
		}
		cursor := r.URL.Query().Get("cursor")
		body := map[string]interface{}{}
		if calls == 1 {
			if cursor != "" {
				t.Errorf("first call cursor = %q", cursor)
			}
			body["users"] = []map[string]interface{}{
				{"id": "u1", "firstName": "Alice", "lastName": "A", "emailAddress": "a@x.com", "active": true},
			}
			body["records"] = map[string]interface{}{"cursor": "next"}
		} else {
			if cursor != "next" {
				t.Errorf("cursor = %q", cursor)
			}
			body["users"] = []map[string]interface{}{
				{"id": "u2", "firstName": "Bob", "lastName": "B", "emailAddress": "b@x.com", "active": false},
			}
			body["records"] = map[string]interface{}{"cursor": ""}
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
	if got[1].Status != "inactive" {
		t.Errorf("status = %q", got[1].Status)
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
	short, _ := md["key_short"].(string)
	if short == "" || strings.Contains(short, "AAAA1234") {
		t.Errorf("key_short = %q", short)
	}
	secShort, _ := md["secret_short"].(string)
	if secShort == "" || strings.Contains(secShort, "AAAA1234") {
		t.Errorf("secret_short = %q", secShort)
	}
}
