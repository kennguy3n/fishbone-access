package personio

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		"client_id":     "ciAAAA1234bbbbCCCC",
		"client_secret": "csAAAA1234bbbbCCCC",
	}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing creds")
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

func makeEmployee(id int, first, last, email string) map[string]interface{} {
	return map[string]interface{}{
		"type": "Employee",
		"attributes": map[string]interface{}{
			"id":         map[string]interface{}{"value": float64(id)},
			"first_name": map[string]interface{}{"value": first},
			"last_name":  map[string]interface{}{"value": last},
			"email":      map[string]interface{}{"value": email},
			"status":     map[string]interface{}{"value": "active"},
		},
	}
}

func TestSync_PaginatesUsers(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth" {
			_, _ = w.Write([]byte(`{"success":true,"data":{"token":"tk-1"}}`))
			return
		}
		calls++
		offset := r.URL.Query().Get("offset")
		if calls == 1 && offset != "0" {
			t.Errorf("offset = %q", offset)
		}
		if calls == 2 && offset != fmt.Sprintf("%d", pageSize) {
			t.Errorf("offset = %q", offset)
		}
		if calls == 1 {
			data := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				data = append(data, makeEmployee(i+1, "F", fmt.Sprintf("L%d", i+1), fmt.Sprintf("e%d@x.com", i+1)))
			}
			b, _ := json.Marshal(map[string]interface{}{"success": true, "data": data})
			_, _ = w.Write(b)
			return
		}
		b, _ := json.Marshal(map[string]interface{}{
			"success": true,
			"data":    []map[string]interface{}{makeEmployee(999, "Last", "User", "last@x.com")},
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

// TestAuthToken_PercentEncodesSpecialCharacters guards against regressions in
// the OAuth2 token-exchange form body. Personio (and most OAuth2 providers)
// issue client secrets that may contain `&`, `=`, `+`, `%`, or whitespace; if
// the body is built with naive string interpolation those characters will
// either split into bogus form fields or mangle the secret on the wire,
// causing silent auth failures. The connector MUST percent-encode the
// credentials.
func TestAuthToken_PercentEncodesSpecialCharacters(t *testing.T) {
	const (
		rawClientID     = "client id with spaces"
		rawClientSecret = "abc&def=123+xyz%foo"
	)
	var captured string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			return
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		captured = string(body)
		_, _ = w.Write([]byte(`{"success":true,"data":{"token":"tk-1"}}`))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	tok, err := c.authToken(context.Background(), Secrets{
		ClientID:     rawClientID,
		ClientSecret: rawClientSecret,
	})
	if err != nil {
		t.Fatalf("authToken: %v", err)
	}
	if tok != "tk-1" {
		t.Fatalf("token = %q", tok)
	}

	parsed, err := url.ParseQuery(captured)
	if err != nil {
		t.Fatalf("ParseQuery(%q): %v", captured, err)
	}
	if got := parsed.Get("client_id"); got != rawClientID {
		t.Errorf("decoded client_id = %q; want %q", got, rawClientID)
	}
	if got := parsed.Get("client_secret"); got != rawClientSecret {
		t.Errorf("decoded client_secret = %q; want %q", got, rawClientSecret)
	}
	if len(parsed) != 2 {
		t.Errorf("parsed form had %d fields; want 2 (raw body = %q)", len(parsed), captured)
	}
	// Defense-in-depth: the raw body must NOT contain the unescaped secret.
	if strings.Contains(captured, rawClientSecret) {
		t.Errorf("raw body %q leaks unescaped client_secret", captured)
	}
}

func TestGetCredentialsMetadata_RedactsToken(t *testing.T) {
	md, err := New().GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	short, _ := md["client_secret_short"].(string)
	if short == "" || strings.Contains(short, "AAAA1234") {
		t.Errorf("client_secret_short = %q", short)
	}
}
