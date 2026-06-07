package basecamp

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

func validConfig() map[string]interface{} { return map[string]interface{}{"account_id": "1234567"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "bcmpAAAA1234bbbbCCCC"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing account_id")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing access_token")
	}
}

func TestValidate_RejectsNonNumericAccount(t *testing.T) {
	c := New()
	for _, bad := range []string{"abc", "12-34", "12 34", "12/34"} {
		if err := c.Validate(context.Background(), map[string]interface{}{"account_id": bad}, validSecrets()); err == nil {
			t.Errorf("expected error for account_id %q", bad)
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
		if !strings.HasSuffix(r.URL.Path, "/people.json") {
			t.Errorf("path = %q", r.URL.Path)
		}
		body := []map[string]interface{}{
			{"id": 1, "name": "Alice", "email_address": "a@x.com", "title": "Engineer", "admin": true},
			{"id": 2, "name": "Bot", "email_address": "bot@x.com", "bot": true},
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
	if len(got) != 2 || calls != 1 {
		t.Fatalf("got=%d calls=%d", len(got), calls)
	}
	if got[1].Type != access.IdentityTypeServiceAccount {
		t.Errorf("type = %q", got[1].Type)
	}
}

func TestSync_FollowsLinkHeaderPagination(t *testing.T) {
	var srvURL string
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Query().Get("page") {
		case "", "1":
			// First page advertises a next page via the RFC 5988 Link header.
			w.Header().Set("Link", "<"+srvURL+"/people.json?page=2>; rel=\"next\"")
			b, _ := json.Marshal([]map[string]interface{}{
				{"id": 1, "name": "Alice", "email_address": "a@x.com"},
			})
			_, _ = w.Write(b)
		default:
			// Last page: no Link header -> pagination terminates.
			b, _ := json.Marshal([]map[string]interface{}{
				{"id": 2, "name": "Bob", "email_address": "b@x.com"},
			})
			_, _ = w.Write(b)
		}
	}))
	t.Cleanup(srv.Close)
	srvURL = srv.URL
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
		t.Fatalf("expected 2 identities across 2 pages, got=%d calls=%d", len(got), calls)
	}
	if got[0].ExternalID != "1" || got[1].ExternalID != "2" {
		t.Errorf("unexpected identities: %q, %q", got[0].ExternalID, got[1].ExternalID)
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

// TestSync_RejectsOffHostCheckpoint pins the assertSameHost guard: a persisted
// checkpoint pointing off the API host must be refused rather than followed,
// since SyncIdentities attaches the auth token to every request and would
// otherwise leak it off-host. Mirrors the azure nextLink guard.
func TestSync_RejectsOffHostCheckpoint(t *testing.T) {
	contacted := false
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacted = true
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("auth token leaked off-host: %q", got)
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(evil.Close)

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(api.Close)

	c := New()
	c.urlOverride = api.URL
	c.httpClient = func() httpDoer { return api.Client() }
	badCheckpoint := evil.URL + "/people.json"
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), badCheckpoint, func(b []*access.Identity, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected error for off-host checkpoint, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected host") {
		t.Fatalf("error = %v; want host-mismatch refusal", err)
	}
	if contacted {
		t.Fatal("off-host server was contacted with the auth token")
	}
}
