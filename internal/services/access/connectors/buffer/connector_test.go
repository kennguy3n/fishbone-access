package buffer

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
	return map[string]interface{}{"token": "tok_AAAA1234bbbbCCCC"}
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

// Buffer does not paginate; assert that one GET yields all profiles in
// a single batch and that the next-checkpoint is empty.
func TestSync_PaginatesUsers(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			t.Errorf("expected Bearer auth; got %q", got)
		}
		if r.URL.Path != "/1/profiles.json" {
			t.Errorf("path = %q", r.URL.Path)
		}
		body := []map[string]interface{}{
			{"id": "p1", "service": "twitter", "service_username": "alice", "formatted_username": "@alice"},
			{"id": "p2", "service": "linkedin", "service_username": "bob", "disabled": true},
		}
		b, _ := json.Marshal(body)
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	var lastNext string
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, next string) error {
		got = append(got, b...)
		lastNext = next
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(got) != 2 || calls != 1 || lastNext != "" {
		t.Fatalf("got=%d calls=%d next=%q", len(got), calls, lastNext)
	}
	if got[1].Status != "disabled" {
		t.Errorf("expected disabled status; got %q", got[1].Status)
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
	got, _ := md["token_short"].(string)
	if !strings.Contains(got, "...") || strings.Contains(got, "AAAA1234") {
		t.Errorf("redaction failed: %q", got)
	}
}

// TestShortToken_MasksShortSecret guards that a short (≤8 char) secret is
// never echoed verbatim through the credential fingerprint. Real API
// tokens are long, but a misconfigured short token must still be fully
// masked rather than surfaced as-is in GetCredentialsMetadata output
// (which is shown in the admin UI and may reach logs). This shortToken
// is duplicated verbatim across the batch's connectors.
func TestShortToken_MasksShortSecret(t *testing.T) {
	for _, tok := range []string{"a", "abc", "secret12", "abcd1234"} {
		got := shortToken(tok)
		if strings.ContainsAny(got, "abcdefghijklmnopqrstuvwxyz0123456789") {
			t.Errorf("shortToken(%q) = %q leaks secret characters; want fully masked", tok, got)
		}
	}
	// Long tokens keep the first/last 4 fingerprint with an ellipsis.
	if got := shortToken("tok_AAAA1234bbbbCCCC"); !strings.Contains(got, "...") || strings.Contains(got, "AAAA1234") {
		t.Errorf("shortToken(long) = %q, want first4...last4 fingerprint", got)
	}
}
