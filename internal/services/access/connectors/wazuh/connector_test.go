package wazuh

import (
	"context"
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

func validConfig() map[string]interface{} {
	return map[string]interface{}{"endpoint": "https://wazuh.corp.example"}
}
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "wzAAAA1234bbbbCCCC"}
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
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing endpoint")
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

// TestSync_PaginatesUsers verifies Wazuh's audit-only contract:
// SyncIdentities returns a single empty batch with no checkpoint and never
// touches the network. The batch slice must be non-nil per the
// SyncIdentities empty-batch contract documented in access/types.go so
// downstream consumers that JSON-marshal the batch see `[]` rather than
// `null`.
func TestSync_PaginatesUsers(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })
	calls := 0
	var batch []*access.Identity
	var lastCheckpoint string
	err := New().SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, next string) error {
		calls++
		batch = b
		lastCheckpoint = next
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if calls != 1 || len(batch) != 0 || lastCheckpoint != "" {
		t.Errorf("calls=%d batchLen=%d checkpoint=%q; want 1, 0, \"\"", calls, len(batch), lastCheckpoint)
	}
	if batch == nil {
		t.Error("batch is nil; want non-nil empty slice per SyncIdentities empty-batch contract (types.go)")
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

// TestCountIdentities_ValidatesCredentials confirms that CountIdentities
// rejects missing credentials with an error rather than silently
// returning zero, so callers cannot mistake a misconfigured tenant for
// an empty one.
func TestCountIdentities_ValidatesCredentials(t *testing.T) {
	c := New()
	if _, err := c.CountIdentities(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("CountIdentities with missing token should error")
	}
	got, err := c.CountIdentities(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CountIdentities: %v", err)
	}
	if got != 0 {
		t.Errorf("CountIdentities = %d; want 0 for audit-only connector", got)
	}
}

func TestGetCredentialsMetadata_RedactsToken(t *testing.T) {
	c := New()
	md, err := c.GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	got, _ := md["token_short"].(string)
	if !strings.Contains(got, "...") || strings.Contains(got, "AAAA1234") {
		t.Errorf("redaction failed: %q", got)
	}
}

func TestValidate_RejectsBadEndpoint(t *testing.T) {
	c := New()
	bad := map[string]string{
		"http scheme":      "http://wazuh.corp.example",
		"empty scheme":     "wazuh.corp.example",
		"file scheme":      "file:///etc/passwd",
		"ip literal":       "https://10.0.0.1",
		"v6 ip literal":    "https://[::1]",
		"with userinfo":    "https://attacker@wazuh.corp.example",
		"with path":        "https://wazuh.corp.example/internal",
		"with query":       "https://wazuh.corp.example?x=1",
		"with fragment":    "https://wazuh.corp.example#frag",
		"hyphen leading":   "https://-wazuh.corp.example",
		"underscore label": "https://bad_label.corp.example",
		"empty host":       "https://",
		"unparseable":      "https://%zz",
	}
	for name, ep := range bad {
		t.Run(name, func(t *testing.T) {
			err := c.Validate(context.Background(), map[string]interface{}{"endpoint": ep}, validSecrets())
			if err == nil {
				t.Errorf("expected error for endpoint %q", ep)
			}
		})
	}
}
