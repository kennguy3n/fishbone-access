package woocommerce

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

func validConfig() map[string]interface{} {
	return map[string]interface{}{"endpoint": "https://example.com"}
}
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"consumer_key": "tok_AAAA1234bbbbCCCC", "consumer_secret": "tok_AAAA1234bbbbCCCC"}
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

func TestValidate_PureLocal(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestIsHost_RejectsInvalidDNSLabels pins that the endpoint host validator
// rejects RFC 952/1123-invalid labels (leading/trailing hyphen, empty, or
// over-63-character labels), matching the wazuh/wrike sibling validators. The
// prior regex permitted trailing hyphens (e.g. "shop-test-.example.com") and
// did not enforce the 63-char label cap.
func TestIsHost_RejectsInvalidDNSLabels(t *testing.T) {
	longLabel := strings.Repeat("a", 64)
	cases := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"shop.example.co.uk", true},
		{"a-b.example.com", true},
		{"shop-test-.example.com", false}, // trailing hyphen
		{"-shop.example.com", false},      // leading hyphen
		{"abc-.example.com", false},       // trailing hyphen
		{"example-.com", false},
		{longLabel + ".example.com", false}, // label > 63 chars
		{"foo..example.com", false},         // empty label
		{"", false},
	}
	for _, tc := range cases {
		if got := isHost(tc.host); got != tc.want {
			t.Errorf("isHost(%q) = %v; want %v", tc.host, got, tc.want)
		}
	}
}

func TestValidate_RejectsInvalidHostLabel(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })
	cfg := map[string]interface{}{"endpoint": "https://shop-test-.example.com"}
	if err := New().Validate(context.Background(), cfg, validSecrets()); err == nil {
		t.Fatal("expected Validate to reject endpoint host with trailing-hyphen label")
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
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Basic ") {
			t.Errorf("expected Basic auth; got %q", got)
		}
		var arr []map[string]interface{}
		if calls == 1 {
			for i := 0; i < pageSize; i++ {
				arr = append(arr, map[string]interface{}{
					"id":         1000 + i,
					"email":      fmt.Sprintf("u%d@x.com", i),
					"first_name": fmt.Sprintf("U%d", i),
				})
			}
		} else {
			arr = []map[string]interface{}{{
				"id":         9999,
				"email":      "last@x.com",
				"first_name": "Last",
			}}
		}
		b, _ := json.Marshal(arr)
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
	got, _ := md["consumer_key_short"].(string)
	if !strings.Contains(got, "...") || strings.Contains(got, "AAAA1234") {
		t.Errorf("redaction failed: %q", got)
	}
}
