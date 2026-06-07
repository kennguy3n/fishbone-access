package make

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

func TestSync_PaginatesUsers(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Token ") {
			t.Errorf("expected Token auth; got %q", got)
		}
		if r.URL.Path != "/api/v2/users" {
			t.Errorf("path = %q", r.URL.Path)
		}
		// Make uses pg[offset]/pg[limit]; r.URL.Query() URL-decodes the keys.
		off := r.URL.Query().Get("pg[offset]")
		if calls == 1 && off != "0" {
			t.Errorf("offset = %q", off)
		}
		if calls == 2 && off != fmt.Sprintf("%d", pageSize) {
			t.Errorf("offset = %q", off)
		}
		var arr []map[string]interface{}
		if calls == 1 {
			for i := 0; i < pageSize; i++ {
				arr = append(arr, map[string]interface{}{
					"id":    i + 1,
					"email": fmt.Sprintf("u%d@x.com", i),
					"name":  fmt.Sprintf("U%d", i),
				})
			}
		} else {
			arr = []map[string]interface{}{{"id": 9999, "email": "last@x.com", "name": "Last"}}
		}
		body := map[string]interface{}{"users": arr}
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
	got, _ := md["token_short"].(string)
	if !strings.Contains(got, "...") || strings.Contains(got, "AAAA1234") {
		t.Errorf("redaction failed: %q", got)
	}
}

// TestBaseURL_RegionAndOverride is a regression test for the configurable Make
// region/base URL. The endpoint was previously hardcoded to eu1.make.com, which
// locked out operators on us1/eu2/etc. baseURL must honor base_url, then region,
// then fall back to the eu1 default.
func TestBaseURL_RegionAndOverride(t *testing.T) {
	cases := []struct {
		name string
		raw  map[string]interface{}
		want string
	}{
		{"default eu1", map[string]interface{}{}, "https://eu1.make.com"},
		{"region us1", map[string]interface{}{"region": "us1"}, "https://us1.make.com"},
		{"region eu2", map[string]interface{}{"region": " eu2 "}, "https://eu2.make.com"},
		{"base_url override", map[string]interface{}{"base_url": "https://make.example.com/"}, "https://make.example.com"},
		{"base_url wins over region", map[string]interface{}{"base_url": "https://make.example.com", "region": "us1"}, "https://make.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := DecodeConfig(tc.raw)
			if err != nil {
				t.Fatalf("DecodeConfig: %v", err)
			}
			if got := (&MakeAccessConnector{}).baseURL(cfg); got != tc.want {
				t.Errorf("baseURL = %q; want %q", got, tc.want)
			}
		})
	}
}

// TestShortToken_NeverLeaksShortTokens is a regression test for the
// GetCredentialsMetadata contract: shortToken must never return an unredacted
// credential. The shared helper previously returned the full token verbatim for
// len<=8, leaking short keys into metadata surfaced in admin UIs and logs.
func TestShortToken_NeverLeaksShortTokens(t *testing.T) {
	for _, in := range []string{"a", "abc", "12345678", "123456789", "01234567890"} {
		got := shortToken(in)
		if got == in {
			t.Errorf("shortToken(%q) = %q; leaked raw value", in, got)
		}
		if strings.Contains(got, in) {
			t.Errorf("shortToken(%q) = %q; contains raw value", in, got)
		}
	}
	if got := shortToken(""); got != "" {
		t.Errorf("shortToken(\"\") = %q; want empty", got)
	}
	// Long tokens still get a useful first4...last4 hint with a hidden middle.
	if got := shortToken("tok_AAAA1234bbbbCCCC"); !strings.Contains(got, "...") || strings.Contains(got, "AAAA1234") {
		t.Errorf("shortToken(long) = %q; want redacted window", got)
	}
}

// TestValidate_RejectsInsecureBaseURL guards against a misconfigured base_url
// that would send the bearer token over plaintext http, or that isn't a valid
// absolute URL. Loopback http is tolerated for local dev/testing.
func TestValidate_RejectsInsecureBaseURL(t *testing.T) {
	for _, bad := range []string{
		"http://make.example.com", "ftp://make.example.com",
		"make.example.com", "://nohost", "https://",
	} {
		cfg := map[string]interface{}{"base_url": bad}
		if err := New().Validate(context.Background(), cfg, validSecrets()); err == nil {
			t.Errorf("Validate(base_url=%q) = nil; want error", bad)
		}
	}
	for _, ok := range []string{
		"https://make.example.com", "https://make.example.com/", "",
		"http://localhost:8080", "http://127.0.0.1:9000",
	} {
		cfg := map[string]interface{}{"base_url": ok}
		if err := New().Validate(context.Background(), cfg, validSecrets()); err != nil {
			t.Errorf("Validate(base_url=%q) = %v; want nil", ok, err)
		}
	}
}

// TestValidate_RejectsRegionThatLooksLikeURL guards the operator against putting
// a full URL — or any non-zone-label injection — in the region field, which
// would build a malformed host. The region is restricted to an
// alphanumeric+hyphen allowlist so only a single DNS label can be interpolated
// into https://{region}.make.com.
func TestValidate_RejectsRegionThatLooksLikeURL(t *testing.T) {
	for _, bad := range []string{
		"https://us1.make.com", "us1.make.com", "us1/extra",
		"eu1;DROP TABLE", "eu1 us1", "eu1_internal", "eu1@evil",
	} {
		cfg := map[string]interface{}{"region": bad}
		if err := New().Validate(context.Background(), cfg, validSecrets()); err == nil {
			t.Errorf("Validate(region=%q) = nil; want error", bad)
		}
	}
	// Valid zone labels must still pass.
	for _, ok := range []string{"eu1", "eu2", "us1", "us2", ""} {
		cfg := map[string]interface{}{"region": ok}
		if err := New().Validate(context.Background(), cfg, validSecrets()); err != nil {
			t.Errorf("Validate(region=%q) = %v; want nil", ok, err)
		}
	}
}
