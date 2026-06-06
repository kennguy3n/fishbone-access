package insightly

import (
	"context"
	"encoding/base64"
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

func validConfig() map[string]interface{} { return map[string]interface{}{"pod": "na1"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "ins_AAAA1234bbbbCCCC"}
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
	if err := c.Validate(context.Background(), map[string]interface{}{"pod": "bad pod"}, validSecrets()); err == nil {
		t.Error("invalid pod")
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
		hdr := r.Header.Get("Authorization")
		if !strings.HasPrefix(hdr, "Basic ") {
			t.Errorf("expected Basic auth, got %q", hdr)
		}
		if dec, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hdr, "Basic ")); err == nil {
			if !strings.HasSuffix(string(dec), ":") {
				t.Errorf("expected api_key:<empty>, got %q", string(dec))
			}
		}
		if r.URL.Path != "/v3.1/Users" {
			t.Errorf("path = %q", r.URL.Path)
		}
		skip := r.URL.Query().Get("skip")
		var arr []map[string]interface{}
		if calls == 1 {
			if skip != "0" {
				t.Errorf("skip = %q", skip)
			}
			for i := 0; i < pageSize; i++ {
				arr = append(arr, map[string]interface{}{"USER_ID": i + 1, "FIRST_NAME": fmt.Sprintf("U%d", i), "EMAIL_ADDRESS": fmt.Sprintf("u%d@x.com", i), "ACTIVE": true})
			}
		} else {
			if skip != fmt.Sprintf("%d", pageSize) {
				t.Errorf("skip = %q", skip)
			}
			arr = []map[string]interface{}{{"USER_ID": 999, "FIRST_NAME": "Last", "EMAIL_ADDRESS": "last@x.com", "ACTIVE": false}}
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
	if got[len(got)-1].Status != "inactive" {
		t.Errorf("status = %q", got[len(got)-1].Status)
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
