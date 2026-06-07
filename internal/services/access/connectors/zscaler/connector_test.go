package zscaler

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
	return map[string]interface{}{"token": "zs_AAAA1234bbbbCCCC"}
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
		if r.URL.Path != "/api/v1/adminUsers" {
			t.Errorf("path = %q", r.URL.Path)
		}
		page := r.URL.Query().Get("page")
		body := map[string]interface{}{}
		var arr []map[string]interface{}
		if calls == 1 {
			if page != "1" {
				t.Errorf("page = %q", page)
			}
			for i := 0; i < pageSize; i++ {
				// Zscaler ZIA returns numeric admin ids.
				arr = append(arr, map[string]interface{}{"id": i, "email": fmt.Sprintf("u%d@x.com", i), "userName": fmt.Sprintf("U%d", i)})
			}
		} else {
			if page != "2" {
				t.Errorf("page = %q", page)
			}
			arr = []map[string]interface{}{{"id": 9999, "email": "last@x.com", "userName": "Last"}}
		}
		body["data"] = arr
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

// TestSync_NumericIDs is a regression test for a decode bug: the real
// Zscaler ZIA /api/v1/adminUsers endpoint returns `id` as a JSON number
// (e.g. 7355487), not a quoted string. When zscalerUser.ID was typed as
// `string`, json.Unmarshal failed with "cannot unmarshal number into Go
// struct field ... of type string", aborting the entire sync. Decoding as
// json.Number and stringifying preserves the numeric id as ExternalID.
func TestSync_NumericIDs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":7355487,"email":"admin@x.com","userName":"Admin"}]}`))
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
		t.Fatalf("Sync with numeric id: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d identities, want 1", len(got))
	}
	if got[0].ExternalID != "7355487" {
		t.Errorf("ExternalID = %q, want %q", got[0].ExternalID, "7355487")
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
	got, _ := md["token_short"].(string)
	if !strings.Contains(got, "...") || strings.Contains(got, "AAAA1234") {
		t.Errorf("redaction failed: %q", got)
	}
}
