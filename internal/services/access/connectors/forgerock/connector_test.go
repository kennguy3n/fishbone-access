package forgerock

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
	return map[string]interface{}{"endpoint": "https://idm.corp.example"}
}
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "frAAAA1234bbbbCCCC"}
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

func TestSync_PaginatesUsers(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.URL.Query().Get("_queryFilter"); got != "true" {
			t.Errorf("_queryFilter = %q", got)
		}
		cookie := r.URL.Query().Get("_pagedResultsCookie")
		body := map[string]interface{}{}
		var arr []map[string]interface{}
		if calls == 1 {
			if cookie != "" {
				t.Errorf("first call cookie = %q", cookie)
			}
			for i := 0; i < pageSize; i++ {
				arr = append(arr, map[string]interface{}{
					"_id":           fmt.Sprintf("u%d", i),
					"userName":      fmt.Sprintf("user%d", i),
					"givenName":     fmt.Sprintf("Given%d", i),
					"sn":            "Family",
					"mail":          fmt.Sprintf("u%d@x.com", i),
					"accountStatus": "active",
				})
			}
			body["pagedResultsCookie"] = "next-page-cookie"
		} else {
			if cookie != "next-page-cookie" {
				t.Errorf("cookie = %q", cookie)
			}
			arr = []map[string]interface{}{{"_id": "ulast", "userName": "last", "givenName": "Last", "sn": "User", "mail": "last@x.com", "accountStatus": "inactive"}}
			body["pagedResultsCookie"] = ""
		}
		body["result"] = arr
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
	if got[len(got)-1].Status != "disabled" {
		t.Errorf("last user status = %q; want disabled", got[len(got)-1].Status)
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
