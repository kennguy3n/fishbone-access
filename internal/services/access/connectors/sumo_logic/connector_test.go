package sumo_logic

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

func validConfig() map[string]interface{} { return map[string]interface{}{"deployment": "us2"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"access_id": "smloAAAA1234bbbbCCCC", "access_key": "smkeAAAA1234bbbbDDDD"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{"access_id": "x"}); err == nil {
		t.Error("missing access_key")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{"access_key": "y"}); err == nil {
		t.Error("missing access_id")
	}
}

func TestValidate_RejectsInvalidDeployment(t *testing.T) {
	c := New()
	for _, bad := range []string{"us2.evil", "us2/x", "us 2"} {
		if err := c.Validate(context.Background(), map[string]interface{}{"deployment": bad}, validSecrets()); err == nil {
			t.Errorf("expected error for deployment %q", bad)
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
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("expected Basic auth")
		}
		if r.Header.Get("X-Sumo-Client") == "" {
			t.Errorf("missing X-Sumo-Client header")
		}
		if r.URL.Path != "/api/v1/users" {
			t.Errorf("path = %q", r.URL.Path)
		}
		offset := r.URL.Query().Get("offset")
		if calls == 1 && offset != "0" {
			t.Errorf("offset = %q", offset)
		}
		if calls == 2 && offset != fmt.Sprintf("%d", pageSize) {
			t.Errorf("offset = %q", offset)
		}
		body := map[string]interface{}{}
		if calls == 1 {
			items := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				items = append(items, map[string]interface{}{"id": fmt.Sprintf("u%d", i), "firstName": "User", "lastName": fmt.Sprintf("%d", i), "email": fmt.Sprintf("u%d@x.com", i), "isActive": true})
			}
			body["data"] = items
		} else {
			body["data"] = []map[string]interface{}{{"id": "ulocked", "firstName": "L", "lastName": "U", "email": "l@x.com", "isLocked": true}}
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
	if len(got) != pageSize+1 {
		t.Fatalf("len = %d", len(got))
	}
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
	if got[len(got)-1].Status != "locked" {
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
	md, err := New().GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	idShort, _ := md["id_short"].(string)
	keyShort, _ := md["key_short"].(string)
	if idShort == "" || strings.Contains(idShort, "AAAA1234") {
		t.Errorf("id_short = %q", idShort)
	}
	if keyShort == "" || strings.Contains(keyShort, "AAAA1234") {
		t.Errorf("key_short = %q", keyShort)
	}
}
