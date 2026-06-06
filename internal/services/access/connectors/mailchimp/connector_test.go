package mailchimp

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

func validConfig() map[string]interface{} { return map[string]interface{}{"list_id": "abc123def4"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "mcAAAA1234bbbbCCCC-us12"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing list_id")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing api_key")
	}
}

func TestValidate_RejectsKeyWithoutDatacenter(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{"api_key": "noDcSuffix"}); err == nil {
		t.Error("expected error for key without datacenter")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{"api_key": "trailing-"}); err == nil {
		t.Error("expected error for trailing dash")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{"api_key": "abc-bad/dc"}); err == nil {
		t.Error("expected error for invalid dc characters")
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
		if !strings.Contains(r.URL.Path, "/3.0/lists/") || !strings.HasSuffix(r.URL.Path, "/members") {
			t.Errorf("path = %q", r.URL.Path)
		}
		offset := r.URL.Query().Get("offset")
		body := map[string]interface{}{"list_id": "abc123def4", "total_items": pageSize + 1}
		if calls == 1 {
			if offset != "0" {
				t.Errorf("offset = %q", offset)
			}
			items := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				items = append(items, map[string]interface{}{"id": fmt.Sprintf("m%d", i), "email_address": fmt.Sprintf("u%d@x.com", i), "full_name": "User", "status": "subscribed"})
			}
			body["members"] = items
		} else {
			if offset != fmt.Sprintf("%d", pageSize) {
				t.Errorf("offset = %q want %d", offset, pageSize)
			}
			body["members"] = []map[string]interface{}{{"id": "mlast", "email_address": "last@x.com", "full_name": "Last", "status": "unsubscribed"}}
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
	if len(got) != pageSize+1 || calls != 2 {
		t.Fatalf("got=%d calls=%d", len(got), calls)
	}
	if got[len(got)-1].Status != "unsubscribed" {
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
	short, _ := md["key_short"].(string)
	if short == "" || strings.Contains(short, "AAAA1234") {
		t.Errorf("key_short = %q", short)
	}
	if md["datacenter"] != "us12" {
		t.Errorf("datacenter = %v", md["datacenter"])
	}
}
