package loom

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
	return map[string]interface{}{"token": "loomAAAA1234bbbbCCCC"}
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
		if r.URL.Path != "/v1/members" {
			t.Errorf("path = %q", r.URL.Path)
		}
		cursor := r.URL.Query().Get("cursor")
		body := map[string]interface{}{}
		if calls == 1 {
			if cursor != "" {
				t.Errorf("first call cursor = %q", cursor)
			}
			body["data"] = []map[string]interface{}{
				{"id": "m1", "name": "Alice", "email": "a@x.com", "role": "admin", "status": "ACTIVE"},
			}
			body["next_cursor"] = "page2"
		} else {
			if cursor != "page2" {
				t.Errorf("second call cursor = %q", cursor)
			}
			body["data"] = []map[string]interface{}{
				{"id": "m2", "name": "Bob", "email": "b@x.com", "role": "member", "disabled": true},
			}
			body["next_cursor"] = ""
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
	if len(got) != 2 || calls != 2 {
		t.Fatalf("got=%d calls=%d", len(got), calls)
	}
	if got[1].Status != "disabled" {
		t.Errorf("status = %q", got[1].Status)
	}
	_ = fmt.Sprintf
}

// TestSync_PaginationCapped asserts SyncIdentities terminates with an error
// instead of looping forever when the server never clears next_cursor. Without
// the loomMembersMaxPages bound this test would hang.
func TestSync_PaginationCapped(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		body := map[string]interface{}{
			"data":        []map[string]interface{}{{"id": fmt.Sprintf("m%d", calls), "email": "x@y.com"}},
			"next_cursor": fmt.Sprintf("cursor-%d", calls),
		}
		b, _ := json.Marshal(body)
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func([]*access.Identity, string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "pagination exceeded") {
		t.Fatalf("err = %v; want pagination-exceeded error", err)
	}
	if calls != loomMembersMaxPages {
		t.Fatalf("calls = %d; want exactly %d (the cap)", calls, loomMembersMaxPages)
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
