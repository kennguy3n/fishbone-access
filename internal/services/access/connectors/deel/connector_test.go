package deel

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
	return map[string]interface{}{"token": "deelAAAA1234bbbbCCCC"}
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
		if r.URL.Path != "/rest/v2/contracts" {
			t.Errorf("path = %q", r.URL.Path)
		}
		page := r.URL.Query().Get("page")
		if calls == 1 && page != "1" {
			t.Errorf("page = %q", page)
		}
		body := map[string]interface{}{"data": []map[string]interface{}{}, "page": map[string]interface{}{"page": calls, "page_size": pageSize, "total_pages": 2}}
		if calls == 1 {
			items := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				items = append(items, map[string]interface{}{"id": fmt.Sprintf("ct%d", i), "status": "active", "worker": map[string]interface{}{"id": fmt.Sprintf("w%d", i), "first_name": "User", "last_name": fmt.Sprintf("%d", i), "email": fmt.Sprintf("u%d@x.com", i)}})
			}
			body["data"] = items
		} else {
			body["data"] = []map[string]interface{}{{"id": "ctlast", "status": "ended", "worker": map[string]interface{}{"id": "wlast", "first_name": "Last", "last_name": "Worker", "email": "last@x.com"}}}
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
	if got[len(got)-1].Status != "ended" {
		t.Errorf("status = %q", got[len(got)-1].Status)
	}
}

// TestSync_PrefersActiveContractStatus guards against the regression
// where a worker holding several contracts inherited the status of
// whichever contract the API returned first. A still-active worker who
// also has an ended contract must be reported as active, otherwise the
// sync records a false loss of access. This covers both the in-page
// case (two contracts on the same page) and the cross-page case (the
// active contract arrives on a later page after the ended one).
func TestSync_PrefersActiveContractStatus(t *testing.T) {
	t.Run("within a page", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := map[string]interface{}{
				"page": map[string]interface{}{"page": 1, "page_size": pageSize, "total_pages": 1},
				"data": []map[string]interface{}{
					{"id": "ct-ended", "status": "ended", "worker": map[string]interface{}{"id": "w1", "first_name": "Ann", "last_name": "Lee", "email": "ann@x.com"}},
					{"id": "ct-active", "status": "active", "worker": map[string]interface{}{"id": "w1", "first_name": "Ann", "last_name": "Lee", "email": "ann@x.com"}},
				},
			}
			b, _ := json.Marshal(body)
			_, _ = w.Write(b)
		}))
		t.Cleanup(srv.Close)
		c := New()
		c.urlOverride = srv.URL
		c.httpClient = func() httpDoer { return srv.Client() }
		var got []*access.Identity
		if err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
			got = append(got, b...)
			return nil
		}); err != nil {
			t.Fatalf("Sync: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("len = %d, want 1 deduped identity", len(got))
		}
		if got[0].Status != "active" {
			t.Fatalf("status = %q, want active (active contract must win over ended)", got[0].Status)
		}
	})

	t.Run("across pages", func(t *testing.T) {
		calls := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			body := map[string]interface{}{"page": map[string]interface{}{"page": calls, "page_size": pageSize, "total_pages": 2}}
			if calls == 1 {
				body["data"] = []map[string]interface{}{{"id": "ct-ended", "status": "ended", "worker": map[string]interface{}{"id": "w1", "first_name": "Ann", "last_name": "Lee", "email": "ann@x.com"}}}
			} else {
				body["data"] = []map[string]interface{}{{"id": "ct-active", "status": "active", "worker": map[string]interface{}{"id": "w1", "first_name": "Ann", "last_name": "Lee", "email": "ann@x.com"}}}
			}
			b, _ := json.Marshal(body)
			_, _ = w.Write(b)
		}))
		t.Cleanup(srv.Close)
		c := New()
		c.urlOverride = srv.URL
		c.httpClient = func() httpDoer { return srv.Client() }
		var got []*access.Identity
		if err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
			got = append(got, b...)
			return nil
		}); err != nil {
			t.Fatalf("Sync: %v", err)
		}
		// The active contract on page 2 is re-emitted so the downstream
		// upsert can correct the worker's status to active.
		final := map[string]string{}
		for _, id := range got {
			final[id.ExternalID] = id.Status
		}
		if final["w1"] != "active" {
			t.Fatalf("final status = %q, want active", final["w1"])
		}
	})
}

func TestConnect_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
