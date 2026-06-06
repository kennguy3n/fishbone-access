package salesloft

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
	return map[string]interface{}{"token": "slfAAAA1234bbbbCCCC"}
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
		if r.URL.Path != "/v2/users" {
			t.Errorf("path = %q", r.URL.Path)
		}
		page := r.URL.Query().Get("page")
		body := map[string]interface{}{}
		if calls == 1 {
			if page != "1" {
				t.Errorf("page = %q", page)
			}
			items := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				items = append(items, map[string]interface{}{"id": i + 1, "name": fmt.Sprintf("U%d", i), "email": fmt.Sprintf("u%d@x.com", i), "active": true})
			}
			body["data"] = items
			body["metadata"] = map[string]interface{}{"paging": map[string]interface{}{"current_page": 1, "next_page": 2, "per_page": pageSize}}
		} else {
			if page != "2" {
				t.Errorf("page = %q", page)
			}
			body["data"] = []map[string]interface{}{{"id": 999, "name": "Last", "email": "last@x.com", "active": false, "locked": true}}
			body["metadata"] = map[string]interface{}{"paging": map[string]interface{}{"current_page": 2, "per_page": pageSize}}
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

// TestSync_CheckpointTracksLocalCursor verifies that the checkpoint emitted
// to the handler always corresponds to the page the loop will fetch next
// (i.e. page+1) — never the API's reported `metadata.paging.next_page` value,
// which can disagree and would otherwise cause page skipping on resume.
func TestSync_CheckpointTracksLocalCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		body := map[string]interface{}{}
		if page == "1" {
			items := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				items = append(items, map[string]interface{}{"id": i, "name": "U", "email": fmt.Sprintf("u%d@x.com", i), "active": true})
			}
			body["data"] = items
			// Server reports a wildly out-of-band next_page so we can
			// prove the connector ignores it for checkpoint emission.
			body["metadata"] = map[string]interface{}{"paging": map[string]interface{}{"current_page": 1, "next_page": 99, "per_page": pageSize}}
		} else {
			body["data"] = []map[string]interface{}{}
			body["metadata"] = map[string]interface{}{"paging": map[string]interface{}{"current_page": 2, "per_page": pageSize}}
		}
		b, _ := json.Marshal(body)
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var seen []string
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, next string) error {
		seen = append(seen, next)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(seen) != 2 {
		t.Fatalf("emitted %d checkpoints, want 2: %v", len(seen), seen)
	}
	if seen[0] != "2" {
		t.Errorf("checkpoint after page 1 = %q, want %q (local cursor, not API next_page=99)", seen[0], "2")
	}
	if seen[1] != "" {
		t.Errorf("final checkpoint = %q, want empty", seen[1])
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
