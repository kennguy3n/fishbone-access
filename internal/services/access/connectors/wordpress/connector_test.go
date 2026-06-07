package wordpress

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

func validConfig() map[string]interface{} { return map[string]interface{}{"site": "acme"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "tok_AAAA1234bbbbCCCC"}
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
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			t.Errorf("expected Bearer auth; got %q", got)
		}
		var arr []map[string]interface{}
		if calls == 1 {
			for i := 0; i < pageSize; i++ {
				arr = append(arr, map[string]interface{}{
					"ID":    1000 + i,
					"email": fmt.Sprintf("u%d@x.com", i),
					"name":  fmt.Sprintf("U%d", i),
				})
			}
		} else {
			arr = []map[string]interface{}{{
				"ID":    9999,
				"email": "last@x.com",
				"name":  "Last",
			}}
		}
		body := map[string]interface{}{
			"users": arr,
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

// TestSync_UsesOffsetPagination pins the WordPress.com /sites/$site/users
// pagination contract: the endpoint honours `number` + `offset` and has NO
// `page` parameter. A connector that paginates with `page` never advances the
// offset, so every request returns the same first page — re-emitting page 1
// forever (the loop only terminates because the server's runaway guard starts
// returning empty pages). This server emulates the real API (offset/number
// only) so the bug surfaces instead of being masked by a self-referential mock.
func TestSync_UsesOffsetPagination(t *testing.T) {
	const total = pageSize + 1
	users := make([]map[string]interface{}, total)
	for i := 0; i < total; i++ {
		users[i] = map[string]interface{}{
			"ID":    1000 + i,
			"email": fmt.Sprintf("u%d@x.com", i),
			"name":  fmt.Sprintf("U%d", i),
		}
	}
	calls := 0
	sawPageParam := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		q := r.URL.Query()
		if q.Get("page") != "" {
			sawPageParam = true
		}
		// Runaway guard: a connector stuck on offset 0 would loop forever.
		// Break it so assertions fail deterministically instead of hanging.
		if calls > 4 {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"users": []map[string]interface{}{}})
			return
		}
		offset, number := 0, 0
		_, _ = fmt.Sscanf(q.Get("offset"), "%d", &offset)
		_, _ = fmt.Sscanf(q.Get("number"), "%d", &number)
		page := []map[string]interface{}{}
		if offset < len(users) {
			end := offset + number
			if end > len(users) {
				end = len(users)
			}
			page = users[offset:end]
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"users": page})
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
	if sawPageParam {
		t.Errorf("connector sent unsupported `page` query param; WordPress.com /users paginates via number+offset")
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2 (offset 0 then offset %d)", calls, pageSize)
	}
	if len(got) != total {
		t.Fatalf("got %d identities, want %d (offset pagination must traverse all users exactly once)", len(got), total)
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
