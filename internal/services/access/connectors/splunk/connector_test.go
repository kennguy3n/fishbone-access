package splunk

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
	return map[string]interface{}{"base_url": "https://acme.splunkcloud.com:8089"}
}
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "spkAAAA1234bbbbCCCC"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing base_url")
	}
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
		if r.URL.Path != "/services/authentication/users" {
			t.Errorf("path = %q", r.URL.Path)
		}
		offset := r.URL.Query().Get("offset")
		body := map[string]interface{}{"entry": []map[string]interface{}{}, "paging": map[string]interface{}{"total": pageSize + 1}}
		if calls == 1 && offset != "0" {
			t.Errorf("offset = %q", offset)
		}
		if calls == 2 && offset != fmt.Sprintf("%d", pageSize) {
			t.Errorf("offset = %q", offset)
		}
		if calls == 1 {
			res := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				res = append(res, map[string]interface{}{"name": fmt.Sprintf("user%d", i), "content": map[string]interface{}{"email": fmt.Sprintf("u%d@x.com", i), "realname": fmt.Sprintf("User %d", i), "locked-out": false}})
			}
			body["entry"] = res
		} else {
			body["entry"] = []map[string]interface{}{{"name": "lockout", "content": map[string]interface{}{"email": "lock@x.com", "realname": "Locked", "locked-out": true}}}
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
		t.Errorf("last status = %q", got[len(got)-1].Status)
	}
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

// TestSplunk_SyncIdentities_MaxPagesGuard verifies the defense-in-depth
// cap on pagination loops in SyncIdentities. A misconfigured / malicious
// upstream that returns a perpetually inflated paging.total combined
// with a non-empty page on every request would otherwise loop forever
// (the secondary next-empty guard never trips). The cap surfaces a
// clear error so the worker fails fast instead of hanging — same
// pattern the bot flagged + we applied in groups.go.
func TestSplunk_SyncIdentities_MaxPagesGuard(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"entry": []map[string]interface{}{
				{"name": "u", "content": map[string]interface{}{"email": "u@x.com", "realname": "U", "locked-out": false}},
			},
			"paging": map[string]interface{}{"total": 1 << 30, "perPage": 100, "offset": 0},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, _ string) error { return nil })
	if err == nil {
		t.Fatalf("err = nil; want pagination cap error")
	}
	if !strings.Contains(err.Error(), "pagination exceeded") {
		t.Errorf("err = %q; want 'pagination exceeded' surface", err.Error())
	}
	if callCount != splunkIdentitiesMaxPages {
		t.Errorf("callCount = %d; want %d", callCount, splunkIdentitiesMaxPages)
	}
}

// NOTE: the UTF-8 rune-boundary truncation and truncateAtRune
// precondition guards previously tested here now live with the shared
// scrubber in internal/services/access/httputil (see
// TestSafeErrorBody_TruncatesJSONAtRuneBoundary and
// TestTruncateAtRune_Boundaries). The connector reaches that logic via
// httputil.SafeErrorBody; the proxy-scrubbing behaviour of the error
// path is still exercised end-to-end in connector_flow_test.go.
