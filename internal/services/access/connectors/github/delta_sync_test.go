package github

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func ghDeltaConfig() map[string]interface{}  { return map[string]interface{}{"organization": "acme"} }
func ghDeltaSecrets() map[string]interface{} { return map[string]interface{}{"access_token": "ghp_x"} }

func TestGitHub_SyncIdentitiesDelta_HappyPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/orgs/acme/audit-log") {
			t.Errorf("path=%q; want /orgs/acme/audit-log", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"@timestamp_documentId": "doc-1",
				"action":                "org.add_member",
				"actor":                 "admin",
				"user":                  "alice",
			},
			{
				"@timestamp_documentId": "doc-2",
				"action":                "org.remove_member",
				"actor":                 "admin",
				"user":                  "bob",
			},
		})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL

	var batch, removed int
	final, err := c.SyncIdentitiesDelta(context.Background(), ghDeltaConfig(), ghDeltaSecrets(), "",
		func(b []*access.Identity, r []string, _ string) error {
			batch += len(b)
			removed += len(r)
			return nil
		})
	if err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if batch != 1 || removed != 1 {
		t.Fatalf("batch=%d removed=%d; want 1 / 1", batch, removed)
	}
	if !strings.Contains(final, "after=doc-2") {
		t.Errorf("finalCursor=%q; want to contain after=doc-2", final)
	}
}

func TestGitHub_SyncIdentitiesDelta_ExpiredCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"cursor expired","errors":[{"code":"cursor_expired","message":"too old"}]}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL

	_, err := c.SyncIdentitiesDelta(context.Background(), ghDeltaConfig(), ghDeltaSecrets(),
		server.URL+"/orgs/acme/audit-log?after=stale",
		func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if !errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Fatalf("got %v; want ErrDeltaTokenExpired", err)
	}
}

func TestGitHub_SyncIdentitiesDelta_HTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL

	_, err := c.SyncIdentitiesDelta(context.Background(), ghDeltaConfig(), ghDeltaSecrets(), "",
		func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
	if errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Fatalf("got ErrDeltaTokenExpired on plain 500; want generic error: %v", err)
	}
}

func TestGitHub_InitialDeltaCursor_BuildsValidAuditLogURL(t *testing.T) {
	c := New()
	cursor, err := c.InitialDeltaCursor(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("InitialDeltaCursor: %v", err)
	}
	if !strings.HasPrefix(cursor, "https://api.github.com/orgs/acme/audit-log?") {
		t.Errorf("seeded cursor %q missing audit-log URL prefix", cursor)
	}
	u, perr := url.Parse(cursor)
	if perr != nil {
		t.Fatalf("seeded cursor %q is not a valid URL: %v", cursor, perr)
	}
	phrase := u.Query().Get("phrase")
	if !strings.Contains(phrase, "created:>") {
		t.Errorf("phrase %q missing created:> timestamp filter", phrase)
	}
	// http.NewRequest must accept the seed verbatim — this is the
	// SyncIdentitiesDelta contract.
	if _, rerr := http.NewRequest(http.MethodGet, cursor, nil); rerr != nil {
		t.Errorf("http.NewRequest(seed) failed: %v", rerr)
	}
}
