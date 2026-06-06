package docker_hub

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func dockerAuditConfig() map[string]interface{} {
	return map[string]interface{}{"organization": "acme"}
}
func dockerAuditSecrets() map[string]interface{} {
	return map[string]interface{}{"username": "u", "password": "p"}
}

func TestDockerHubFetchAccessAuditLogs_MapsAndPaginates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/users/login":
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "jwt.token.value"})
		case "/v2/auditlogs/acme/":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "JWT ") {
				t.Errorf("auth header = %q", r.Header.Get("Authorization"))
			}
			page := r.URL.Query().Get("page")
			body := map[string]interface{}{}
			if page == "1" {
				body["next"] = "https://hub.docker.com/v2/auditlogs/acme/?page=2"
				body["logs"] = []map[string]interface{}{
					{
						"action":    "repo.create",
						"actor":     "alice",
						"data":      map[string]string{"repository": "acme/alpha"},
						"account":   "alice",
						"timestamp": "2024-02-02T09:00:00Z",
					},
				}
			} else {
				if page != "2" {
					t.Errorf("page = %q", page)
				}
				body["next"] = ""
				body["logs"] = []map[string]interface{}{
					{
						"action":    "team.member.added",
						"actor":     "alice",
						"data":      map[string]string{"team": "developers", "member": "bob"},
						"account":   "alice",
						"timestamp": "2024-02-02T10:00:00Z",
					},
				}
			}
			_ = json.NewEncoder(w).Encode(body)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var collected []*access.AuditLogEntry
	var nextSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), dockerAuditConfig(), dockerAuditSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, n time.Time, _ string) error {
			collected = append(collected, batch...)
			nextSince = n
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 2 {
		t.Fatalf("len = %d", len(collected))
	}
	if collected[0].Action != "repo.create" {
		t.Errorf("entry 0 action = %q", collected[0].Action)
	}
	if collected[1].TargetType != "member" || collected[1].TargetExternalID != "bob" {
		t.Errorf("entry 1 target = %q/%q", collected[1].TargetType, collected[1].TargetExternalID)
	}
	want := time.Date(2024, 2, 2, 10, 0, 0, 0, time.UTC)
	if !nextSince.Equal(want) {
		t.Errorf("nextSince = %s, want %s", nextSince, want)
	}
}

func TestDockerHubFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/users/login":
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "jwt"})
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), dockerAuditConfig(), dockerAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want ErrAuditNotAvailable", err)
	}
}

func TestDockerHubFetchAccessAuditLogs_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/users/login":
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "jwt"})
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	called := false
	err := c.FetchAccessAuditLogs(context.Background(), dockerAuditConfig(), dockerAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { called = true; return nil })
	if err == nil || errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want non-nil non-ErrAuditNotAvailable", err)
	}
	if called {
		t.Error("handler should not be called on full failure")
	}
}
