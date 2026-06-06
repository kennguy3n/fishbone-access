package terraform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func tfAuditConfig() map[string]interface{} {
	return map[string]interface{}{"organization": "acme"}
}
func tfAuditSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "abc.terraform.token"}
}

func TestTerraformFetchAccessAuditLogs_MapsAndPaginates(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth header = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/api/v2/organization/acme/audit-trail" {
			t.Errorf("path = %s", r.URL.Path)
		}
		page := r.URL.Query().Get("page[number]")
		if r.URL.Query().Get("page[size]") != "100" {
			t.Errorf("page[size] = %q", r.URL.Query().Get("page[size]"))
		}
		body := map[string]interface{}{
			"meta": map[string]interface{}{
				"pagination": map[string]interface{}{
					"current-page": 1,
					"total-pages":  2,
				},
			},
		}
		if page == "1" {
			body["data"] = []map[string]interface{}{
				{
					"id":   "evt-1",
					"type": "audit_events",
					"attributes": map[string]interface{}{
						"action":    "create",
						"timestamp": "2024-02-01T10:00:00Z",
						"actor":     map[string]interface{}{"id": "user-a", "email": "a@example.com"},
						"target":    map[string]interface{}{"id": "ws-1", "type": "workspace"},
						"source":    map[string]interface{}{"ip": "203.0.113.10", "user-agent": "terraform-cli"},
					},
				},
			}
			body["meta"].(map[string]interface{})["pagination"].(map[string]interface{})["current-page"] = 1
		} else {
			if page != "2" {
				t.Errorf("page[number] = %q", page)
			}
			body["data"] = []map[string]interface{}{
				{
					"id":   "evt-2",
					"type": "audit_events",
					"attributes": map[string]interface{}{
						"action":    "delete",
						"timestamp": "2024-02-01T11:00:00Z",
						"actor":     map[string]interface{}{"id": "user-b"},
						"target":    map[string]interface{}{"id": "ws-2", "type": "workspace"},
					},
				},
			}
			body["meta"].(map[string]interface{})["pagination"].(map[string]interface{})["current-page"] = 2
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var collected []*access.AuditLogEntry
	var nextSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), tfAuditConfig(), tfAuditSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, n time.Time, _ string) error {
			collected = append(collected, batch...)
			nextSince = n
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 2 {
		t.Fatalf("len(collected) = %d", len(collected))
	}
	if collected[0].EventID != "evt-1" || collected[1].EventID != "evt-2" {
		t.Errorf("entries = %+v", collected)
	}
	if collected[0].TargetType != "workspace" {
		t.Errorf("target type = %q", collected[0].TargetType)
	}
	want := time.Date(2024, 2, 1, 11, 0, 0, 0, time.UTC)
	if !nextSince.Equal(want) {
		t.Errorf("nextSince = %s, want %s", nextSince, want)
	}
	if hits != 2 {
		t.Errorf("hits = %d, want 2", hits)
	}
}

func TestTerraformFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), tfAuditConfig(), tfAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want ErrAuditNotAvailable", err)
	}
}

func TestTerraformFetchAccessAuditLogs_ServerErrorDoesNotAdvance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"errors":[{"detail":"boom"}]}`)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	called := false
	err := c.FetchAccessAuditLogs(context.Background(), tfAuditConfig(), tfAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { called = true; return nil })
	if err == nil || errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want non-nil non-ErrAuditNotAvailable", err)
	}
	if called {
		t.Error("handler should not be called on full failure")
	}
}
