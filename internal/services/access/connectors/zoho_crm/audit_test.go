package zoho_crm

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

func TestZohoCRMFetchAccessAuditLogs_MapsAndPaginates(t *testing.T) {
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/settings/audit_log") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Zoho-oauthtoken ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		switch call {
		case 0:
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"audit_log": []map[string]interface{}{
					{
						"id":           "evt-1",
						"action":       "added",
						"module":       "Users",
						"audited_time": "2024-01-01T10:00:00Z",
						"done_by":      map[string]interface{}{"id": "u-1", "email": "admin@example.com"},
						"record_id":    "u-9",
						"ip_address":   "203.0.113.1",
					},
				},
				"info": map[string]interface{}{"per_page": 200, "page": 1, "more_records": true},
			})
		case 1:
			call++
			if r.URL.Query().Get("page") != "2" {
				t.Errorf("page = %s", r.URL.Query().Get("page"))
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"audit_log": []map[string]interface{}{
					{
						"id":           "evt-2",
						"action":       "deleted",
						"module":       "Contacts",
						"audited_time": "2024-01-01T11:00:00Z",
						"done_by":      map[string]interface{}{"id": "u-1"},
						"record_id":    "c-5",
					},
				},
				"info": map[string]interface{}{"per_page": 200, "page": 2, "more_records": false},
			})
		default:
			t.Errorf("unexpected call %d", call)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	var lastSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, nextSince time.Time, _ string) error {
			collected = append(collected, batch...)
			lastSince = nextSince
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 2 {
		t.Fatalf("len = %d", len(collected))
	}
	if collected[0].EventType != "Users.added" {
		t.Errorf("entry 0 event_type = %s", collected[0].EventType)
	}
	want := time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC)
	if !lastSince.Equal(want) {
		t.Errorf("lastSince = %s, want %s", lastSince, want)
	}
}

func TestZohoCRMFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want ErrAuditNotAvailable", err)
	}
}

func TestZohoCRMFetchAccessAuditLogs_NoContent_IsNotAudit(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	handlerCalls := 0
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error {
			handlerCalls++
			return nil
		})
	if err != nil {
		t.Fatalf("err = %v, want nil (204 is a successful empty batch)", err)
	}
	if errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("204 must not be treated as ErrAuditNotAvailable")
	}
	if calls != 1 {
		t.Fatalf("expected 1 HTTP call before exit, got %d", calls)
	}
	if handlerCalls != 0 {
		t.Fatalf("handler must not be invoked for an empty (204) response, got %d calls", handlerCalls)
	}
}

func TestZohoCRMFetchAccessAuditLogs_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want non-nil non-ErrAuditNotAvailable", err)
	}
}
