package klaviyo

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestKlaviyoFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/account-activity-logs" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Klaviyo-API-Key ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{{
				"type": "account-activity-log",
				"id":   "aal-1",
				"attributes": map[string]interface{}{
					"datetime":   "2024-09-01T10:00:00Z",
					"event_type": "user.login",
					"action":     "login",
					"actor_id":   "u-1",
					"actor_name": "ada@example.com",
					"ip_address": "10.0.0.1",
				},
			}},
			"links": map[string]string{"next": ""},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	var nextSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, n time.Time, _ string) error {
			collected = append(collected, batch...)
			nextSince = n
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 || collected[0].ActorEmail != "ada@example.com" {
		t.Fatalf("collected = %+v", collected)
	}
	if !nextSince.Equal(time.Date(2024, 9, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("nextSince = %s", nextSince)
	}
}

func TestKlaviyoFetchAccessAuditLogs_PaginatesByCursor(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		switch n {
		case 1:
			if r.URL.Query().Get("page[cursor]") != "" {
				t.Errorf("call 1 cursor = %q", r.URL.Query().Get("page[cursor]"))
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{{
					"type": "account-activity-log",
					"id":   "aal-1",
					"attributes": map[string]interface{}{
						"datetime": "2024-09-01T10:00:00Z",
						"action":   "login",
					},
				}},
				"links": map[string]string{"next": "/api/account-activity-logs?page%5Bcursor%5D=cur2"},
			})
		case 2:
			if r.URL.Query().Get("page[cursor]") != "cur2" {
				t.Errorf("call 2 cursor = %q", r.URL.Query().Get("page[cursor]"))
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{{
					"type": "account-activity-log",
					"id":   "aal-2",
					"attributes": map[string]interface{}{
						"datetime": "2024-09-01T11:00:00Z",
						"action":   "logout",
					},
				}},
				"links": map[string]string{"next": ""},
			})
		default:
			t.Errorf("unexpected call %d", n)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{}, func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 2 {
		t.Fatalf("len = %d", len(collected))
	}
}

func TestKlaviyoFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestKlaviyoFetchAccessAuditLogs_TransientFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v", err)
	}
}
