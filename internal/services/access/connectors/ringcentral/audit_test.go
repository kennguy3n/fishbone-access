package ringcentral

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestRingcentralFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/restapi/v1.0/account/~/audit-trail" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Errorf("auth header missing")
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{{
				"id":         "evt-1",
				"event_type": "user.created",
				"action":     "create",
				"timestamp":  "2024-09-01T10:00:00Z",
				"actor":      map[string]interface{}{"id": "u1", "email": "admin@example.com"},
				"target":     map[string]interface{}{"id": "u9", "type": "user"},
			}},
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
	if len(collected) != 1 || collected[0].ActorEmail != "admin@example.com" {
		t.Fatalf("collected = %+v", collected)
	}
	if !nextSince.Equal(time.Date(2024, 9, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("nextSince = %s", nextSince)
	}
}

func TestRingcentralFetchAccessAuditLogs_NotAvailable(t *testing.T) {
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

func TestRingcentralFetchAccessAuditLogs_TransientFailure(t *testing.T) {
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

// TestRingcentralFetchAccessAuditLogs_MultiPagePagination locks in that the
// `page` query parameter is incremented as a page number (1, 2, ...) rather
// than as a row offset (100, 200, ...). The first page returns a full page of
// events, which forces the connector to issue a second request — and that
// second request must use page=2, not page=ringcentralAuditPageSize.
func TestRingcentralFetchAccessAuditLogs_MultiPagePagination(t *testing.T) {
	var mu sync.Mutex
	var seenPages []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenPages = append(seenPages, r.URL.Query().Get("page"))
		mu.Unlock()
		page := r.URL.Query().Get("page")
		switch page {
		case "1":
			data := make([]map[string]interface{}, ringcentralAuditPageSize)
			for i := 0; i < ringcentralAuditPageSize; i++ {
				data[i] = map[string]interface{}{
					"id":         fmt.Sprintf("evt-p1-%d", i),
					"event_type": "user.created",
					"action":     "create",
					"timestamp":  "2024-09-01T10:00:00Z",
					"actor":      map[string]interface{}{"id": "u1", "email": "admin@example.com"},
					"target":     map[string]interface{}{"id": fmt.Sprintf("u%d", i), "type": "user"},
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{{
					"id":         "evt-p2-1",
					"event_type": "user.deleted",
					"action":     "delete",
					"timestamp":  "2024-09-02T10:00:00Z",
					"actor":      map[string]interface{}{"id": "u1", "email": "admin@example.com"},
					"target":     map[string]interface{}{"id": "u999", "type": "user"},
				}},
			})
		default:
			t.Errorf("unexpected page=%q (must be 1-indexed and contiguous)", page)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != ringcentralAuditPageSize+1 {
		t.Fatalf("collected = %d events, want %d", len(collected), ringcentralAuditPageSize+1)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seenPages) != 2 || seenPages[0] != "1" || seenPages[1] != "2" {
		t.Fatalf("seenPages = %v, want [1 2] — pagination is not advancing by page number", seenPages)
	}
}
