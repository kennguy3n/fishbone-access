package front

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

func TestFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	var srv *httptest.Server
	call := 0
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/events") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Errorf("auth missing")
		}
		switch call {
		case 0:
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"_results": []map[string]interface{}{
					{
						"id":         "evt-1",
						"type":       "assign",
						"emitted_at": 1704103200.0, // 2024-01-01T10:00:00Z
						"source": map[string]interface{}{
							"_data": map[string]interface{}{
								"id":    "actor-1",
								"email": "admin@example.com",
							},
						},
						"target": map[string]interface{}{
							"_meta": map[string]interface{}{"type": "conversation"},
							"_data": map[string]interface{}{"id": "conv-9"},
						},
					},
				},
				"_pagination": map[string]interface{}{
					"next": srv.URL + "/events?page=2&token=cursor-2",
				},
			})
		case 1:
			call++
			if r.URL.Query().Get("page") != "2" {
				t.Errorf("page = %s", r.URL.Query().Get("page"))
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"_results": []map[string]interface{}{
					{
						"id":         "evt-2",
						"type":       "comment",
						"emitted_at": 1704106800.0, // 2024-01-01T11:00:00Z
						"source": map[string]interface{}{
							"_data": map[string]interface{}{"id": "actor-2"},
						},
						"target": map[string]interface{}{
							"_meta": map[string]interface{}{"type": "comment"},
							"_data": map[string]interface{}{"id": "c-77"},
						},
					},
				},
				"_pagination": map[string]interface{}{},
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
	if collected[0].EventType != "assign" || collected[0].ActorEmail != "admin@example.com" || collected[0].TargetExternalID != "conv-9" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	want := time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC)
	if !lastSince.Equal(want) {
		t.Errorf("lastSince = %s, want %s", lastSince, want)
	}
}

func TestFetchAccessAuditLogs_ProviderError(t *testing.T) {
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
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
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
