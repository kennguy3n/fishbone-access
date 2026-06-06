package apollo

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

func TestApolloFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/activities" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"activities": []map[string]interface{}{{
				"id":         "act-1",
				"type":       "email",
				"action":     "sent",
				"updated_at": "2024-09-01T10:00:00Z",
				"user_id":    "u-1",
				"user_email": "rep@example.com",
				"contact_id": "c-1",
			}},
			"pagination": map[string]interface{}{"page": 1, "per_page": 100, "total_pages": 1, "total_count": 1},
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
	if len(collected) != 1 || collected[0].EventID != "act-1" {
		t.Fatalf("collected = %+v", collected)
	}
	if !nextSince.Equal(time.Date(2024, 9, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("nextSince = %s", nextSince)
	}
}

func TestApolloFetchAccessAuditLogs_NotAvailable(t *testing.T) {
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

func TestApolloFetchAccessAuditLogs_TransientFailure(t *testing.T) {
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
