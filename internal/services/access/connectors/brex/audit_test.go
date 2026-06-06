package brex

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestBrexFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/v2/audit_logs" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"items":[{"id":"a1","event_type":"role.change","action":"role.assigned","created_at":"2024-08-01T12:00:00Z","user_id":"u1","user_email":"u1@example.com","resource_id":"r1","outcome":"success"}],"page":1,"total_pages":1}`))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.AuditLogEntry
	var nextSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Time{}},
		func(batch []*access.AuditLogEntry, ns time.Time, _ string) error {
			got = batch
			nextSince = ns
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(got) != 1 || got[0].EventID != "a1" {
		t.Fatalf("got = %#v", got)
	}
	if !nextSince.Equal(time.Date(2024, 8, 1, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("nextSince = %v", nextSince)
	}
}

func TestBrexFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(), nil,
		func([]*access.AuditLogEntry, time.Time, string) error { return nil })
	if err != access.ErrAuditNotAvailable {
		t.Fatalf("err = %v; want ErrAuditNotAvailable", err)
	}
}

func TestBrexFetchAccessAuditLogs_TransientFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(), nil,
		func([]*access.AuditLogEntry, time.Time, string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v", err)
	}
}
