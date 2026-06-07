package ovhcloud

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

func ovhAuditConfig() map[string]interface{} {
	return map[string]interface{}{"endpoint": "eu"}
}
func ovhAuditSecrets() map[string]interface{} {
	return map[string]interface{}{
		"application_key":    "app",
		"application_secret": "secret",
		"consumer_key":       "consumer",
	}
}

func TestOVHcloudFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Ovh-Application") == "" {
			t.Errorf("missing X-Ovh-Application")
		}
		switch {
		case r.URL.Path == "/me/api/logs/self":
			_ = json.NewEncoder(w).Encode([]int{42, 43})
		case strings.HasPrefix(r.URL.Path, "/me/api/logs/self/"):
			id := strings.TrimPrefix(r.URL.Path, "/me/api/logs/self/")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      id,
				"date":    "2024-09-01T10:00:0" + id[len(id)-1:] + "Z",
				"method":  "GET",
				"url":     "/me/identity/user/" + id,
				"status":  200,
				"ip":      "203.0.113.1",
				"account": "admin@example.com",
			})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2024, 9, 1, 11, 0, 0, 0, time.UTC) }
	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), ovhAuditConfig(), ovhAuditSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 2 || collected[0].IPAddress != "203.0.113.1" {
		t.Fatalf("collected = %+v", collected)
	}
}

func TestOVHcloudFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2024, 9, 1, 11, 0, 0, 0, time.UTC) }
	err := c.FetchAccessAuditLogs(context.Background(), ovhAuditConfig(), ovhAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestNewestOVHAuditIDs_KeepsNewestAscending(t *testing.T) {
	in := []json.Number{"5", "1", "9", "3", "7"}
	got := newestOVHAuditIDs(in, 3)
	// Newest 3 by numeric value are 5,7,9, returned ascending.
	want := []string{"5", "7", "9"}
	if len(got) != len(want) {
		t.Fatalf("len = %d; want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("got[%d] = %s; want %s (%v)", i, got[i].String(), want[i], got)
		}
	}
}

func TestNewestOVHAuditIDs_NoCapWhenUnderLimit(t *testing.T) {
	in := []json.Number{"2", "10", "1"}
	got := newestOVHAuditIDs(in, 500)
	want := []string{"1", "2", "10"}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("got[%d] = %s; want %s (%v)", i, got[i].String(), want[i], got)
		}
	}
}
