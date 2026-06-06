package slack

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
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/audit/v1/logs") {
			t.Errorf("path = %s", r.URL.Path)
		}
		switch call {
		case 0:
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"entries": []map[string]interface{}{
					{
						"id":          "e-1",
						"date_create": 1704110400,
						"action":      "user_login",
						"actor":       map[string]interface{}{"type": "user", "user": map[string]interface{}{"id": "U1", "email": "alice@corp.example"}},
						"entity":      map[string]interface{}{"type": "user", "user": map[string]interface{}{"id": "U1"}},
						"context":     map[string]interface{}{"ip_address": "203.0.113.1"},
					},
				},
				"response_metadata": map[string]interface{}{"next_cursor": "c2"},
			})
		case 1:
			if r.URL.Query().Get("cursor") != "c2" {
				t.Errorf("cursor = %s", r.URL.Query().Get("cursor"))
			}
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"entries": []map[string]interface{}{
					{
						"id":          "e-2",
						"date_create": 1704114000,
						"action":      "channel_created",
						"actor":       map[string]interface{}{"type": "user", "user": map[string]interface{}{"id": "U2"}},
						"entity":      map[string]interface{}{"type": "channel", "channel": map[string]interface{}{"id": "C1"}},
					},
				},
				"response_metadata": map[string]interface{}{"next_cursor": ""},
			})
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), nil, validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 2 {
		t.Fatalf("len = %d", len(collected))
	}
	if collected[1].TargetType != "channel" || collected[1].TargetExternalID != "C1" {
		t.Errorf("entry 1 target = %s/%s", collected[1].TargetType, collected[1].TargetExternalID)
	}
}

func TestFetchAccessAuditLogs_NotEnterprise(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "team_not_eligible"})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), nil, validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want ErrAuditNotAvailable", err)
	}
}
