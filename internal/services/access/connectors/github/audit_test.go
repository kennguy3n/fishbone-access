package github

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

func TestFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	var serverURL string
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/orgs/acme/audit-log") {
			t.Errorf("path = %s", r.URL.Path)
		}
		switch call {
		case 0:
			call++
			w.Header().Set("Link", fmt.Sprintf(`<%s/orgs/acme/audit-log?page=2>; rel="next"`, defaultBaseURL))
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"_document_id": "doc-1",
					"action":       "org.add_member",
					"actor":        "alice",
					"actor_id":     1,
					"created_at":   1704110400000,
					"actor_ip":     "203.0.113.1",
					"user":         "bob",
				},
			})
		case 1:
			if r.URL.Query().Get("page") != "2" {
				t.Errorf("page = %s", r.URL.Query().Get("page"))
			}
			call++
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"_document_id": "doc-2",
					"action":       "team.add_member",
					"actor":        "carol",
					"created_at":   1704114000000,
					"team":         "platform",
				},
			})
		}
		_ = serverURL
	}))
	t.Cleanup(srv.Close)
	serverURL = srv.URL

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
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
	if collected[0].TargetType != "user" || collected[0].TargetExternalID != "bob" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].TargetType != "team" || collected[1].TargetExternalID != "platform" {
		t.Errorf("entry 1 = %+v", collected[1])
	}
}

func TestFetchAccessAuditLogs_NotEligible(t *testing.T) {
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
