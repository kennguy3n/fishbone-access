package jira

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
		if !strings.HasPrefix(r.URL.Path, "/admin/v1/orgs/org-123/events") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		switch call {
		case 0:
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"id":   "evt-1",
						"type": "audit",
						"attributes": map[string]interface{}{
							"time":   "2024-01-01T10:00:00.123Z",
							"action": "user.invited",
							"actor": map[string]interface{}{
								"id":    "actor-1",
								"email": "admin@example.com",
							},
							"context": []map[string]interface{}{
								{"id": "user-9", "type": "user"},
							},
							"location": map[string]interface{}{
								"ip":        "203.0.113.5",
								"userAgent": "ua-1",
							},
						},
					},
				},
				"links": map[string]interface{}{
					"next": fmt.Sprintf("%s/admin/v1/orgs/org-123/events?from=cursor2", serverURL),
				},
			})
		case 1:
			call++
			if r.URL.RawQuery != "from=cursor2" {
				t.Errorf("page2 query = %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"id":   "evt-2",
						"type": "audit",
						"attributes": map[string]interface{}{
							"time":   "2024-01-01T11:00:00Z",
							"action": "policy.updated",
							"actor": map[string]interface{}{
								"id": "actor-2",
							},
						},
					},
				},
				"links": map[string]interface{}{},
			})
		default:
			t.Errorf("unexpected call %d", call)
		}
	}))
	t.Cleanup(srv.Close)
	serverURL = srv.URL

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	cfg := validConfig()
	cfg["org_id"] = "org-123"

	var collected []*access.AuditLogEntry
	var lastSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), cfg, validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error {
			if partitionKey != access.DefaultAuditPartition {
				t.Errorf("partitionKey = %q", partitionKey)
			}
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
	if collected[0].EventType != "user.invited" || collected[0].TargetExternalID != "user-9" || collected[0].IPAddress != "203.0.113.5" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[0].Timestamp.IsZero() {
		t.Errorf("entry 0 timestamp is zero")
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
	cfg := validConfig()
	cfg["org_id"] = "org-123"
	err := c.FetchAccessAuditLogs(context.Background(), cfg, validSecrets(),
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
	cfg := validConfig()
	cfg["org_id"] = "org-123"
	err := c.FetchAccessAuditLogs(context.Background(), cfg, validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want ErrAuditNotAvailable", err)
	}
}

func TestFetchAccessAuditLogs_MissingOrgID(t *testing.T) {
	c := New()
	// No urlOverride needed — should short-circuit before any HTTP call.
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want ErrAuditNotAvailable", err)
	}
}

// TestMapJiraAuditEvent_DropsZeroTimestamp is a regression guard for the missing
// zero-timestamp drop in mapJiraAuditEvent. An Atlassian audit record whose
// `time` is absent or unparseable must be dropped rather than emitted with a
// 0001-01-01 timestamp; the latter pollutes the audit stream with bogus
// zero-time entries (and, on watermark cursors that don't use strict After()
// semantics, can stall forward progress). Mirrors the guard already present in
// the sibling connectors' audit mappers.
func TestMapJiraAuditEvent_DropsZeroTimestamp(t *testing.T) {
	e := &jiraAuditEvent{ID: "evt-1"}
	e.Attributes.Action = "user_login"
	// Empty Time -> parseJiraTime returns the zero value -> must be dropped.
	if got := mapJiraAuditEvent(e); got != nil {
		t.Fatalf("mapJiraAuditEvent with empty time = %+v; want nil", got)
	}
	// An unparseable timestamp must also be dropped.
	e.Attributes.Time = "not-a-timestamp"
	if got := mapJiraAuditEvent(e); got != nil {
		t.Fatalf("mapJiraAuditEvent with bad time = %+v; want nil", got)
	}
	// Sanity: a well-formed event is still mapped with a non-zero timestamp.
	e.Attributes.Time = "2023-11-14T22:13:20Z"
	if got := mapJiraAuditEvent(e); got == nil || got.Timestamp.IsZero() {
		t.Fatalf("mapJiraAuditEvent with valid time returned nil/zero ts: %+v", got)
	}
}
