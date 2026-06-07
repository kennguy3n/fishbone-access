package wordpress

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

func TestWordPressFetchAccessAuditLogs_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/rest/v1.1/sites/") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			t.Errorf("auth = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"current": map[string]interface{}{
				"orderedItems": []map[string]interface{}{{
					"activity_id": "act-1",
					"name":        "user__invited",
					"published":   "2024-05-01T12:00:00Z",
					"status":      "success",
					"actor":       map[string]interface{}{"wpcom_user_id": "42", "email": "admin@example.com"},
					"object":      map[string]interface{}{"type": "user", "object_id": "100"},
				}},
			},
		})
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
	if len(collected) != 1 || collected[0].ActorEmail != "admin@example.com" {
		t.Fatalf("collected = %+v", collected)
	}
}

func TestWordPressFetchAccessAuditLogs_NotAvailable(t *testing.T) {
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

func TestWordPressFetchAccessAuditLogs_TransientFailure(t *testing.T) {
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

// TestMapWordPressActivity_AcceptsSubsecondTimestamp pins that activity
// entries carrying fractional-second timestamps (and non-UTC offsets) are
// retained — not silently dropped — and are normalized to UTC. Go's
// time.Parse accepts a fractional second after the seconds field even when
// the RFC3339 layout omits it, so subsecond precision parses correctly.
func TestMapWordPressActivity_AcceptsSubsecondTimestamp(t *testing.T) {
	cases := []struct {
		name      string
		published string
		wantUnix  int64
	}{
		{"subsecond-zulu", "2024-05-01T12:00:00.123Z", time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC).Unix()},
		{"subsecond-offset", "2024-05-01T17:00:00.123456+05:00", time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC).Unix()},
		{"no-subsecond", "2024-05-01T12:00:00Z", time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC).Unix()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry := mapWordPressActivity(&wpActivityEntry{
				ActivityID:  "act-1",
				Name:        "user__invited",
				PublishedAt: tc.published,
				Status:      "success",
			})
			if entry == nil {
				t.Fatalf("entry dropped for timestamp %q (subsecond precision must be retained)", tc.published)
			}
			if entry.Timestamp.Location() != time.UTC {
				t.Fatalf("timestamp location = %v; want UTC", entry.Timestamp.Location())
			}
			if entry.Timestamp.Unix() != tc.wantUnix {
				t.Fatalf("timestamp = %v (unix %d); want unix %d", entry.Timestamp, entry.Timestamp.Unix(), tc.wantUnix)
			}
		})
	}
}

func TestWordPressFetchAccessAuditLogs_InvalidSecrets(t *testing.T) {
	c := New()
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(),
		map[string]interface{}{},
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v; want secrets validation error", err)
	}
}
