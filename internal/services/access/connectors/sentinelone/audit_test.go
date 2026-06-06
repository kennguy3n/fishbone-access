package sentinelone

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/web/api/v2.1/activities") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "ApiToken ") {
			t.Errorf("missing ApiToken auth, got %q", auth)
		}
		calls++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("cursor") == "" {
			next := "cursor-2"
			_ = json.NewEncoder(w).Encode(sentineloneActivitiesResponse{
				Data: []sentineloneActivity{
					{
						ID:                 "a1",
						ActivityType:       27,
						ActivityTypeName:   "Login",
						PrimaryDescription: "User signed in",
						CreatedAt:          "2024-01-01T10:00:00.000000Z",
						UserEmail:          "alice@example.com",
						UserID:             "u1",
					},
				},
				Pagination: struct {
					NextCursor *string `json:"nextCursor"`
					TotalItems int     `json:"totalItems"`
				}{NextCursor: &next, TotalItems: 2},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(sentineloneActivitiesResponse{
			Data: []sentineloneActivity{
				{
					ID:                 "a2",
					ActivityType:       28,
					ActivityTypeName:   "Logout",
					PrimaryDescription: "User signed out",
					CreatedAt:          "2024-01-01T11:30:45Z",
					UserEmail:          "bob@example.com",
					UserID:             "u2",
				},
			},
		})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

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
	if calls != 2 {
		t.Errorf("calls = %d; want 2", calls)
	}
	if len(collected) != 2 {
		t.Fatalf("collected %d; want 2", len(collected))
	}
	if collected[0].EventType != "Login" || collected[0].ActorEmail != "alice@example.com" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].EventType != "Logout" || collected[1].ActorEmail != "bob@example.com" {
		t.Errorf("entry 1 = %+v", collected[1])
	}
}

// A provider that always returns a non-empty nextCursor must not loop
// forever: the auditMaxPages guard bounds the number of requests and the
// fetch returns nil so the persisted cursor lets the next run resume.
func TestFetchAccessAuditLogs_MaxPagesGuard(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		next := "always-more"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sentineloneActivitiesResponse{
			Data: []sentineloneActivity{{
				ID: "a", ActivityTypeName: "Login", CreatedAt: "2024-01-01T10:00:00Z",
			}},
			Pagination: struct {
				NextCursor *string `json:"nextCursor"`
				TotalItems int     `json:"totalItems"`
			}{NextCursor: &next},
		})
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		nil, func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if calls != auditMaxPages {
		t.Errorf("calls = %d; want %d (bounded by guard)", calls, auditMaxPages)
	}
}

func TestFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":[{"detail":"insufficient scope"}]}`))
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err != access.ErrAuditNotAvailable {
		t.Fatalf("err = %v; want ErrAuditNotAvailable", err)
	}
}

func TestFetchAccessAuditLogs_ProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"errors":[{"detail":"server boom"}]}`))
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		nil,
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected provider error")
	}
	if err == access.ErrAuditNotAvailable {
		t.Fatalf("err = ErrAuditNotAvailable; want generic error")
	}
}

func TestMapSentineloneActivity_TimestampParsing(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want time.Time
	}{
		{"rfc3339", "2024-01-01T10:00:00Z", time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)},
		{"rfc3339_nano", "2024-01-01T10:00:00.123456789Z", time.Date(2024, 1, 1, 10, 0, 0, 123456789, time.UTC)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mapSentineloneActivity(&sentineloneActivity{
				ID: "x", ActivityTypeName: "T", CreatedAt: tc.in,
			})
			if got == nil {
				t.Fatalf("nil entry")
			}
			if !got.Timestamp.Equal(tc.want) {
				t.Errorf("timestamp = %v; want %v", got.Timestamp, tc.want)
			}
		})
	}
}

// A non-empty but unparseable CreatedAt must not produce an entry with a
// zero Timestamp; the mapper drops it like every other audit mapper.
func TestMapSentineloneActivity_DropsUnparseableTimestamp(t *testing.T) {
	for _, in := range []string{"not-a-date", "2024/01/01 10:00:00", "0"} {
		if got := mapSentineloneActivity(&sentineloneActivity{
			ID: "x", ActivityTypeName: "T", CreatedAt: in,
		}); got != nil {
			t.Errorf("CreatedAt=%q: got %+v; want nil", in, got)
		}
	}
}
