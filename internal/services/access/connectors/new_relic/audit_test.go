package new_relic

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func nrAuditConfig() map[string]interface{} { return map[string]interface{}{"region": "us"} }
func nrAuditSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "NRAK-abcdef1234"}
}

func TestNewRelicFetchAccessAuditLogs_MapsAndCursorPages(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/graphql" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("API-Key") == "" {
			t.Errorf("API-Key empty")
		}
		var req struct {
			Query     string                 `json:"query"`
			Variables map[string]interface{} `json:"variables"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		body := map[string]interface{}{}
		if calls == 1 {
			if c := req.Variables["cursor"]; c != nil {
				t.Errorf("first cursor should be nil, got %v", c)
			}
			body["data"] = map[string]interface{}{"actor": map[string]interface{}{
				"organization": map[string]interface{}{
					"auditLogging": map[string]interface{}{
						"events": map[string]interface{}{
							"nextCursor": "page-2",
							"results": []map[string]interface{}{
								{
									"id":               "evt-1",
									"actionIdentifier": "user.invite",
									"createdAt":        "2024-04-01T11:00:00Z",
									"actor":            map[string]string{"id": "u-1", "email": "a@x.com", "type": "user"},
									"target":           map[string]string{"id": "u-9", "type": "user", "displayName": "newbie"},
									"outcome":          "success",
								},
							},
						},
					},
				},
			}}
		} else {
			if c, _ := req.Variables["cursor"].(string); c != "page-2" {
				t.Errorf("second cursor = %q", c)
			}
			body["data"] = map[string]interface{}{"actor": map[string]interface{}{
				"organization": map[string]interface{}{
					"auditLogging": map[string]interface{}{
						"events": map[string]interface{}{
							"nextCursor": "",
							"results": []map[string]interface{}{
								{
									"id":               "evt-2",
									"actionIdentifier": "user.delete",
									"createdAt":        "2024-04-01T10:00:00Z",
									"actor":            map[string]string{"id": "u-1", "email": "a@x.com"},
									"target":           map[string]string{"id": "u-9", "type": "user"},
								},
							},
						},
					},
				},
			}}
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var collected []*access.AuditLogEntry
	var nextSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), nrAuditConfig(), nrAuditSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 4, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, n time.Time, _ string) error {
			collected = append(collected, batch...)
			nextSince = n
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 2 {
		t.Fatalf("len = %d", len(collected))
	}
	// Reverse: oldest first → evt-2 then evt-1
	if collected[0].EventID != "evt-2" || collected[1].EventID != "evt-1" {
		t.Errorf("order = %s,%s", collected[0].EventID, collected[1].EventID)
	}
	want := time.Date(2024, 4, 1, 11, 0, 0, 0, time.UTC)
	if !nextSince.Equal(want) {
		t.Errorf("nextSince = %s, want %s", nextSince, want)
	}
	if calls != 2 {
		t.Errorf("calls = %d", calls)
	}
}

func TestNewRelicFetchAccessAuditLogs_NotAvailable_GraphQLError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"errors": []map[string]interface{}{
				{"message": "User not authorized for audit logging"},
			},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), nrAuditConfig(), nrAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want ErrAuditNotAvailable", err)
	}
}

func TestNewRelicFetchAccessAuditLogs_NotAvailable_HTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), nrAuditConfig(), nrAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want ErrAuditNotAvailable", err)
	}
}

func TestNewRelicFetchAccessAuditLogs_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), nrAuditConfig(), nrAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}
