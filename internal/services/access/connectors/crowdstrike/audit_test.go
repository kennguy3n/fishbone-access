package crowdstrike

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "tok", "expires_in": 3600, "token_type": "bearer",
			})
		case "/user-management/queries/user-login-history/v1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"resources": []string{"uuid-1"},
				"meta": map[string]interface{}{
					"pagination": map[string]interface{}{"offset": 0, "limit": 200, "total": 1},
				},
			})
		case "/user-management/entities/user-login-history/v1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"resources": []map[string]interface{}{
					{
						"UUID": "uuid-1",
						"uid":  "alice@example.com",
						"user_logins": []map[string]interface{}{
							{"user_uuid": "uuid-1", "login_time": "2024-01-01T10:00:00Z", "success": true},
							{"user_uuid": "uuid-1", "login_time": "2024-01-01T11:00:00Z", "success": false},
						},
					},
				},
			})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
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
	if len(collected) != 2 {
		t.Fatalf("len = %d", len(collected))
	}
	if collected[0].Outcome != "success" || collected[0].ActorEmail != "alice@example.com" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].Outcome != "failure" {
		t.Errorf("entry 1 outcome = %q; want failure", collected[1].Outcome)
	}
}

func TestFetchAccessAuditLogs_Forbidden_SoftSkip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "expires_in": 3600})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":[{"code":403}]}`))
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

// TestFetchAccessAuditLogs_SoftSkipStatuses guards against the
// regression where audit-not-available detection matched the literal
// string "status 403" in the formatted error. The soft-skip set is
// 401/403/404 (docs/architecture.md §2); a 401 (expired token) or 404
// must also map to ErrAuditNotAvailable rather than a hard error, and
// the check must be on the typed httpError status, not the error text.
func TestFetchAccessAuditLogs_SoftSkipStatuses(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth2/token" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "expires_in": 3600})
				return
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"errors":[{"message":"nope"}]}`))
		}))
		c := New()
		c.urlOverride = server.URL
		c.httpClient = func() httpDoer { return server.Client() }
		err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
			map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
			func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
		server.Close()
		if err != access.ErrAuditNotAvailable {
			t.Fatalf("status %d: err = %v; want ErrAuditNotAvailable", status, err)
		}
	}
}

// TestFetchAccessAuditLogs_SkipsUnparseableLoginTime verifies the mapper
// drops a login whose login_time is present but unparseable instead of
// emitting a zero-value (year 0001) timestamp. The partition is zero (a
// first run), so a zero-timestamp entry would otherwise slip past the
// entry.Timestamp.After(since) filter and reach downstream consumers.
func TestFetchAccessAuditLogs_SkipsUnparseableLoginTime(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "expires_in": 3600})
		case "/user-management/queries/user-login-history/v1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"resources": []string{"uuid-1"},
				"meta":      map[string]interface{}{"pagination": map[string]interface{}{"offset": 0, "limit": 200, "total": 1}},
			})
		case "/user-management/entities/user-login-history/v1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"resources": []map[string]interface{}{{
					"UUID": "uuid-1", "uid": "alice@example.com",
					"user_logins": []map[string]interface{}{
						{"user_uuid": "uuid-1", "login_time": "not-a-timestamp", "success": true},
						{"user_uuid": "uuid-1", "login_time": "2024-01-01T10:00:00Z", "success": true},
					},
				}},
			})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

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
	if len(collected) != 1 {
		t.Fatalf("collected %d entries, want 1 (unparseable login_time must be dropped)", len(collected))
	}
	if collected[0].Timestamp.IsZero() {
		t.Fatalf("emitted entry has zero timestamp: %+v", collected[0])
	}
}
