package checkpoint

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

func TestCheckPointFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/web_api/show-logs" {
			t.Errorf("path = %s", r.URL.Path)
		}
		// The /web_api/* endpoints are POST-only and take their params in a
		// JSON body, not URL query params (a GET 405s on the real API).
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		if r.URL.RawQuery != "" {
			t.Errorf("params must be in body, got query %q", r.URL.RawQuery)
		}
		var reqBody map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if reqBody["limit"] == nil {
			t.Errorf("limit missing from JSON body: %+v", reqBody)
		}
		if r.Header.Get("X-chkp-sid") == "" {
			t.Errorf("missing X-chkp-sid")
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"logs": []map[string]interface{}{{
				"id":            "ckp-1",
				"action":        "log",
				"operation":     "policy.install",
				"time":          "2024-09-01T10:00:00Z",
				"origin":        "gw-1",
				"subject":       "policy/standard",
				"administrator": "secops@example.com",
				"src_ip":        "10.0.0.17",
			}},
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
	if len(collected) != 1 || collected[0].TargetExternalID != "policy/standard" {
		t.Fatalf("collected = %+v", collected)
	}
	if !nextSince.Equal(time.Date(2024, 9, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("nextSince = %s", nextSince)
	}
}

// TestCheckPointFetchAccessAuditLogs_Pagination guards the new-query
// semantics: show-logs must initiate a fresh query only on the first page
// (new-query:true) and continue the same query on later pages
// (new-query:false), advancing by offset. Sending new-query:true on every
// page would restart the query and corrupt offset-based pagination.
func TestCheckPointFetchAccessAuditLogs_Pagination(t *testing.T) {
	var gotNewQuery []bool
	var gotOffsets []float64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		nq, _ := reqBody["new-query"].(bool)
		off, _ := reqBody["offset"].(float64)
		gotNewQuery = append(gotNewQuery, nq)
		gotOffsets = append(gotOffsets, off)

		logs := make([]map[string]interface{}, 0, checkpointAuditPageSize)
		// First page: a full page (forces a second request). Second page:
		// a single row (< page size) so the loop terminates.
		n := checkpointAuditPageSize
		if int(off) >= checkpointAuditPageSize {
			n = 1
		}
		for i := 0; i < n; i++ {
			logs = append(logs, map[string]interface{}{
				"id":            "ckp",
				"operation":     "policy.install",
				"time":          "2024-09-01T10:00:00Z",
				"subject":       "policy/standard",
				"administrator": "secops@example.com",
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"logs": logs})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(gotNewQuery) != 2 {
		t.Fatalf("expected 2 requests, got %d (new-query=%v)", len(gotNewQuery), gotNewQuery)
	}
	if !gotNewQuery[0] {
		t.Errorf("page 0 new-query = false, want true")
	}
	if gotNewQuery[1] {
		t.Errorf("page 1 new-query = true, want false (must continue same query)")
	}
	if gotOffsets[0] != 0 || gotOffsets[1] != float64(checkpointAuditPageSize) {
		t.Errorf("offsets = %v, want [0 %d]", gotOffsets, checkpointAuditPageSize)
	}
}

func TestCheckPointFetchAccessAuditLogs_NotAvailable(t *testing.T) {
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

func TestCheckPointFetchAccessAuditLogs_TransientFailure(t *testing.T) {
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
