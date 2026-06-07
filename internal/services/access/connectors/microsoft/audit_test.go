package microsoft

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
	page1SignIn := map[string]interface{}{
		"value": []map[string]interface{}{
			{
				"id":                "si-1",
				"createdDateTime":   "2024-01-01T10:00:00Z",
				"userId":            "u-1",
				"userPrincipalName": "u1@corp.example",
				"appDisplayName":    "Office 365",
				"ipAddress":         "203.0.113.1",
				"clientAppUsed":     "Browser",
				"status":            map[string]interface{}{"errorCode": 0},
			},
		},
	}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/auditLogs/signIns") && !strings.Contains(r.URL.RawQuery, "page=next"):
			page1SignIn["@odata.nextLink"] = server.URL + "/v1.0/auditLogs/signIns?page=next"
			_ = json.NewEncoder(w).Encode(page1SignIn)
		case strings.Contains(r.URL.Path, "/auditLogs/signIns"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":                "si-2",
						"createdDateTime":   "2024-01-01T11:00:00Z",
						"userId":            "u-2",
						"userPrincipalName": "u2@corp.example",
						"status":            map[string]interface{}{"errorCode": 50001, "failureReason": "user blocked"},
					},
				},
			})
		case strings.Contains(r.URL.Path, "/auditLogs/directoryAudits"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":                  "da-1",
						"activityDateTime":    "2024-01-01T12:00:00Z",
						"activityDisplayName": "Add user",
						"category":            "UserManagement",
						"operationType":       "Add",
						"result":              "success",
						"initiatedBy": map[string]interface{}{
							"user": map[string]interface{}{"id": "admin-1", "userPrincipalName": "admin@corp.example"},
						},
						"targetResources": []map[string]interface{}{
							{"id": "u-99", "type": "User", "displayName": "New User"},
						},
					},
				},
			})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: server.URL, http: server.Client()}
	}

	var collected []*access.AuditLogEntry
	since := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	var lastCursor time.Time
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{
			auditPartitionSignIns:         since,
			auditPartitionDirectoryAudits: since,
		},
		func(batch []*access.AuditLogEntry, nextSince time.Time, _ string) error {
			collected = append(collected, batch...)
			lastCursor = nextSince
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 3 {
		t.Fatalf("expected 3 entries; got %d", len(collected))
	}
	if collected[0].EventType != "signIn" || collected[0].Action != "login" {
		t.Errorf("first entry = %+v", collected[0])
	}
	if collected[1].Outcome != "failure" {
		t.Errorf("second entry outcome = %q", collected[1].Outcome)
	}
	if collected[2].EventType != "UserManagement" || collected[2].TargetExternalID != "u-99" {
		t.Errorf("third entry = %+v", collected[2])
	}
	if lastCursor.Before(time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC)) {
		t.Errorf("lastCursor = %v; expected at least 11:00Z", lastCursor)
	}
}

func TestNormalizeDirectoryAuditOutcome(t *testing.T) {
	// Table is a slice (not a map) so whitespace inputs like
	// " success " remain literal — gocritic's mapKey linter
	// rightly flags whitespace-only map keys, but here it is
	// the assertion subject.
	cases := []struct {
		in, want string
	}{
		{"success", "success"},
		{"Success", "success"},
		{" success ", "success"},
		{"", "success"},
		{"failure", "failure"},
		{"timeout", "failure"},
		{"unknownFutureValue", "failure"},
		{"weird", "failure"},
	}
	for _, tc := range cases {
		if got := normalizeDirectoryAuditOutcome(tc.in); got != tc.want {
			t.Errorf("normalizeDirectoryAuditOutcome(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestBuildAuditStartURL_AlwaysSetsOrderBy(t *testing.T) {
	// First-backfill case (since.IsZero()): $orderby must still be set so
	// pages stream oldest-first; otherwise Graph defaults to descending and
	// a mid-backfill failure persists a cursor at the newest event already
	// seen, causing older un-fetched events to be skipped on retry.
	urlStr, err := buildAuditStartURL("/auditLogs/signIns", "createdDateTime", time.Time{})
	if err != nil {
		t.Fatalf("buildAuditStartURL zero since: %v", err)
	}
	if !strings.Contains(urlStr, "%24orderby=createdDateTime+asc") &&
		!strings.Contains(urlStr, "$orderby=createdDateTime+asc") {
		t.Errorf("zero since URL missing $orderby asc: %s", urlStr)
	}
	if strings.Contains(urlStr, "%24filter") || strings.Contains(urlStr, "$filter") {
		t.Errorf("zero since URL should not include $filter: %s", urlStr)
	}

	// Resume case (since non-zero): both $filter and $orderby asc.
	urlStr, err = buildAuditStartURL("/auditLogs/directoryAudits", "activityDateTime",
		time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("buildAuditStartURL non-zero since: %v", err)
	}
	if !strings.Contains(urlStr, "%24orderby=activityDateTime+asc") &&
		!strings.Contains(urlStr, "$orderby=activityDateTime+asc") {
		t.Errorf("non-zero since URL missing $orderby asc: %s", urlStr)
	}
	if !strings.Contains(urlStr, "%24filter") && !strings.Contains(urlStr, "$filter") {
		t.Errorf("non-zero since URL missing $filter: %s", urlStr)
	}
}

// TestFetchAccessAuditLogs_CursorResetsPerEndpoint guards against a
// regression where cursor was shared across signIns and directoryAudits.
// signIns return entries with timestamps newer than directoryAudits;
// without per-endpoint cursor reset, the directoryAudit batch's
// nextSince would be shadowed by the inflated signIn max, causing the
// access-audit worker to persist an inflated cursor and skip older
// directoryAudit events on retry after a partial failure.
func TestFetchAccessAuditLogs_CursorResetsPerEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/auditLogs/signIns"):
			// signIn entry is NEWER than directoryAudit entries.
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":                "si-late",
						"createdDateTime":   "2024-01-01T12:00:00Z",
						"userId":            "u-1",
						"userPrincipalName": "u1@corp.example",
						"status":            map[string]interface{}{"errorCode": 0},
					},
				},
			})
		case strings.Contains(r.URL.Path, "/auditLogs/directoryAudits"):
			// directoryAudit entry is OLDER than the signIn above.
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":                  "da-early",
						"activityDateTime":    "2024-01-01T09:00:00Z",
						"activityDisplayName": "Add user",
						"category":            "UserManagement",
						"operationType":       "Add",
						"result":              "success",
						"initiatedBy": map[string]interface{}{
							"user": map[string]interface{}{"id": "admin-1"},
						},
						"targetResources": []map[string]interface{}{
							{"id": "u-99", "type": "User"},
						},
					},
				},
			})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: server.URL, http: server.Client()}
	}

	type batchCall struct {
		eventType    string
		nextSince    time.Time
		partitionKey string
	}
	var calls []batchCall
	since := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{
			auditPartitionSignIns:         since,
			auditPartitionDirectoryAudits: since,
		},
		func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error {
			if len(batch) == 0 {
				return nil
			}
			calls = append(calls, batchCall{
				eventType:    batch[0].EventType,
				nextSince:    nextSince,
				partitionKey: partitionKey,
			})
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 handler invocations (one per endpoint); got %d (%+v)", len(calls), calls)
	}

	// signIns batch reports its own max (12:00Z).
	signInCall := calls[0]
	if signInCall.eventType != "signIn" {
		t.Fatalf("first call should be signIn; got %q", signInCall.eventType)
	}
	if signInCall.partitionKey != auditPartitionSignIns {
		t.Errorf("signIn partitionKey = %q; want %q", signInCall.partitionKey, auditPartitionSignIns)
	}
	wantSignInMax := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	if !signInCall.nextSince.Equal(wantSignInMax) {
		t.Errorf("signIn nextSince = %v; want %v", signInCall.nextSince, wantSignInMax)
	}

	// directoryAudits batch MUST report its own max (09:00Z), NOT the
	// inflated signIn cursor (12:00Z). This is the regression guard.
	daCall := calls[1]
	if daCall.eventType != "UserManagement" {
		t.Fatalf("second call should be directoryAudit; got %q", daCall.eventType)
	}
	if daCall.partitionKey != auditPartitionDirectoryAudits {
		t.Errorf("directoryAudit partitionKey = %q; want %q",
			daCall.partitionKey, auditPartitionDirectoryAudits)
	}
	wantDaMax := time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC)
	if !daCall.nextSince.Equal(wantDaMax) {
		t.Errorf("directoryAudit nextSince = %v; want %v (cursor leaked from signIn endpoint)",
			daCall.nextSince, wantDaMax)
	}
}

func TestFetchAccessAuditLogs_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"InvalidAuthenticationToken"}}`))
	}))
	t.Cleanup(server.Close)
	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: server.URL, http: server.Client()}
	}
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{
			auditPartitionSignIns:         time.Now().Add(-time.Hour),
			auditPartitionDirectoryAudits: time.Now().Add(-time.Hour),
		},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected 401 to propagate as error")
	}
}

// TestGraphMappers_TimestampParsing is a regression test for two related bugs in
// mapGraphSignIn / mapGraphDirectoryAudit:
//
//  1. They parsed timestamps with time.RFC3339, which rejects the fractional
//     seconds Microsoft Graph commonly returns (e.g. directoryAudit's
//     activityDateTime "2024-01-01T10:00:00.1234567Z"). parseGraphTime must try
//     RFC3339Nano first so those records are kept.
//  2. On parse failure they emitted an entry with a zero Timestamp instead of
//     dropping it, unlike every sibling connector. Both mappers must now return
//     (nil, nil) when the timestamp is unparseable/empty.
func TestGraphMappers_TimestampParsing(t *testing.T) {
	// Fractional-second timestamps must parse (RFC3339Nano), not be dropped.
	signInFrac, err := mapGraphSignIn(json.RawMessage(`{
		"id": "si-frac",
		"createdDateTime": "2024-01-01T10:00:00.1234567Z",
		"userId": "u-1",
		"status": {"errorCode": 0}
	}`))
	if err != nil {
		t.Fatalf("mapGraphSignIn fractional: %v", err)
	}
	if signInFrac == nil {
		t.Fatal("mapGraphSignIn dropped a record with fractional-second timestamp")
	}
	want := time.Date(2024, 1, 1, 10, 0, 0, 123456700, time.UTC)
	if !signInFrac.Timestamp.Equal(want) {
		t.Errorf("signIn timestamp = %v; want %v", signInFrac.Timestamp, want)
	}

	dirFrac, err := mapGraphDirectoryAudit(json.RawMessage(`{
		"id": "da-frac",
		"activityDateTime": "2024-01-01T12:00:00.7654321Z",
		"category": "UserManagement",
		"operationType": "Add",
		"result": "success"
	}`))
	if err != nil {
		t.Fatalf("mapGraphDirectoryAudit fractional: %v", err)
	}
	if dirFrac == nil {
		t.Fatal("mapGraphDirectoryAudit dropped a record with fractional-second timestamp")
	}

	// Unparseable / empty timestamps must be dropped (nil entry), not emitted
	// with a zero time.Time.
	badSignIn, err := mapGraphSignIn(json.RawMessage(`{
		"id": "si-bad",
		"createdDateTime": "not-a-timestamp",
		"userId": "u-2",
		"status": {"errorCode": 0}
	}`))
	if err != nil {
		t.Fatalf("mapGraphSignIn bad ts: %v", err)
	}
	if badSignIn != nil {
		t.Errorf("mapGraphSignIn emitted entry for unparseable timestamp: %+v", badSignIn)
	}

	badDir, err := mapGraphDirectoryAudit(json.RawMessage(`{
		"id": "da-bad",
		"activityDateTime": "",
		"category": "UserManagement",
		"operationType": "Add",
		"result": "success"
	}`))
	if err != nil {
		t.Fatalf("mapGraphDirectoryAudit bad ts: %v", err)
	}
	if badDir != nil {
		t.Errorf("mapGraphDirectoryAudit emitted entry for empty timestamp: %+v", badDir)
	}
}
