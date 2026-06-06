package aws

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type cloudTrailReqBody struct {
	LookupAttributes []struct {
		AttributeKey   string `json:"AttributeKey"`
		AttributeValue string `json:"AttributeValue"`
	} `json:"LookupAttributes"`
	StartTime  int64  `json:"StartTime"`
	NextToken  string `json:"NextToken"`
	MaxResults int    `json:"MaxResults"`
}

func TestAWS_SyncIdentitiesDelta_MapsLifecycleEvents(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	createUserEvent := `{"responseElements":{"user":{"userName":"alice","userId":"AIDA1","arn":"arn:aws:iam::1:user/alice"}}}`
	deleteUserEvent := `{"requestParameters":{"userName":"bob"}}`
	attachPolicyEvent := `{"requestParameters":{"userName":"alice"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Target") != cloudTrailTarget {
			t.Errorf("X-Amz-Target = %q", r.Header.Get("X-Amz-Target"))
		}
		body, _ := io.ReadAll(r.Body)
		var parsed cloudTrailReqBody
		_ = json.Unmarshal(body, &parsed)
		if len(parsed.LookupAttributes) != 1 || parsed.LookupAttributes[0].AttributeKey != "EventName" {
			t.Errorf("LookupAttributes = %+v", parsed.LookupAttributes)
		}
		eventName := parsed.LookupAttributes[0].AttributeValue
		var events []map[string]interface{}
		switch eventName {
		// In real CloudTrail responses, the top-level Username is
		// the API CALLER (e.g. the admin who ran the command), NOT
		// the target user. The target lives in
		// requestParameters.userName / responseElements.user.userName
		// inside CloudTrailEvent. We mirror that here so the tests
		// validate extractAWSUserIdentifiers against real semantics.
		case "CreateUser":
			events = append(events, map[string]interface{}{
				"EventId":         "ev-create-1",
				"EventName":       "CreateUser",
				"EventTime":       float64(now.Add(-10 * time.Minute).Unix()),
				"Username":        "root-admin",
				"CloudTrailEvent": createUserEvent,
			})
		case "DeleteUser":
			events = append(events, map[string]interface{}{
				"EventId":         "ev-delete-1",
				"EventName":       "DeleteUser",
				"EventTime":       float64(now.Add(-5 * time.Minute).Unix()),
				"Username":        "root-admin",
				"CloudTrailEvent": deleteUserEvent,
			})
		case "AttachUserPolicy":
			events = append(events, map[string]interface{}{
				"EventId":         "ev-attach-1",
				"EventName":       "AttachUserPolicy",
				"EventTime":       float64(now.Add(-1 * time.Minute).Unix()),
				"Username":        "root-admin",
				"CloudTrailEvent": attachPolicyEvent,
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"Events": events})
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	c.timeOverride = func() time.Time { return now }

	var (
		gotBatch       []*access.Identity
		gotRemoved     []string
		callsToHandler int
	)
	cursor, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "",
		func(b []*access.Identity, removed []string, _ string) error {
			callsToHandler++
			gotBatch = append(gotBatch, b...)
			gotRemoved = append(gotRemoved, removed...)
			return nil
		})
	if err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if callsToHandler != 1 {
		t.Errorf("handler called %d times; want 1", callsToHandler)
	}
	// Alice should be active (CreateUser + AttachUserPolicy → last write wins).
	if len(gotBatch) != 1 || gotBatch[0].DisplayName != "alice" {
		t.Errorf("active batch = %+v; want one entry for alice", gotBatch)
	}
	if len(gotRemoved) != 1 || gotRemoved[0] != "bob" {
		t.Errorf("removed = %v; want [bob]", gotRemoved)
	}
	// Cursor should be the unix seconds of the newest observed event (AttachUserPolicy, now-1min).
	wantCursor := strconv.FormatInt(now.Add(-1*time.Minute).Unix(), 10)
	if cursor != wantCursor {
		t.Errorf("cursor = %q; want %q", cursor, wantCursor)
	}
}

func TestAWS_SyncIdentitiesDelta_CursorPreservedWhenNoEvents(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"Events": []interface{}{}})
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	c.timeOverride = func() time.Time { return now }

	priorCursor := strconv.FormatInt(now.Add(-30*time.Minute).Unix(), 10)
	cursor, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), priorCursor,
		func(_ []*access.Identity, _ []string, _ string) error {
			t.Error("handler should not be called when no events")
			return nil
		})
	if err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if cursor != priorCursor {
		t.Errorf("cursor = %q; want unchanged %q", cursor, priorCursor)
	}
}

func TestAWS_SyncIdentitiesDelta_InvalidTimeRangeReturnsExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"__type":"InvalidTimeRangeException","message":"Start time too old"}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	c.timeOverride = func() time.Time { return time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC) }

	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "1234567890",
		func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if !errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Fatalf("want ErrDeltaTokenExpired; got %v", err)
	}
}

func TestAWS_SyncIdentitiesDelta_Paginates(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	createEvent := `{"responseElements":{"user":{"userName":"alice","userId":"AIDA1"}}}`
	var (
		mu        sync.Mutex
		callCount int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed cloudTrailReqBody
		_ = json.Unmarshal(body, &parsed)
		mu.Lock()
		callCount++
		mu.Unlock()
		eventName := parsed.LookupAttributes[0].AttributeValue
		if eventName != "CreateUser" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"Events": []interface{}{}})
			return
		}
		switch parsed.NextToken {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"Events": []map[string]interface{}{{
					"EventId": "p1", "EventName": "CreateUser",
					"EventTime": float64(now.Add(-10 * time.Minute).Unix()),
					// Username is the API caller, target is in CloudTrailEvent.
					"Username": "root-admin", "CloudTrailEvent": createEvent,
				}},
				"NextToken": "page2",
			})
		case "page2":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"Events": []map[string]interface{}{{
					"EventId": "p2", "EventName": "CreateUser",
					"EventTime":       float64(now.Add(-5 * time.Minute).Unix()),
					"Username":        "root-admin",
					"CloudTrailEvent": `{"responseElements":{"user":{"userName":"charlie","userId":"AIDA3"}}}`,
				}},
			})
		}
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	c.timeOverride = func() time.Time { return now }
	var got []*access.Identity
	if _, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "",
		func(b []*access.Identity, _ []string, _ string) error {
			got = append(got, b...)
			return nil
		}); err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if len(got) != 2 {
		names := make([]string, 0, len(got))
		for _, i := range got {
			names = append(names, i.DisplayName)
		}
		t.Errorf("batch = %v; want 2 (alice, charlie)", strings.Join(names, ","))
	}
}

// TestAWS_SyncIdentitiesDelta_DeleteThenRecreate pins the contract
// that a DeleteUser event followed chronologically by a CreateUser
// for the same UserName (IAM usernames are reusable) does NOT emit
// the user in both the removedExternalIDs and active batch — the
// later (re)creation rescinds the earlier tombstone so the
// downstream reconciler sees a single coherent state.
func TestAWS_SyncIdentitiesDelta_DeleteThenRecreate(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	createBody := `{"responseElements":{"user":{"userName":"alice","userId":"AIDA2","arn":"arn:aws:iam::1:user/alice"}}}`
	deleteBody := `{"requestParameters":{"userName":"alice"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed cloudTrailReqBody
		_ = json.Unmarshal(body, &parsed)
		var events []map[string]interface{}
		switch parsed.LookupAttributes[0].AttributeValue {
		// Username here is the admin caller; the target user "alice"
		// lives in CloudTrailEvent (requestParameters / responseElements).
		case "DeleteUser":
			events = append(events, map[string]interface{}{
				"EventId":         "ev-del",
				"EventName":       "DeleteUser",
				"EventTime":       float64(now.Add(-10 * time.Minute).Unix()),
				"Username":        "root-admin",
				"CloudTrailEvent": deleteBody,
			})
		case "CreateUser":
			events = append(events, map[string]interface{}{
				"EventId":         "ev-create",
				"EventName":       "CreateUser",
				"EventTime":       float64(now.Add(-1 * time.Minute).Unix()),
				"Username":        "root-admin",
				"CloudTrailEvent": createBody,
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"Events": events})
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	c.timeOverride = func() time.Time { return now }

	var (
		gotBatch   []*access.Identity
		gotRemoved []string
	)
	if _, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "",
		func(b []*access.Identity, removed []string, _ string) error {
			gotBatch = append(gotBatch, b...)
			gotRemoved = append(gotRemoved, removed...)
			return nil
		}); err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	// Alice must appear ONLY as active (recreate at T-1m rescinds the delete at T-10m).
	if len(gotBatch) != 1 || gotBatch[0].ExternalID != "alice" {
		t.Errorf("active batch = %+v; want one entry for alice", gotBatch)
	}
	if len(gotRemoved) != 0 {
		t.Errorf("removed = %v; want empty (recreate rescinds tombstone)", gotRemoved)
	}
}

// TestAWS_ExtractAWSUserIdentifiers_PrefersTargetOverActor is a unit
// test that pins the contract for extractAWSUserIdentifiers against
// real-shaped CloudTrail events. The top-level Username carries the
// API caller (e.g. the admin who initiated the action); the target
// user lives in requestParameters.userName (for most IAM mutations)
// or responseElements.user.userName (for CreateUser/GetUser/etc.).
// Returning the caller would attribute every lifecycle event to the
// admin and incorrectly tombstone the admin's own identity on every
// DeleteUser — see Devin Review BUG_… pr-review-job-567e7df4.
func TestAWS_ExtractAWSUserIdentifiers_PrefersTargetOverActor(t *testing.T) {
	cases := []struct {
		name     string
		event    cloudTrailEvent
		wantName string
		wantID   string
	}{
		{
			name: "delete_user_target_in_request_params",
			event: cloudTrailEvent{
				EventName:       "DeleteUser",
				Username:        "root-admin",
				CloudTrailEvent: `{"requestParameters":{"userName":"alice"}}`,
			},
			wantName: "alice",
		},
		{
			name: "create_user_target_in_response_elements",
			event: cloudTrailEvent{
				EventName:       "CreateUser",
				Username:        "root-admin",
				CloudTrailEvent: `{"responseElements":{"user":{"userName":"bob","userId":"AIDA9"}}}`,
			},
			wantName: "bob",
			wantID:   "AIDA9",
		},
		{
			// extractAWSUserIdentifiers is rename-agnostic: for an
			// UpdateUser-with-rename event it returns the OLD name
			// (which lives in requestParameters.userName). The
			// rename handling — emitting the new name as active
			// and the old name as removed — lives in
			// mapAWSLifecycleEvents (see the dedicated rename
			// integration test) so the extractor stays pure.
			name: "update_user_rename_returns_old_name_for_tombstone",
			event: cloudTrailEvent{
				EventName:       "UpdateUser",
				Username:        "root-admin",
				CloudTrailEvent: `{"requestParameters":{"userName":"old","newUserName":"new"}}`,
			},
			wantName: "old",
		},
		{
			name: "falls_back_to_top_level_username_when_detail_missing",
			event: cloudTrailEvent{
				EventName:       "AttachUserPolicy",
				Username:        "fallback",
				CloudTrailEvent: "",
			},
			wantName: "fallback",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotName, gotID := extractAWSUserIdentifiers(tc.event)
			if gotName != tc.wantName {
				t.Errorf("userName = %q; want %q", gotName, tc.wantName)
			}
			if gotID != tc.wantID {
				t.Errorf("userID = %q; want %q", gotID, tc.wantID)
			}
		})
	}
}

// TestAWS_SyncIdentitiesDelta_UpdateUserRename pins the contract that
// an iam:UpdateUser event with a NewUserName parameter is a rename:
// the OLD name appears in removedExternalIDs (so the downstream
// reconciler tombstones the row IAM no longer accepts) AND the NEW
// name appears in the active batch (so the row downstream now uses
// to issue IAM mutations is the one IAM will actually accept).
//
// Without this special case the active batch would only carry the
// old name, and every subsequent SessionRevoker / SyncGroupMembers /
// SyncIdentitiesDelta call keyed on that name would 404 against IAM.
func TestAWS_SyncIdentitiesDelta_UpdateUserRename(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed cloudTrailReqBody
		_ = json.Unmarshal(body, &parsed)
		var events []map[string]interface{}
		if parsed.LookupAttributes[0].AttributeValue == "UpdateUser" {
			events = append(events, map[string]interface{}{
				"EventId":         "ev-rename",
				"EventName":       "UpdateUser",
				"EventTime":       float64(now.Add(-5 * time.Minute).Unix()),
				"Username":        "root-admin",
				"CloudTrailEvent": `{"requestParameters":{"userName":"alice.old","newUserName":"alice.new"}}`,
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"Events": events})
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	c.timeOverride = func() time.Time { return now }

	var (
		gotBatch   []*access.Identity
		gotRemoved []string
	)
	if _, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "",
		func(b []*access.Identity, removed []string, _ string) error {
			gotBatch = append(gotBatch, b...)
			gotRemoved = append(gotRemoved, removed...)
			return nil
		}); err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	// Active batch must carry the NEW name only.
	if len(gotBatch) != 1 || gotBatch[0].ExternalID != "alice.new" {
		t.Fatalf("active batch = %+v; want one entry with ExternalID=alice.new", gotBatch)
	}
	if gotBatch[0].DisplayName != "alice.new" {
		t.Errorf("DisplayName = %q; want alice.new", gotBatch[0].DisplayName)
	}
	// The renamed_from breadcrumb is preserved in RawData so a
	// caller debugging a downstream stitch can correlate.
	if got, _ := gotBatch[0].RawData["renamed_from"].(string); got != "alice.old" {
		t.Errorf("RawData[renamed_from] = %q; want alice.old", got)
	}
	// Removed list must carry the OLD name so the row IAM no
	// longer accepts is tombstoned downstream.
	if len(gotRemoved) != 1 || gotRemoved[0] != "alice.old" {
		t.Errorf("removed = %v; want [alice.old]", gotRemoved)
	}
}

// TestAWS_SyncIdentitiesDelta_UpdateUserNonRename verifies that
// UpdateUser without a NewUserName (e.g. a path-only update) is
// treated as a normal active-identity event — no tombstone, no
// renamed_from breadcrumb.
func TestAWS_SyncIdentitiesDelta_UpdateUserNonRename(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed cloudTrailReqBody
		_ = json.Unmarshal(body, &parsed)
		var events []map[string]interface{}
		if parsed.LookupAttributes[0].AttributeValue == "UpdateUser" {
			events = append(events, map[string]interface{}{
				"EventId":         "ev-path",
				"EventName":       "UpdateUser",
				"EventTime":       float64(now.Add(-5 * time.Minute).Unix()),
				"Username":        "root-admin",
				"CloudTrailEvent": `{"requestParameters":{"userName":"alice","newPath":"/engineering/"}}`,
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"Events": events})
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	c.timeOverride = func() time.Time { return now }

	var (
		gotBatch   []*access.Identity
		gotRemoved []string
	)
	if _, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "",
		func(b []*access.Identity, removed []string, _ string) error {
			gotBatch = append(gotBatch, b...)
			gotRemoved = append(gotRemoved, removed...)
			return nil
		}); err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if len(gotBatch) != 1 || gotBatch[0].ExternalID != "alice" {
		t.Errorf("active batch = %+v; want one entry for alice", gotBatch)
	}
	if _, ok := gotBatch[0].RawData["renamed_from"]; ok {
		t.Errorf("RawData[renamed_from] should not be set on a non-rename UpdateUser")
	}
	if len(gotRemoved) != 0 {
		t.Errorf("removed = %v; want empty (no rename → no tombstone)", gotRemoved)
	}
}

func TestAWS_SatisfiesIdentityDeltaSyncerInterface(t *testing.T) {
	var _ access.IdentityDeltaSyncer = New()
}

func TestAWS_InitialDeltaCursor_UnixSecondsParseable(t *testing.T) {
	c := New()
	cursor, err := c.InitialDeltaCursor(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("InitialDeltaCursor: %v", err)
	}
	secs, perr := strconv.ParseInt(cursor, 10, 64)
	if perr != nil {
		t.Fatalf("seeded cursor %q is not a Unix-seconds integer: %v", cursor, perr)
	}
	if delta := time.Since(time.Unix(secs, 0)); delta > 5*time.Second || delta < -5*time.Second {
		t.Errorf("seeded cursor %q is %v away from now; want within 5s", cursor, delta)
	}
}
