// Package aws — IdentityDeltaSyncer via CloudTrail LookupEvents.
//
// CloudTrail records every IAM mutation as a management event with
// 90-day retention. We poll cloudtrail:LookupEvents filtered to each
// user-lifecycle event name, paginate via NextToken, and emit each
// event's user as either an active Identity (CreateUser, UpdateUser,
// AttachUserPolicy etc.) or a removed ExternalID (DeleteUser).
//
// The cursor is the unix-second timestamp of the newest observed
// event. On the next invocation it is fed back as StartTime so the
// API returns only events newer than that. CloudTrail has a 90-day
// window; if the persisted cursor falls outside that window
// CloudTrail simply returns what's still in retention — we treat
// "InvalidTimeRangeException" (and other 400 variants) as
// access.ErrDeltaTokenExpired so the orchestrator falls back to a
// full SyncIdentities pass.
//
// This file reuses the shared cloudTrailEvent, cloudTrailLookupResponse,
// and cloudTrailEndpoint() from audit.go. The SigV4 helper is shared
// via signRequestSigV4.
package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// awsUserLifecycleEvents lists the IAM event names the delta syncer
// cares about. CloudTrail LookupEvents accepts exactly ONE
// LookupAttribute per call, so we issue N page-walks (one per event
// name) and merge the results.
var awsUserLifecycleEvents = []string{
	"CreateUser",
	"DeleteUser",
	"UpdateUser",
	"AttachUserPolicy",
	"DetachUserPolicy",
	"AddUserToGroup",
	"RemoveUserFromGroup",
	"EnableMFADevice",
	"DeactivateMFADevice",
	"PutUserPolicy",
	"DeleteUserPolicy",
}

type cloudTrailEventDetail struct {
	ResponseElements struct {
		User struct {
			UserName string `json:"userName"`
			UserID   string `json:"userId"`
			Arn      string `json:"arn"`
		} `json:"user"`
	} `json:"responseElements"`
	RequestParameters struct {
		UserName string `json:"userName"`
		// NewUserName is set by iam:UpdateUser when the call
		// renames the user (the parameter is optional — UpdateUser
		// can also be a no-op path update). When present, the
		// delta syncer treats the event as a rename: the old
		// UserName is tombstoned and the new UserName is emitted
		// as an active identity.
		NewUserName string `json:"newUserName"`
	} `json:"requestParameters"`
}

// SyncIdentitiesDelta polls CloudTrail for each user-lifecycle event
// name, merges the results into a single deduplicated batch, and emits
// one handler call with the complete set. The final cursor is the
// unix-second timestamp of the newest observed event.
func (c *AWSAccessConnector) SyncIdentitiesDelta(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	deltaLink string,
	handler func(batch []*access.Identity, removedExternalIDs []string, nextLink string) error,
) (string, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return "", err
	}

	var since time.Time
	if deltaLink != "" {
		if v, err := strconv.ParseInt(strings.TrimSpace(deltaLink), 10, 64); err == nil && v > 0 {
			since = time.Unix(v, 0).UTC()
		}
	}
	if since.IsZero() {
		since = c.now().UTC().Add(-1 * time.Hour)
	}

	var allEvents []cloudTrailEvent
	for _, eventName := range awsUserLifecycleEvents {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		events, err := c.lookupAllDeltaPages(ctx, cfg, secrets, eventName, since)
		if err != nil {
			if isCloudTrailInvalidRange(err) {
				return "", access.ErrDeltaTokenExpired
			}
			return "", err
		}
		allEvents = append(allEvents, events...)
	}

	batch, removed, cursorMax := mapAWSLifecycleEvents(allEvents, since)
	cursor := strconv.FormatInt(cursorMax.Unix(), 10)
	if len(batch) == 0 && len(removed) == 0 {
		return cursor, nil
	}
	if err := handler(batch, removed, cursor); err != nil {
		return "", err
	}
	return cursor, nil
}

func (c *AWSAccessConnector) lookupAllDeltaPages(ctx context.Context, cfg Config, secrets Secrets, eventName string, since time.Time) ([]cloudTrailEvent, error) {
	const maxPages = 50
	var all []cloudTrailEvent
	nextToken := ""
	startUnix := since.Unix()
	for page := 0; page < maxPages; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		reqBody := map[string]interface{}{
			"LookupAttributes": []map[string]string{{
				"AttributeKey":   "EventName",
				"AttributeValue": eventName,
			}},
			"StartTime":  startUnix,
			"MaxResults": 50,
		}
		if nextToken != "" {
			reqBody["NextToken"] = nextToken
		}
		raw, _ := json.Marshal(reqBody)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cloudTrailEndpoint(), bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", cloudTrailTarget)
		if err := signRequestSigV4(req, secrets.AccessKeyID, secrets.SecretAccessKey, defaultRegion, "cloudtrail", c.now()); err != nil {
			return nil, fmt.Errorf("aws: sign cloudtrail: %w", err)
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return nil, fmt.Errorf("aws: cloudtrail %s: %w", eventName, err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("aws: cloudtrail %s: status %d: %s", eventName, resp.StatusCode, string(body))
		}
		var parsed cloudTrailLookupResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("aws: decode cloudtrail %s: %w", eventName, err)
		}
		all = append(all, parsed.Events...)
		if strings.TrimSpace(parsed.NextToken) == "" {
			return all, nil
		}
		nextToken = parsed.NextToken
	}
	return all, nil
}

// mapAWSLifecycleEvents folds the union of per-event-name pages into a
// single batch/removed/cursor triple. DeleteUser → removedExternalIDs;
// everything else → active Identity (user still exists; downstream
// refreshes from the source when needed).
//
// Events are sorted by EventTime ascending so the "latest_event"
// recorded against each user reflects the chronologically most recent
// IAM mutation observed in this window, independent of which
// LookupAttributes call returned it.
//
// Dedupe is keyed by IAM UserName (matching SyncIdentities, which
// emits UserName as the Identity ExternalID). Three special cases:
//   - DeleteUser tombstones the user (added to removedSet, removed
//     from seen).
//   - A subsequent non-Delete event for the same name rescinds the
//     tombstone (IAM usernames are reusable; a delete-then-recreate
//     within one delta window must not leak both rows).
//   - UpdateUser with a NewUserName is a rename: the old name is
//     tombstoned AND the new name is emitted as the active identity.
//     Without this, the active batch would carry a record under a
//     name that no longer exists in IAM, and downstream mutation
//     APIs (which are keyed by UserName) would silently fail.
func mapAWSLifecycleEvents(events []cloudTrailEvent, cursorMax time.Time) ([]*access.Identity, []string, time.Time) {
	maxTS := cursorMax
	sorted := make([]cloudTrailEvent, len(events))
	copy(sorted, events)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].EventTime < sorted[j].EventTime
	})
	seen := make(map[string]*access.Identity)
	removedSet := make(map[string]bool)
	for _, e := range sorted {
		ts := time.Unix(int64(e.EventTime), 0).UTC()
		if ts.After(maxTS) {
			maxTS = ts
		}
		userName, userID := extractAWSUserIdentifiers(e)
		if userName == "" {
			continue
		}
		if e.EventName == "DeleteUser" {
			removedSet[userName] = true
			delete(seen, userName)
			continue
		}
		// UpdateUser with a NewUserName parameter is a rename: the
		// old name disappears from IAM, the new name takes its
		// place. Emit the old name as removed and switch the
		// active-identity emission to the new name so downstream
		// uses the only name IAM will now accept.
		activeName := userName
		isRename := false
		if e.EventName == "UpdateUser" {
			if newName := extractAWSUserRename(e); newName != "" && newName != userName {
				removedSet[userName] = true
				delete(seen, userName)
				activeName = newName
				isRename = true
			}
		}
		rawData := map[string]interface{}{
			"latest_event": e.EventName,
			"event_time":   ts.Format(time.RFC3339),
			"user_name":    activeName,
		}
		if userID != "" {
			rawData["user_id"] = userID
		}
		if isRename {
			rawData["renamed_from"] = userName
		}
		// IAM usernames are reusable: an operator can DeleteUser
		// "alice" and CreateUser "alice" again within the same
		// delta window. Because we iterate chronologically, the
		// later (re)creation must rescind the earlier tombstone —
		// otherwise the handler receives "alice" in both
		// removedExternalIDs and batch, and the downstream
		// reconciler will tombstone the freshly-created identity.
		delete(removedSet, activeName)
		seen[activeName] = &access.Identity{
			ExternalID:  activeName,
			Type:        access.IdentityTypeUser,
			DisplayName: activeName,
			Status:      "active",
			RawData:     rawData,
		}
	}
	batch := make([]*access.Identity, 0, len(seen))
	for _, ident := range seen {
		batch = append(batch, ident)
	}
	removed := make([]string, 0, len(removedSet))
	for id := range removedSet {
		removed = append(removed, id)
	}
	return batch, removed, maxTS
}

// extractAWSUserIdentifiers pulls the TARGET user out of a CloudTrail
// IAM event — the user the API was operating ON, not the principal
// who called it. CloudTrail's top-level `userIdentity.userName` (which
// the SDK surfaces as cloudTrailEvent.Username) is the API caller —
// e.g. the admin who ran `aws iam delete-user --user-name alice`
// surfaces with Username="root-admin" — so using it as the user
// identifier would attribute every lifecycle event to the admin and
// tombstone the admin's identity on every DeleteUser.
//
// The target always lives inside the per-event detail blob. For most
// IAM mutations (DeleteUser, UpdateUser, AttachUserPolicy, etc.)
// `requestParameters.userName` is the current name of the user being
// operated on; for CreateUser the same value also appears in
// `responseElements.user.userName` (plus the immutable AIDA…
// `userId`). We therefore consult `requestParameters.userName` first
// and fall through to `responseElements.user.userName` only when the
// former is empty (e.g. CreateUser shapes that omit
// requestParameters in some SDK versions, or test events that build
// only the response side).
//
// For UpdateUser-with-rename specifically, `requestParameters.userName`
// is the OLD name (the user as it exists right now). The NEW name
// lives in `requestParameters.newUserName` and is consumed by
// extractAWSUserRename — see mapAWSLifecycleEvents for how the
// returned value is folded into the rename special case.
//
// `cloudTrailEvent.Username` (the API caller) is only used as a
// defensive last resort for synthetic events that omit the detail
// blob entirely. `userID` stays scoped to responseElements, which is
// the only place CloudTrail ever surfaces AIDA…
func extractAWSUserIdentifiers(e cloudTrailEvent) (userName, userID string) {
	if e.CloudTrailEvent != "" {
		var d cloudTrailEventDetail
		if err := json.Unmarshal([]byte(e.CloudTrailEvent), &d); err == nil {
			userName = strings.TrimSpace(d.RequestParameters.UserName)
			if userName == "" {
				userName = strings.TrimSpace(d.ResponseElements.User.UserName)
			}
			userID = strings.TrimSpace(d.ResponseElements.User.UserID)
		}
	}
	if userName == "" {
		userName = strings.TrimSpace(e.Username)
	}
	return userName, userID
}

// extractAWSUserRename returns the new UserName encoded in an
// iam:UpdateUser event's requestParameters.newUserName (empty when
// the field is absent or the event isn't a rename). Splitting this
// out from extractAWSUserIdentifiers keeps the common-case path —
// every non-UpdateUser event — free of an extra JSON parse.
func extractAWSUserRename(e cloudTrailEvent) string {
	if e.CloudTrailEvent == "" {
		return ""
	}
	var d cloudTrailEventDetail
	if err := json.Unmarshal([]byte(e.CloudTrailEvent), &d); err != nil {
		return ""
	}
	return strings.TrimSpace(d.RequestParameters.NewUserName)
}

func isCloudTrailInvalidRange(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "InvalidTimeRangeException") ||
		strings.Contains(msg, "InvalidLookupAttributes") ||
		strings.Contains(msg, "InvalidNextTokenException")
}

// InitialDeltaCursor returns a Unix-seconds "now" timestamp the
// orchestrator persists as the baseline cursor after a successful
// full sync. The next SyncIdentitiesDelta passes it back as the
// CloudTrail LookupEvents StartTime (Unix-seconds), so the delta
// path returns events from "now" onwards. CloudTrail's 90-day
// retention window does not affect this baseline (we're at the
// boundary, not in the past). No network call.
func (c *AWSAccessConnector) InitialDeltaCursor(
	_ context.Context,
	_ map[string]interface{},
	_ map[string]interface{},
) (string, error) {
	return strconv.FormatInt(time.Now().UTC().Unix(), 10), nil
}

var _ access.IdentityDeltaSyncer = (*AWSAccessConnector)(nil)
