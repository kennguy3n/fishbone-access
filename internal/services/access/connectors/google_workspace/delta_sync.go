// Package google_workspace — incremental identity delta via Admin SDK
// Reports API. Implements access.IdentityDeltaSyncer.
package google_workspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// SyncIdentitiesDelta polls the Admin SDK Reports activity endpoint
// for user-management events (USER_CREATED, USER_DELETED, MOVE_USER,
// CHANGE_USER_NAME, SUSPEND_USER, UNSUSPEND_USER) since the last
// deltaLink. The deltaLink is a fully-qualified URL with the
// `startTime` (and optional `pageToken`) query parameters — the
// connector resumes by re-issuing the request.
//
// When the startTime cursor falls outside Google's audit retention
// window the Reports API returns 400 with `invalidParameter`; we map
// that — along with 410 Gone — to access.ErrDeltaTokenExpired so the
// orchestrator can drop the stored link and fall back to a full
// enumeration.
func (c *GoogleWorkspaceAccessConnector) SyncIdentitiesDelta(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	deltaLink string,
	handler func(batch []*access.Identity, removedExternalIDs []string, nextLink string) error,
) (string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return "", err
	}
	client, err := c.reportsClient(ctx, cfg, secrets)
	if err != nil {
		return "", err
	}

	startURL := deltaLink
	if startURL == "" {
		since := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
		startURL = reportsBaseURL + "/activity/users/all/applications/admin?startTime=" + url.QueryEscape(since)
	}

	var finalDeltaLink string
	next := startURL
	for next != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("google_workspace: delta request: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
		case http.StatusGone:
			return "", access.ErrDeltaTokenExpired
		case http.StatusBadRequest:
			if isReportsExpiredCursorBody(body) {
				return "", access.ErrDeltaTokenExpired
			}
			return "", fmt.Errorf("google_workspace: delta status %d: %s", resp.StatusCode, string(body))
		default:
			return "", fmt.Errorf("google_workspace: delta status %d: %s", resp.StatusCode, string(body))
		}
		var page struct {
			Items         []reportsActivity `json:"items"`
			NextPageToken string            `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return "", fmt.Errorf("google_workspace: decode delta page: %w", err)
		}
		batch, removed, latest := mapReportsAdminUserEvents(page.Items)
		nextLink := ""
		if page.NextPageToken != "" {
			nextLink = appendOrReplaceQuery(next, "pageToken", page.NextPageToken)
		}
		if err := handler(batch, removed, nextLink); err != nil {
			return "", err
		}
		if nextLink == "" {
			finalDeltaLink = buildNextDeltaLink(next, latest)
		}
		next = nextLink
	}
	return finalDeltaLink, nil
}

// mapReportsAdminUserEvents folds Admin Reports user-management
// events into (created/updated identities, removed externalIDs,
// latest event timestamp).
func mapReportsAdminUserEvents(items []reportsActivity) ([]*access.Identity, []string, time.Time) {
	var batch []*access.Identity
	var removed []string
	var latest time.Time
	for i := range items {
		a := &items[i]
		ts, _ := time.Parse(time.RFC3339, a.ID.Time)
		if ts.After(latest) {
			latest = ts
		}
		for _, ev := range a.Events {
			switch ev.Name {
			case "DELETE_USER":
				// Only the successful DELETE_USER event indicates the
				// user was actually removed from the directory.
				// DELETE_USER_FAILURE (and the matching FAILURE siblings
				// for the other admin events) means the change did not
				// take effect, so we ignore them.
				if id := paramValue(ev.Parameters, "USER_ID"); id != "" {
					removed = append(removed, id)
				} else if email := paramValue(ev.Parameters, "USER_EMAIL"); email != "" {
					removed = append(removed, email)
				}
			case "CREATE_USER", "UNDELETE_USER", "UNSUSPEND_USER", "CHANGE_USER_NAME":
				if id := paramValue(ev.Parameters, "USER_ID"); id != "" {
					batch = append(batch, &access.Identity{
						ExternalID:  id,
						Type:        access.IdentityTypeUser,
						DisplayName: paramValue(ev.Parameters, "USER_EMAIL"),
						Email:       paramValue(ev.Parameters, "USER_EMAIL"),
						Status:      "active",
					})
				}
			case "SUSPEND_USER":
				if id := paramValue(ev.Parameters, "USER_ID"); id != "" {
					batch = append(batch, &access.Identity{
						ExternalID:  id,
						Type:        access.IdentityTypeUser,
						DisplayName: paramValue(ev.Parameters, "USER_EMAIL"),
						Email:       paramValue(ev.Parameters, "USER_EMAIL"),
						Status:      "suspended",
					})
				}
			}
		}
	}
	return batch, removed, latest
}

func paramValue(params []struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}, key string) string {
	for _, p := range params {
		if p.Name == key {
			return p.Value
		}
	}
	return ""
}

func isReportsExpiredCursorBody(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var env struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return false
	}
	if strings.Contains(strings.ToLower(env.Error.Message), "starttime") &&
		strings.Contains(strings.ToLower(env.Error.Message), "old") {
		return true
	}
	if strings.EqualFold(env.Error.Status, "INVALID_ARGUMENT") &&
		strings.Contains(strings.ToLower(env.Error.Message), "starttime") {
		return true
	}
	return false
}

func appendOrReplaceQuery(rawURL, key, val string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(key, val)
	u.RawQuery = q.Encode()
	return u.String()
}

func buildNextDeltaLink(currentURL string, latest time.Time) string {
	if latest.IsZero() {
		return currentURL
	}
	u, err := url.Parse(currentURL)
	if err != nil {
		return currentURL
	}
	q := u.Query()
	q.Set("startTime", latest.UTC().Format(time.RFC3339))
	q.Del("pageToken")
	u.RawQuery = q.Encode()
	return u.String()
}

// ensure compile-time the package error import is used when expired
// cursor detection fires.
var _ = errors.New

// InitialDeltaCursor returns a Reports-activity URL with `startTime`
// set to "now" so the very next SyncIdentitiesDelta sees only events
// the orchestrator emitted after its full sync. No network call —
// `secrets` is intentionally unused because the URL does not embed
// any credential material; secrets are applied by directoryClient
// when SyncIdentitiesDelta later issues the actual request.
func (c *GoogleWorkspaceAccessConnector) InitialDeltaCursor(
	_ context.Context,
	_ map[string]interface{},
	_ map[string]interface{},
) (string, error) {
	since := time.Now().UTC().Format(time.RFC3339)
	return reportsBaseURL + "/activity/users/all/applications/admin?startTime=" + url.QueryEscape(since), nil
}

var _ access.IdentityDeltaSyncer = (*GoogleWorkspaceAccessConnector)(nil)
