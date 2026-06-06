// Package salesforce — incremental identity delta via SOQL
// `SystemModstamp >` filter. Implements access.IdentityDeltaSyncer.
package salesforce

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// SyncIdentitiesDelta uses a SOQL filter on `SystemModstamp` to pull
// User rows that changed since the last cursor. The deltaLink is a
// fully-qualified `nextRecordsUrl`-style path when paginating within
// one sync, OR an opaque RFC3339 timestamp from the previous
// invocation. Tombstones (`IsActive=false`) feed the removed slice;
// active rows feed the batch.
//
// Salesforce returns HTTP 400 with `errorCode: "MALFORMED_QUERY"` if
// the SystemModstamp literal is unparseable; for cursors older than
// the org's audit retention window the API responds with
// `errorCode: "INVALID_QUERY_LOCATOR"`. Both surface as
// access.ErrDeltaTokenExpired so the caller can fall back to a full
// enumeration.
func (c *SalesforceAccessConnector) SyncIdentitiesDelta(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	deltaLink string,
	handler func(batch []*access.Identity, removedExternalIDs []string, nextLink string) error,
) (string, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return "", err
	}
	base := c.instanceBase(cfg)

	var requestURL string
	cursorIsTimestamp := false
	switch {
	case strings.HasPrefix(deltaLink, "/services/data/"):
		requestURL = base + deltaLink
	case deltaLink != "":
		// Treat as RFC3339 timestamp cursor. Validate before interpolating
		// into SOQL to prevent injection via a tampered cursor.
		parsed, perr := time.Parse(time.RFC3339, strings.TrimSpace(deltaLink))
		if perr != nil {
			return "", fmt.Errorf("salesforce: invalid deltaLink cursor %q: %w", deltaLink, perr)
		}
		cursorIsTimestamp = true
		q := url.Values{"q": {soqlDeltaQuery(parsed.UTC().Format(time.RFC3339))}}
		requestURL = base + "/services/data/" + defaultAPIVersion + "/query?" + q.Encode()
	default:
		// First run — pull everything since one hour ago to bound the
		// initial page size.
		cursorIsTimestamp = true
		since := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
		q := url.Values{"q": {soqlDeltaQuery(since)}}
		requestURL = base + "/services/data/" + defaultAPIVersion + "/query?" + q.Encode()
	}

	var finalCursor time.Time
	for {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, requestURL)
		if err != nil {
			return "", err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return "", fmt.Errorf("salesforce: delta request: %w", err)
		}
		body, rawErr := readBodyClose(resp)
		if rawErr != nil {
			return "", rawErr
		}
		if resp.StatusCode == http.StatusBadRequest && isExpiredDeltaCursor(body) {
			return "", access.ErrDeltaTokenExpired
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return "", fmt.Errorf("salesforce: delta status %d: %s", resp.StatusCode, string(body))
		}
		var page sfDeltaResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return "", fmt.Errorf("salesforce: decode delta: %w", err)
		}
		batch := make([]*access.Identity, 0, len(page.Records))
		var removed []string
		for _, u := range page.Records {
			if ts, err := time.Parse(time.RFC3339, u.SystemModstamp); err == nil && ts.After(finalCursor) {
				finalCursor = ts
			}
			if !u.IsActive {
				removed = append(removed, u.ID)
				continue
			}
			display := u.Name
			if display == "" {
				display = u.Email
			}
			batch = append(batch, &access.Identity{
				ExternalID:  u.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      "active",
			})
		}
		next := strings.TrimSpace(page.NextRecordsURL)
		if err := handler(batch, removed, next); err != nil {
			return "", err
		}
		if next == "" || page.Done {
			break
		}
		requestURL = base + next
	}
	if cursorIsTimestamp && !finalCursor.IsZero() {
		return finalCursor.UTC().Format(time.RFC3339), nil
	}
	if finalCursor.IsZero() {
		// No rows changed since the cursor — preserve the cursor as-is so
		// the next sync re-uses it.
		return deltaLink, nil
	}
	return finalCursor.UTC().Format(time.RFC3339), nil
}

func soqlDeltaQuery(since string) string {
	return fmt.Sprintf(
		"SELECT Id, Name, Email, IsActive, SystemModstamp FROM User WHERE SystemModstamp > %s",
		soqlDateTimeLiteral(since),
	)
}

// soqlDateTimeLiteral renders an RFC3339 timestamp as a SOQL datetime
// literal (no quotes, ISO 8601). Salesforce requires this format for
// SystemModstamp comparisons. Input that does not parse as RFC3339 is
// rejected (returns the current UTC timestamp) so a tampered cursor
// cannot inject arbitrary SOQL.
func soqlDateTimeLiteral(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Now().UTC().Format(time.RFC3339)
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Now().UTC().Format(time.RFC3339)
	}
	return t.UTC().Format(time.RFC3339)
}

func isExpiredDeltaCursor(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var envs []struct {
		ErrorCode string `json:"errorCode"`
		Message   string `json:"message"`
	}
	if err := json.Unmarshal(body, &envs); err != nil || len(envs) == 0 {
		// Salesforce sometimes wraps in a single object instead of a list.
		var env struct {
			ErrorCode string `json:"errorCode"`
			Message   string `json:"message"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			return false
		}
		envs = []struct {
			ErrorCode string `json:"errorCode"`
			Message   string `json:"message"`
		}{env}
	}
	for _, e := range envs {
		switch strings.ToUpper(e.ErrorCode) {
		case "INVALID_QUERY_LOCATOR", "QUERY_TIMEOUT":
			return true
		case "MALFORMED_QUERY":
			if strings.Contains(strings.ToLower(e.Message), "systemmodstamp") {
				return true
			}
		}
	}
	return false
}

type sfDeltaResponse struct {
	Done           bool         `json:"done"`
	NextRecordsURL string       `json:"nextRecordsUrl"`
	Records        []sfUserRow2 `json:"records"`
}

type sfUserRow2 struct {
	ID             string `json:"Id"`
	Name           string `json:"Name"`
	Email          string `json:"Email"`
	IsActive       bool   `json:"IsActive"`
	SystemModstamp string `json:"SystemModstamp"`
}

// readBodyClose reads up to 1 MiB from resp.Body and closes it,
// matching the pattern in google_workspace/delta_sync.go. Truncated
// payloads return the bytes that were read without error; this is
// safe because callers only feed the result into JSON decoding,
// which surfaces its own error on bad bytes.
func readBodyClose(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// InitialDeltaCursor returns an RFC3339 "now" timestamp the
// orchestrator persists as the baseline cursor after a successful
// full sync, so the very next run enters the delta path. The cursor
// shape is the same as the timestamp branch in SyncIdentitiesDelta
// (the `/services/data/...` URL branch is reserved for in-flight
// pagination continuation tokens, not seeded baselines). No network
// call.
func (c *SalesforceAccessConnector) InitialDeltaCursor(
	_ context.Context,
	_ map[string]interface{},
	_ map[string]interface{},
) (string, error) {
	return time.Now().UTC().Format(time.RFC3339), nil
}

var _ access.IdentityDeltaSyncer = (*SalesforceAccessConnector)(nil)
