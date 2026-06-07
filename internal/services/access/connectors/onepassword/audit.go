package onepassword

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// onepasswordAuditBackfill bounds the first-ever audit run (when no cursor
// has been persisted yet). Unlike Okta — which can omit the time bound and
// receive its full retention window — the 1Password Events API requires an
// explicit start_time on the reset request, so we approximate "full
// retention" with a 90-day look-back (matching Okta's ~90-day window) rather
// than silently dropping anything older than 24h. Subsequent runs resume from
// the persisted cursor, so this window only affects the initial backfill.
const onepasswordAuditBackfill = 90 * 24 * time.Hour

// FetchAccessAuditLogs streams 1Password sign-in attempt events into
// the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	POST /api/v1/signinattempts
//
// 1Password's Events API expects a JSON body containing a `cursor`
// (opaque, for incremental fetches) or a `limit` + `start_time` for
// the first call, and returns a cursor in the response when more
// pages are available. The handler is called once per provider page
// in chronological order so callers can persist `nextSince` (the
// newest timestamp seen so far) as a monotonic cursor.
//
// On HTTP 401/403 the connector returns access.ErrAuditNotAvailable
// so callers treat the tenant as plan-gated (Events API requires the
// 1Password Business plan and an Events Reporting service-account
// token) rather than failing the whole sync.
func (c *OnePasswordAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]
	cursor := since
	pageCursor := ""
	const path = "/api/v1/signinattempts"
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var payload map[string]interface{}
		if pageCursor != "" {
			payload = map[string]interface{}{"cursor": pageCursor}
		} else {
			start := since
			if start.IsZero() {
				start = time.Now().Add(-onepasswordAuditBackfill)
			}
			payload = map[string]interface{}{
				"limit":      1000,
				"start_time": start.UTC().Format(time.RFC3339Nano),
			}
		}
		body, err := c.postEventsAPI(ctx, cfg, secrets, path, payload)
		if err != nil {
			if isAuditNotAvailable(err) {
				return access.ErrAuditNotAvailable
			}
			return err
		}
		var page onepasswordSigninPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("onepassword: decode signinattempts: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Items))
		batchMax := cursor
		for i := range page.Items {
			entry := mapOnePasswordSigninAttempt(&page.Items[i])
			if entry == nil {
				continue
			}
			if entry.Timestamp.After(batchMax) {
				batchMax = entry.Timestamp
			}
			batch = append(batch, entry)
		}
		if err := handler(batch, batchMax, access.DefaultAuditPartition); err != nil {
			return err
		}
		cursor = batchMax
		if !page.HasMore || strings.TrimSpace(page.Cursor) == "" {
			return nil
		}
		pageCursor = page.Cursor
	}
}

type onepasswordSigninPage struct {
	Cursor  string                     `json:"cursor"`
	HasMore bool                       `json:"has_more"`
	Items   []onepasswordSigninAttempt `json:"items"`
}

type onepasswordSigninAttempt struct {
	UUID        string                  `json:"uuid"`
	SessionUUID string                  `json:"session_uuid"`
	Category    string                  `json:"category"`
	Type        string                  `json:"type"`
	Country     string                  `json:"country"`
	Timestamp   string                  `json:"timestamp"`
	TargetUser  onepasswordSigninUser   `json:"target_user"`
	Client      onepasswordSigninClient `json:"client"`
}

type onepasswordSigninUser struct {
	UUID  string `json:"uuid"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type onepasswordSigninClient struct {
	AppName      string `json:"app_name"`
	AppVersion   string `json:"app_version"`
	PlatformName string `json:"platform_name"`
	IPAddress    string `json:"ip_address"`
}

func mapOnePasswordSigninAttempt(a *onepasswordSigninAttempt) *access.AuditLogEntry {
	// Skip entries without a UUID: EventID is derived from a.UUID and the
	// downstream dedup pipeline keys on EventID, so an empty EventID would
	// break de-duplication. Mirrors the UUID/ID guard in every other
	// connector's audit mapper (okta, pagerduty, openai, paloalto, ...).
	if a == nil || strings.TrimSpace(a.UUID) == "" || strings.TrimSpace(a.Timestamp) == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, a.Timestamp)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, a.Timestamp)
	}
	// Skip entries whose timestamp is non-empty but unparseable by both
	// layouts: a zero-timestamp audit entry would never advance the
	// delta-sync cursor (batchMax) and could be mis-ordered downstream.
	// Mirrors the okta auditor.
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(a)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	eventType := strings.TrimSpace(a.Type)
	if eventType == "" {
		eventType = strings.TrimSpace(a.Category)
	}
	if eventType == "" {
		eventType = "signin_attempt"
	}
	outcome := normalizeOnePasswordOutcome(a.Category)
	return &access.AuditLogEntry{
		EventID:         strings.TrimSpace(a.UUID),
		EventType:       eventType,
		Action:          eventType,
		Timestamp:       ts,
		ActorExternalID: a.TargetUser.UUID,
		ActorEmail:      a.TargetUser.Email,
		IPAddress:       a.Client.IPAddress,
		UserAgent:       a.Client.AppName,
		Outcome:         outcome,
		RawData:         rawMap,
	}
}

// normalizeOnePasswordOutcome maps a 1Password sign-in attempt `category`
// to the canonical success/failure vocabulary. 1Password reports a range of
// categories — e.g. "success" and "firewall_reported_success" (both
// successes), plus "credentials_failed", "mfa_failed", "modern_version_failed",
// "firewall_failed", "firewall_prevented" (failures). The previous code
// whitelisted only the literal "success", which misclassified
// "firewall_reported_success" as a failure and would silently break if
// 1Password introduced new success categories. We instead recognize any
// success-bearing category, blacklist the known failure markers, and default
// unknown/empty categories to success — mirroring paychex's
// normalizePaychexOutcome so the whole PR shares one classification policy.
func normalizeOnePasswordOutcome(category string) string {
	c := strings.ToLower(strings.TrimSpace(category))
	if c == "" || strings.Contains(c, "success") {
		return "success"
	}
	switch {
	case strings.Contains(c, "fail"),
		strings.Contains(c, "denied"),
		strings.Contains(c, "declined"),
		strings.Contains(c, "blocked"),
		strings.Contains(c, "prevented"),
		strings.Contains(c, "rejected"),
		strings.Contains(c, "error"):
		return "failure"
	default:
		return "success"
	}
}

func (c *OnePasswordAccessConnector) postEventsAPI(
	ctx context.Context,
	cfg Config,
	secrets Secrets,
	path string,
	payload map[string]interface{},
) ([]byte, error) {
	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.eventsBaseURL(cfg)+path, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secrets.bearerToken())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("onepassword: %s status %d: %s", path, resp.StatusCode, string(body))
	}
	return body, nil
}

func isAuditNotAvailable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "status 401") || strings.Contains(msg, "status 403")
}

var _ access.AccessAuditor = (*OnePasswordAccessConnector)(nil)
