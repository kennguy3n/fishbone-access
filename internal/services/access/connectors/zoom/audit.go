package zoom

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams Zoom user activity (sign-in / sign-out)
// events into the access audit pipeline. Implements
// access.AccessAuditor.
//
// Endpoint:
//
//	GET /report/activities?from={from}&to={to}&page_size=300&next_page_token={tok}
//
// Zoom Reports paginates by `next_page_token`; the handler is called
// once per page in chronological order. Zoom requires the date filter
// in YYYY-MM-DD form. When `since` is zero we use a 30-day backfill
// window (Zoom's report retention) so callers get a sensible default.
func (c *ZoomAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.accessToken(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]
	now := time.Now().UTC()
	from := since
	if from.IsZero() {
		from = now.Add(-30 * 24 * time.Hour)
	}
	to := now

	cursor := since
	pageToken := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("from", from.UTC().Format("2006-01-02"))
		q.Set("to", to.UTC().Format("2006-01-02"))
		q.Set("page_size", "300")
		if pageToken != "" {
			q.Set("next_page_token", pageToken)
		}
		req, err := c.newRequest(ctx, token, http.MethodGet, "/report/activities?"+q.Encode())
		if err != nil {
			return err
		}
		body, status, err := c.doWithStatus(req)
		if err != nil {
			// Only a genuine auth/authorization rejection means the
			// account's plan does not expose the activity report. Branch
			// on the numeric status rather than matching the error text,
			// which a 5xx body could otherwise spoof into a permanent
			// soft-skip.
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				return access.ErrAuditNotAvailable
			}
			return err
		}
		var page zoomActivityPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("zoom: decode activities: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Activities))
		batchMax := cursor
		for i := range page.Activities {
			entry := mapZoomActivity(&page.Activities[i])
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
		if strings.TrimSpace(page.NextPageToken) == "" {
			return nil
		}
		pageToken = page.NextPageToken
	}
}

type zoomActivityPage struct {
	From          string         `json:"from"`
	To            string         `json:"to"`
	PageSize      int            `json:"page_size"`
	NextPageToken string         `json:"next_page_token"`
	Activities    []zoomActivity `json:"activity_logs"`
}

type zoomActivity struct {
	Time      string `json:"time"`
	Email     string `json:"email"`
	UserName  string `json:"user_name"`
	Type      string `json:"type"`
	Action    string `json:"action"`
	IP        string `json:"ip_address"`
	ClientApp string `json:"client_type"`
	UserAgent string `json:"user_agent"`
}

func mapZoomActivity(e *zoomActivity) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.Time) == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, e.Time)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, e.Time)
	}
	// Drop events whose timestamp could not be parsed. Emitting a
	// zero-valued Timestamp pollutes the audit stream with epoch-dated
	// entries and never advances the watermark cursor, so the same
	// malformed page is re-fetched and re-emitted on every poll.
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.Action)
	if action == "" {
		action = strings.TrimSpace(e.Type)
	}
	return &access.AuditLogEntry{
		EventID:    e.Email + "|" + e.Time + "|" + action,
		EventType:  e.Type,
		Action:     action,
		Timestamp:  ts,
		ActorEmail: e.Email,
		IPAddress:  e.IP,
		UserAgent:  e.UserAgent,
		Outcome:    "success",
		RawData:    rawMap,
	}
}

var _ access.AccessAuditor = (*ZoomAccessConnector)(nil)
