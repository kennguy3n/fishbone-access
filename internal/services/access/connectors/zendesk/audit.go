package zendesk

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

// FetchAccessAuditLogs streams Zendesk audit log records into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v2/audit_logs.json?filter[created_at][]={from}&filter[created_at][]={to}
//
// Zendesk paginates by `next_page` URL; the handler is called once
// per provider page in chronological order so callers can persist
// the monotonic `nextSince` cursor between runs.
func (c *ZendeskAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]
	cursor := since
	q := url.Values{}
	q.Set("sort_by", "created_at")
	q.Set("sort_order", "asc")
	if !since.IsZero() {
		q.Add("filter[created_at][]", since.UTC().Format(time.RFC3339))
		q.Add("filter[created_at][]", time.Now().UTC().Format(time.RFC3339))
	}
	nextURL := c.baseURL(cfg) + "/api/v2/audit_logs.json?" + q.Encode()
	for nextURL != "" {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		body, status, err := c.doWithStatus(req)
		if err != nil {
			if status == http.StatusForbidden {
				return access.ErrAuditNotAvailable
			}
			return err
		}
		var page zendeskAuditPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("zendesk: decode audit log page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.AuditLogs))
		batchMax := cursor
		for i := range page.AuditLogs {
			entry := mapZendeskAuditLog(&page.AuditLogs[i])
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
		next := strings.TrimSpace(page.NextPage)
		if next == "" {
			return nil
		}
		if c.urlOverride != "" {
			next = strings.Replace(next, "https://"+cfg.Subdomain+".zendesk.com", strings.TrimRight(c.urlOverride, "/"), 1)
		}
		nextURL = next
	}
	return nil
}

type zendeskAuditPage struct {
	AuditLogs []zendeskAuditLog `json:"audit_logs"`
	NextPage  string            `json:"next_page"`
	Count     int               `json:"count"`
}

type zendeskAuditLog struct {
	ID                int64  `json:"id"`
	ActorID           int64  `json:"actor_id"`
	ActorType         string `json:"actor_type"`
	ActorName         string `json:"actor_name"`
	SourceID          int64  `json:"source_id"`
	SourceLabel       string `json:"source_label"`
	SourceType        string `json:"source_type"`
	Action            string `json:"action"`
	IPAddress         string `json:"ip_address"`
	ChangeDescription string `json:"change_description"`
	CreatedAt         string `json:"created_at"`
}

func mapZendeskAuditLog(e *zendeskAuditLog) *access.AuditLogEntry {
	if e == nil || e.ID == 0 {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, e.CreatedAt)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, e.CreatedAt)
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          fmt.Sprintf("%d", e.ID),
		EventType:        e.SourceType,
		Action:           e.Action,
		Timestamp:        ts,
		ActorExternalID:  fmt.Sprintf("%d", e.ActorID),
		TargetExternalID: fmt.Sprintf("%d", e.SourceID),
		TargetType:       e.SourceType,
		IPAddress:        e.IPAddress,
		Outcome:          "success",
		RawData:          rawMap,
	}
}

var _ access.AccessAuditor = (*ZendeskAccessConnector)(nil)
