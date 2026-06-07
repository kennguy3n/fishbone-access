package klaviyo

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

const (
	klaviyoAuditPageSize = 100
	klaviyoAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Klaviyo account-activity events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/account-activity-logs?page[size]=100&page[cursor]={cursor}&filter=greater-than(datetime,{iso})
//
// The account-activity-logs API requires an admin-tier private key on the
// Klaviyo plan that exposes it; lower-tier keys return 401 / 403 / 404
// which the connector soft-skips via access.ErrAuditNotAvailable per
// docs/architecture.md §2.
func (c *KlaviyoAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]
	base := c.baseURL() + "/api/account-activity-logs"

	cursor := since
	pageCursor := ""
	for page := 0; page < klaviyoAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page[size]", fmt.Sprintf("%d", klaviyoAuditPageSize))
		if pageCursor != "" {
			q.Set("page[cursor]", pageCursor)
		}
		if !since.IsZero() {
			q.Set("filter", fmt.Sprintf("greater-than(datetime,%s)", since.UTC().Format(time.RFC3339)))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("klaviyo: account-activity-logs: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			// Surface read failures instead of advancing the cursor on a
			// truncated body that could parse as a short page and end the
			// sweep early (matches jfrog/jira read-error handling).
			return fmt.Errorf("klaviyo: read account-activity-logs body: %w", readErr)
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("klaviyo: account-activity-logs: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope klaviyoAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("klaviyo: decode account-activity-logs: %w", err)
		}
		// Emit each page as it is fetched so the caller persists nextSince
		// per page as a monotonic cursor (AccessAuditor contract). batchMax
		// starts at the running cursor so it never moves backward, and a
		// mid-stream handler failure only replays the un-acked tail.
		batch := make([]*access.AuditLogEntry, 0, len(envelope.Data))
		batchMax := cursor
		for i := range envelope.Data {
			entry := mapKlaviyoAudit(&envelope.Data[i])
			if entry == nil {
				continue
			}
			if entry.Timestamp.After(batchMax) {
				batchMax = entry.Timestamp
			}
			batch = append(batch, entry)
		}
		if len(batch) > 0 {
			if err := handler(batch, batchMax, access.DefaultAuditPartition); err != nil {
				return err
			}
			cursor = batchMax
		}
		next := strings.TrimSpace(envelope.Links.Next)
		if next == "" || len(envelope.Data) == 0 {
			break
		}
		pageCursor = klaviyoCursorFromNext(next)
		if pageCursor == "" {
			break
		}
	}
	return nil
}

type klaviyoAuditEntry struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Attributes struct {
		Datetime  string                 `json:"datetime"`
		EventType string                 `json:"event_type"`
		Action    string                 `json:"action"`
		ActorID   string                 `json:"actor_id"`
		ActorName string                 `json:"actor_name"`
		IPAddress string                 `json:"ip_address"`
		Extra     map[string]interface{} `json:"data"`
	} `json:"attributes"`
}

type klaviyoAuditPage struct {
	Data  []klaviyoAuditEntry `json:"data"`
	Links struct {
		Next string `json:"next"`
		Prev string `json:"prev"`
		Self string `json:"self"`
	} `json:"links"`
}

func klaviyoCursorFromNext(next string) string {
	u, err := url.Parse(next)
	if err != nil {
		return ""
	}
	return u.Query().Get("page[cursor]")
}

func mapKlaviyoAudit(e *klaviyoAuditEntry) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseKlaviyoTime(e.Attributes.Datetime)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.Attributes.Action)
	if action == "" {
		action = strings.TrimSpace(e.Attributes.EventType)
	}
	return &access.AuditLogEntry{
		EventID:         strings.TrimSpace(e.ID),
		EventType:       strings.TrimSpace(e.Attributes.EventType),
		Action:          action,
		Timestamp:       ts,
		ActorExternalID: strings.TrimSpace(e.Attributes.ActorID),
		ActorEmail:      strings.TrimSpace(e.Attributes.ActorName),
		IPAddress:       strings.TrimSpace(e.Attributes.IPAddress),
		Outcome:         "success",
		RawData:         rawMap,
	}
}

func parseKlaviyoTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts.UTC()
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts.UTC()
	}
	return time.Time{}
}

var _ access.AccessAuditor = (*KlaviyoAccessConnector)(nil)
