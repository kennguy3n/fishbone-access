package hubspot

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

// FetchAccessAuditLogs streams HubSpot audit log events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /account-info/v3/activity/audit-logs?occurredAfter={since}&after={cursor}
//
// HubSpot paginates by `paging.next.after`; the handler is called
// once per page in chronological order so callers can persist the
// monotonic `nextSince` cursor between runs.
func (c *HubSpotAccessConnector) FetchAccessAuditLogs(
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
	cursor := since
	after := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", "100")
		q.Set("sort", "occurredAt")
		if !since.IsZero() {
			q.Set("occurredAfter", since.UTC().Format(time.RFC3339))
		}
		if after != "" {
			q.Set("after", after)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, "/account-info/v3/activity/audit-logs?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("hubspot: audit logs: status %d: %s", resp.StatusCode, string(body))
		}
		var page hubspotAuditPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("hubspot: decode audit logs: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Results))
		batchMax := cursor
		for i := range page.Results {
			entry := mapHubSpotAuditLog(&page.Results[i])
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
		next := strings.TrimSpace(page.Paging.Next.After)
		if next == "" {
			return nil
		}
		after = next
	}
}

type hubspotAuditPage struct {
	Results []hubspotAuditLog `json:"results"`
	Paging  struct {
		Next struct {
			After string `json:"after"`
			Link  string `json:"link"`
		} `json:"next"`
	} `json:"paging"`
}

type hubspotAuditLog struct {
	ID         string                 `json:"id"`
	OccurredAt string                 `json:"occurredAt"`
	UserID     string                 `json:"userId"`
	UserEmail  string                 `json:"userEmail"`
	Action     string                 `json:"action"`
	ObjectType string                 `json:"objectType"`
	ObjectID   string                 `json:"objectId"`
	Meta       map[string]interface{} `json:"meta"`
}

func mapHubSpotAuditLog(e *hubspotAuditLog) *access.AuditLogEntry {
	if e == nil || e.ID == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, e.OccurredAt)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, e.OccurredAt)
	}
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        e.ObjectType,
		Action:           e.Action,
		Timestamp:        ts,
		ActorExternalID:  e.UserID,
		ActorEmail:       e.UserEmail,
		TargetExternalID: e.ObjectID,
		TargetType:       e.ObjectType,
		Outcome:          "success",
		RawData:          rawMap,
	}
}

var _ access.AccessAuditor = (*HubSpotAccessConnector)(nil)
