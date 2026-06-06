package workday

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

// workdayAuditMaxPages caps the offset/limit sweep so a misbehaving tenant
// (e.g. a `from` filter that never advances past a full data window) cannot
// spin the loop indefinitely. Matches the cap used by sibling audit connectors.
const workdayAuditMaxPages = 200

// FetchAccessAuditLogs streams Workday activity-log events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /ccx/api/v1/{tenant}/activityLogging?from={since}&offset=N&limit=100
//
// Pagination is offset/limit-based; iteration stops when a page returns
// fewer than `limit` records. Tenants without an activity-logging
// licence return 403/404 which collapses to access.ErrAuditNotAvailable
// so the worker soft-skips the tenant instead of looping.
func (c *WorkdayAccessConnector) FetchAccessAuditLogs(
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
	offset := 0
	const limit = pageSize
	for pages := 0; pages < workdayAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", limit))
		q.Set("offset", fmt.Sprintf("%d", offset))
		if !since.IsZero() {
			q.Set("from", since.UTC().Format(time.RFC3339))
		}
		fullURL := fmt.Sprintf("%s/ccx/api/v1/%s/activityLogging?%s", c.baseURL(cfg), url.PathEscape(cfg.Tenant), q.Encode())
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
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
			return fmt.Errorf("workday: activityLogging: status %d: %s", resp.StatusCode, string(body))
		}
		var page workdayActivityPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("workday: decode activityLogging: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Data))
		batchMax := cursor
		for i := range page.Data {
			entry := mapWorkdayActivity(&page.Data[i])
			if entry == nil {
				continue
			}
			if entry.Timestamp.After(batchMax) {
				batchMax = entry.Timestamp
			}
			batch = append(batch, entry)
		}
		// Skip the handler when every row on this page was filtered out
		// (e.g. all zero/unparseable timestamps). Emitting an empty batch
		// with an unchanged batchMax would invite callers to persist a
		// non-advancing cursor; this matches the sibling audit connectors,
		// which only invoke the handler for non-empty batches.
		if len(batch) > 0 {
			if err := handler(batch, batchMax, access.DefaultAuditPartition); err != nil {
				return err
			}
		}
		cursor = batchMax
		if len(page.Data) < limit {
			return nil
		}
		offset += limit
	}
	return nil
}

type workdayActivityPage struct {
	Total int                  `json:"total"`
	Data  []workdayActivityRow `json:"data"`
}

type workdayActivityRow struct {
	ID             string `json:"id"`
	ActivityAction string `json:"activityAction"`
	RequestTime    string `json:"requestTime"`
	TaskID         string `json:"taskId,omitempty"`
	TaskDisplay    string `json:"taskDisplayName,omitempty"`
	UserID         string `json:"userId,omitempty"`
	UserName       string `json:"userName,omitempty"`
	IPAddress      string `json:"ipAddress,omitempty"`
	UserAgent      string `json:"userAgent,omitempty"`
	SessionID      string `json:"sessionId,omitempty"`
	TargetID       string `json:"targetId,omitempty"`
	TargetName     string `json:"targetName,omitempty"`
	TargetType     string `json:"targetType,omitempty"`
}

func mapWorkdayActivity(r *workdayActivityRow) *access.AuditLogEntry {
	if r == nil || strings.TrimSpace(r.ID) == "" {
		return nil
	}
	ts := parseWorkdayTime(r.RequestTime)
	if ts.IsZero() {
		return nil
	}
	action := strings.TrimSpace(r.ActivityAction)
	if action == "" {
		action = strings.TrimSpace(r.TaskDisplay)
	}
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(r)
	_ = json.Unmarshal(raw, &rawMap)
	target := strings.TrimSpace(r.TargetID)
	if target == "" {
		target = strings.TrimSpace(r.TaskID)
	}
	targetType := strings.TrimSpace(r.TargetType)
	if targetType == "" && r.TaskID != "" {
		targetType = "task"
	}
	return &access.AuditLogEntry{
		EventID:          r.ID,
		EventType:        action,
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(r.UserID),
		ActorEmail:       strings.TrimSpace(r.UserName),
		TargetExternalID: target,
		TargetType:       targetType,
		IPAddress:        strings.TrimSpace(r.IPAddress),
		UserAgent:        strings.TrimSpace(r.UserAgent),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

// parseWorkdayTime parses Workday's activity-log timestamps, trying
// RFC3339Nano first and falling back to plain RFC3339 (older tenants
// emit second-precision timestamps).
func parseWorkdayTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts
	}
	return time.Time{}
}

var _ access.AccessAuditor = (*WorkdayAccessConnector)(nil)
