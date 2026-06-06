package mycase

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
	mycaseAuditPageSize = 100
	mycaseAuditMaxPages = 200
)

// FetchAccessAuditLogs streams MyCase activity-log events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v1/activity_logs?page=1&per_page=100&since={iso}
//
// Activity-log read requires the admin-tier OAuth2 scope; non-admin
// tokens surface 401 / 403 / 404, which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *MyCaseAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/api/v1/activity_logs"

	var collected []mycaseActivity
	for page := 1; page <= mycaseAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", mycaseAuditPageSize))
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("mycase: activity_logs: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("mycase: activity_logs: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope mycaseActivityPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("mycase: decode activity_logs: %w", err)
		}
		collected = append(collected, envelope.Data...)
		if len(envelope.Data) < mycaseAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapMyCaseActivity(&collected[i])
		if entry == nil {
			continue
		}
		if entry.Timestamp.After(batchMax) {
			batchMax = entry.Timestamp
		}
		batch = append(batch, entry)
	}
	if len(batch) == 0 {
		return nil
	}
	return handler(batch, batchMax, access.DefaultAuditPartition)
}

type mycaseActivity struct {
	ID         string `json:"id"`
	EventType  string `json:"event_type"`
	Action     string `json:"action"`
	OccurredAt string `json:"occurred_at"`
	UserID     string `json:"user_id"`
	UserEmail  string `json:"user_email"`
	CaseID     string `json:"case_id"`
	IPAddress  string `json:"ip_address"`
}

type mycaseActivityPage struct {
	Data []mycaseActivity `json:"data"`
	Meta struct {
		Page    int `json:"page"`
		PerPage int `json:"per_page"`
		Total   int `json:"total"`
	} `json:"meta"`
}

func mapMyCaseActivity(a *mycaseActivity) *access.AuditLogEntry {
	if a == nil || strings.TrimSpace(a.ID) == "" {
		return nil
	}
	ts := parseMyCaseTime(a.OccurredAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(a)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(a.Action)
	if action == "" {
		action = strings.TrimSpace(a.EventType)
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(a.ID),
		EventType:        strings.TrimSpace(a.EventType),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(a.UserID),
		ActorEmail:       strings.TrimSpace(a.UserEmail),
		TargetExternalID: strings.TrimSpace(a.CaseID),
		IPAddress:        strings.TrimSpace(a.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseMyCaseTime(s string) time.Time {
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

var _ access.AccessAuditor = (*MyCaseAccessConnector)(nil)
