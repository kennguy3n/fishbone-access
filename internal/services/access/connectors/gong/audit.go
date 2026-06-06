package gong

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
	gongAuditPageSize = 100
	gongAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Gong audit events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v2/audit/events?limit=100&cursor={cursor}&fromDateTime={iso}
//
// The audit-events API requires the platform "Audit Events" entitlement;
// tenants without it surface 401 / 403 / 404 which the connector
// soft-skips via access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *GongAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/v2/audit/events"

	var collected []gongAuditEvent
	cursor := ""
	for page := 0; page < gongAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", gongAuditPageSize))
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		if !since.IsZero() {
			q.Set("fromDateTime", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("gong: audit events: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("gong: audit events: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope gongAuditResponse
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("gong: decode audit events: %w", err)
		}
		collected = append(collected, envelope.Events...)
		if envelope.Records.Cursor == "" || len(envelope.Events) == 0 {
			break
		}
		cursor = envelope.Records.Cursor
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapGongAuditEvent(&collected[i])
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

type gongAuditEvent struct {
	ID        string `json:"id"`
	EventType string `json:"eventType"`
	Timestamp string `json:"timestamp"`
	UserID    string `json:"userId"`
	UserEmail string `json:"userEmail"`
	IPAddress string `json:"ipAddress"`
	UserAgent string `json:"userAgent"`
	Action    string `json:"action"`
	Target    string `json:"target"`
}

type gongAuditResponse struct {
	Events  []gongAuditEvent `json:"events"`
	Records struct {
		Cursor     string `json:"cursor"`
		TotalCount int    `json:"totalCount"`
	} `json:"records"`
}

func mapGongAuditEvent(e *gongAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseGongAuditTime(e.Timestamp)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.Action)
	if action == "" {
		action = strings.TrimSpace(e.EventType)
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.ID),
		EventType:        strings.TrimSpace(e.EventType),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.UserID),
		ActorEmail:       strings.TrimSpace(e.UserEmail),
		TargetExternalID: strings.TrimSpace(e.Target),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		UserAgent:        strings.TrimSpace(e.UserAgent),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseGongAuditTime(s string) time.Time {
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

var _ access.AccessAuditor = (*GongAccessConnector)(nil)
