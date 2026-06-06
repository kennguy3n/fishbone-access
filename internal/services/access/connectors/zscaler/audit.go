package zscaler

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
	zscalerAuditPageSize = 100
	zscalerAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Zscaler audit-log entries into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v1/auditlogEntryReport?page=1&pagesize=100&startTime={ms}
//
// The audit-log API requires the platform "Audit Log Reports" role;
// non-eligible tokens surface 401 / 403 / 404 which the connector
// soft-skips via access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *ZscalerAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/api/v1/auditlogEntryReport"

	var collected []zscalerAuditEvent
	for page := 1; page <= zscalerAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("pagesize", fmt.Sprintf("%d", zscalerAuditPageSize))
		if !since.IsZero() {
			q.Set("startTime", fmt.Sprintf("%d", since.UTC().UnixMilli()))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("zscaler: auditlogEntryReport: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("zscaler: auditlogEntryReport: status %d: %s", resp.StatusCode, string(body))
		}
		var arr []zscalerAuditEvent
		if err := json.Unmarshal(body, &arr); err != nil {
			var envelope zscalerAuditPage
			if err := json.Unmarshal(body, &envelope); err != nil {
				return fmt.Errorf("zscaler: decode auditlogEntryReport: %w", err)
			}
			arr = envelope.Entries
		}
		collected = append(collected, arr...)
		if len(arr) < zscalerAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapZscalerAuditEvent(&collected[i])
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

type zscalerAuditEvent struct {
	ID         json.Number `json:"id"`
	Action     string      `json:"action"`
	Category   string      `json:"category"`
	ResourceID string      `json:"resourceId"`
	Time       json.Number `json:"time"`
	AdminLogin string      `json:"adminLogin"`
	ClientIP   string      `json:"clientIP"`
	UserAgent  string      `json:"userAgent"`
}

type zscalerAuditPage struct {
	Entries []zscalerAuditEvent `json:"entries"`
}

func mapZscalerAuditEvent(e *zscalerAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(string(e.ID)) == "" {
		return nil
	}
	tsMS, err := e.Time.Int64()
	if err != nil || tsMS == 0 {
		return nil
	}
	ts := time.UnixMilli(tsMS).UTC()
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.Action)
	if action == "" {
		action = strings.TrimSpace(e.Category)
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(string(e.ID)),
		EventType:        strings.TrimSpace(e.Category),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.AdminLogin),
		ActorEmail:       strings.TrimSpace(e.AdminLogin),
		TargetExternalID: strings.TrimSpace(e.ResourceID),
		IPAddress:        strings.TrimSpace(e.ClientIP),
		UserAgent:        strings.TrimSpace(e.UserAgent),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

var _ access.AccessAuditor = (*ZscalerAccessConnector)(nil)
