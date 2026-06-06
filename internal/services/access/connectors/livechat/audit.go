package livechat

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

const (
	livechatAuditPageSize = 100
	livechatAuditMaxPages = 200
)

// FetchAccessAuditLogs streams LiveChat agent-session events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	POST /v3.5/configuration/action/list_auto_access  (paginated)
//
// LiveChat returns audit events newest-first. Tenants without
// configuration-access scope receive 401 / 403, which the connector
// soft-skips via access.ErrAuditNotAvailable.
func (c *LiveChatAccessConnector) FetchAccessAuditLogs(
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
	endpoint := c.baseURL() + "/v3.5/configuration/action/list_auto_access"

	var collected []livechatAuditEvent
	pageID := ""
	for pages := 0; pages < livechatAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		payload := map[string]interface{}{"limit": livechatAuditPageSize}
		if pageID != "" {
			payload["page_id"] = pageID
		}
		buf, _ := json.Marshal(payload)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.PAT))
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("livechat: audit log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("livechat: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope livechatAuditResponse
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("livechat: decode audit log: %w", err)
		}
		olderThanCursor := false
		for i := range envelope.Records {
			ts := parseLiveChatAuditTime(envelope.Records[i].ChangedAt)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, envelope.Records[i])
		}
		if olderThanCursor || envelope.NextPageID == "" {
			break
		}
		pageID = envelope.NextPageID
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapLiveChatAuditEvent(&collected[i])
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

type livechatAuditEvent struct {
	ID         string                 `json:"id"`
	ChangedBy  string                 `json:"changed_by"`
	ChangedAt  string                 `json:"changed_at"`
	Action     string                 `json:"action"`
	ResourceID string                 `json:"resource_id"`
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties"`
}

type livechatAuditResponse struct {
	Records    []livechatAuditEvent `json:"records"`
	NextPageID string               `json:"next_page_id"`
}

func mapLiveChatAuditEvent(e *livechatAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseLiveChatAuditTime(e.ChangedAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Type),
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.ChangedBy),
		TargetExternalID: strings.TrimSpace(e.ResourceID),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseLiveChatAuditTime(s string) time.Time {
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
