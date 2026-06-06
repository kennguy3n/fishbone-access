package slack_enterprise

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
	slackEnterpriseAuditPageSize = 100
	slackEnterpriseAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Slack Enterprise Grid audit-logs API
// events into the access audit pipeline. Implements
// access.AccessAuditor.
//
// Endpoint:
//
//	GET /audit/v1/logs?limit=100&cursor=...&oldest=...
//
// The audit-logs API is Enterprise-Grid-only; non-Grid workspaces
// receive 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *SlackEnterpriseAccessConnector) FetchAccessAuditLogs(
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

	var collected []slackEnterpriseAuditEvent
	cursor := ""
	for pages := 0; pages < slackEnterpriseAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", slackEnterpriseAuditPageSize))
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		if !since.IsZero() {
			q.Set("oldest", fmt.Sprintf("%d", since.Unix()))
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL()+"/audit/v1/logs?"+q.Encode(), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("slack_enterprise: audit log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("slack_enterprise: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope slackEnterpriseAuditResponse
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("slack_enterprise: decode audit log: %w", err)
		}
		olderThanCursor := false
		for i := range envelope.Entries {
			ts := parseSlackEnterpriseAuditTime(envelope.Entries[i].DateCreate)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, envelope.Entries[i])
		}
		if olderThanCursor || envelope.ResponseMetadata.NextCursor == "" {
			break
		}
		cursor = envelope.ResponseMetadata.NextCursor
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapSlackEnterpriseAuditEvent(&collected[i])
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

type slackEnterpriseAuditEvent struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	DateCreate int64  `json:"date_create"`
	Actor      struct {
		Type string `json:"type"`
		User struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
	} `json:"actor"`
	Entity struct {
		Type string `json:"type"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	} `json:"entity"`
	Context struct {
		IPAddress string `json:"ip_address"`
		UserAgent string `json:"ua"`
	} `json:"context"`
}

type slackEnterpriseAuditResponse struct {
	Entries          []slackEnterpriseAuditEvent `json:"entries"`
	ResponseMetadata struct {
		NextCursor string `json:"next_cursor"`
	} `json:"response_metadata"`
}

func mapSlackEnterpriseAuditEvent(e *slackEnterpriseAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseSlackEnterpriseAuditTime(e.DateCreate)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Action),
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Actor.User.ID),
		ActorEmail:       strings.TrimSpace(e.Actor.User.Email),
		TargetExternalID: strings.TrimSpace(e.Entity.User.ID),
		TargetType:       strings.TrimSpace(e.Entity.Type),
		IPAddress:        strings.TrimSpace(e.Context.IPAddress),
		UserAgent:        strings.TrimSpace(e.Context.UserAgent),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseSlackEnterpriseAuditTime(epoch int64) time.Time {
	if epoch <= 0 {
		return time.Time{}
	}
	return time.Unix(epoch, 0).UTC()
}
