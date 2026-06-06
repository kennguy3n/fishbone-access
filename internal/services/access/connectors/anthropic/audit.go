package anthropic

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
	anthropicAuditPageSize = 100
	anthropicAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Anthropic organization audit-log
// records into the access audit pipeline. Implements
// access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/organizations/audit_logs?page=1&per_page=100&since={iso}
//
// Auth header x-api-key is set by AnthropicAccessConnector.newRequest;
// non-Enterprise / non-Team plans surface 401/403/404 which soft-skip
// via access.ErrAuditNotAvailable.
func (c *AnthropicAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/v1/organizations/audit_logs"

	var collected []anthropicAuditEvent
	for page := 1; page <= anthropicAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", anthropicAuditPageSize))
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("anthropic: audit_logs: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("anthropic: audit_logs: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope anthropicAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("anthropic: decode audit_logs: %w", err)
		}
		collected = append(collected, envelope.Data...)
		if len(envelope.Data) < anthropicAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapAnthropicAuditEvent(&collected[i])
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

type anthropicAuditEvent struct {
	ID         string `json:"id"`
	EventType  string `json:"event_type"`
	Action     string `json:"action"`
	OccurredAt string `json:"occurred_at"`
	ActorID    string `json:"actor_id"`
	ActorEmail string `json:"actor_email"`
	TargetID   string `json:"target_id"`
	IPAddress  string `json:"ip_address"`
}

type anthropicAuditPage struct {
	Data []anthropicAuditEvent `json:"data"`
}

func mapAnthropicAuditEvent(e *anthropicAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseAnthropicTime(e.OccurredAt)
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
		ActorExternalID:  strings.TrimSpace(e.ActorID),
		ActorEmail:       strings.TrimSpace(e.ActorEmail),
		TargetExternalID: strings.TrimSpace(e.TargetID),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseAnthropicTime(s string) time.Time {
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

var _ access.AccessAuditor = (*AnthropicAccessConnector)(nil)
