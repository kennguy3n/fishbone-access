package braze

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
	brazeAuditPageSize = 100
	brazeAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Braze audit-log events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /audit_log/users?count=100&startIndex=N&since={iso}
//
// Audit-log access requires an enterprise-tier Braze plan and a REST
// API key with the `audit.events.read` scope; tenants without either
// surface 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *BrazeAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL(cfg) + "/audit_log/users"

	var collected []brazeAuditEvent
	startIndex := 0
	for page := 0; page < brazeAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("count", fmt.Sprintf("%d", brazeAuditPageSize))
		q.Set("startIndex", fmt.Sprintf("%d", startIndex))
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("braze: audit log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("braze: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope brazeAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("braze: decode audit log: %w", err)
		}
		collected = append(collected, envelope.Events...)
		if len(envelope.Events) < brazeAuditPageSize {
			break
		}
		startIndex += len(envelope.Events)
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapBrazeAuditEvent(&collected[i])
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

type brazeAuditEvent struct {
	EventID    string `json:"event_id"`
	EventType  string `json:"event_type"`
	ActorID    string `json:"actor_id"`
	ActorEmail string `json:"actor_email"`
	TargetID   string `json:"target_id"`
	TargetType string `json:"target_type"`
	Timestamp  string `json:"timestamp"`
	IPAddress  string `json:"ip_address"`
	Action     string `json:"action"`
}

type brazeAuditPage struct {
	Events       []brazeAuditEvent `json:"events"`
	TotalResults int               `json:"total_results"`
	StartIndex   int               `json:"start_index"`
	ItemsPerPage int               `json:"items_per_page"`
}

func mapBrazeAuditEvent(e *brazeAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.EventID) == "" {
		return nil
	}
	ts := parseBrazeTime(e.Timestamp)
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
		EventID:          strings.TrimSpace(e.EventID),
		EventType:        strings.TrimSpace(e.EventType),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.ActorID),
		ActorEmail:       strings.TrimSpace(e.ActorEmail),
		TargetExternalID: strings.TrimSpace(e.TargetID),
		TargetType:       strings.TrimSpace(e.TargetType),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseBrazeTime(s string) time.Time {
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

var _ access.AccessAuditor = (*BrazeAccessConnector)(nil)
