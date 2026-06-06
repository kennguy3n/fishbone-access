package zenefits

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

const zenefitsAuditMaxPages = 200

// FetchAccessAuditLogs streams Zenefits audit events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /core/audit_events?modified_since=<ISO8601>
//	    → follow `data.next_url` link until empty
//
// Bearer-token auth. Tenants without audit-event entitlement return
// 401 / 403 / 404, soft-skipped via access.ErrAuditNotAvailable.
func (c *ZenefitsAccessConnector) FetchAccessAuditLogs(
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

	q := url.Values{}
	if !since.IsZero() {
		q.Set("modified_since", since.UTC().Format(time.RFC3339))
	}
	nextURL := c.baseURL() + "/core/audit_events"
	if encoded := q.Encode(); encoded != "" {
		nextURL += "?" + encoded
	}

	var collected []zenefitsAuditEvent
	for page := 0; page < zenefitsAuditMaxPages && nextURL != ""; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("zenefits: audit log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("zenefits: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope struct {
			Data struct {
				Data    []zenefitsAuditEvent `json:"data"`
				NextURL string               `json:"next_url"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("zenefits: decode audit log: %w", err)
		}
		olderThanCursor := false
		for i := range envelope.Data.Data {
			ts := parseZenefitsAuditTime(envelope.Data.Data[i].CreatedAt)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, envelope.Data.Data[i])
		}
		if olderThanCursor {
			break
		}
		nextURL = strings.TrimSpace(envelope.Data.NextURL)
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapZenefitsAuditEvent(&collected[i])
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

type zenefitsAuditEvent struct {
	ID         string `json:"id"`
	EventType  string `json:"event_type"`
	CreatedAt  string `json:"created_at"`
	ActorID    string `json:"actor_id"`
	ActorEmail string `json:"actor_email"`
	TargetID   string `json:"target_id"`
	TargetType string `json:"target_type"`
	Outcome    string `json:"outcome"`
	IP         string `json:"ip"`
}

func mapZenefitsAuditEvent(e *zenefitsAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseZenefitsAuditTime(e.CreatedAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.EventType),
		Action:           strings.TrimSpace(e.EventType),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.ActorID),
		ActorEmail:       strings.TrimSpace(e.ActorEmail),
		TargetExternalID: strings.TrimSpace(e.TargetID),
		TargetType:       strings.TrimSpace(e.TargetType),
		IPAddress:        strings.TrimSpace(e.IP),
		Outcome:          strings.TrimSpace(e.Outcome),
		RawData:          rawMap,
	}
}

func parseZenefitsAuditTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
