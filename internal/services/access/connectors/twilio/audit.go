package twilio

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
	twilioAuditPageSize = 100
	twilioAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Twilio Monitor Events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/Events?PageSize=100&Page=N&StartDate={iso}
//
// Audit access requires an account-admin Auth Token; sub-accounts /
// API keys without the audit scope surface 401 / 403 / 404 which the
// connector soft-skips via access.ErrAuditNotAvailable per
// docs/architecture.md §2. The Twilio Monitor Events endpoint lives on
// monitor.twilio.com — the connector overrides the host portion to
// the Monitor subdomain while preserving HTTP Basic auth from the
// AccountSID / AuthToken secrets.
func (c *TwilioAccessConnector) FetchAccessAuditLogs(
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
	base := c.monitorBaseURL() + "/v1/Events"

	var collected []twilioAuditEvent
	for page := 0; page < twilioAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("PageSize", fmt.Sprintf("%d", twilioAuditPageSize))
		q.Set("Page", fmt.Sprintf("%d", page))
		if !since.IsZero() {
			q.Set("StartDate", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("twilio: audit: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("twilio: audit: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope twilioAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("twilio: decode audit: %w", err)
		}
		collected = append(collected, envelope.Events...)
		if len(envelope.Events) < twilioAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapTwilioAuditEvent(&collected[i])
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

// monitorBaseURL returns the Monitor API host. urlOverride takes
// precedence so tests can stand up an httptest.Server.
func (c *TwilioAccessConnector) monitorBaseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://monitor.twilio.com"
}

type twilioAuditEvent struct {
	Sid          string                 `json:"sid"`
	AccountSid   string                 `json:"account_sid"`
	ActorSid     string                 `json:"actor_sid"`
	ActorType    string                 `json:"actor_type"`
	EventType    string                 `json:"event_type"`
	ResourceSid  string                 `json:"resource_sid"`
	ResourceType string                 `json:"resource_type"`
	EventDate    string                 `json:"event_date"`
	Source       string                 `json:"source"`
	SourceIPAddr string                 `json:"source_ip_address"`
	EventData    map[string]interface{} `json:"event_data"`
	Description  string                 `json:"description"`
}

type twilioAuditPage struct {
	Events []twilioAuditEvent `json:"events"`
}

func mapTwilioAuditEvent(e *twilioAuditEvent) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	ts := parseTwilioAuditTime(e.EventDate)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.Sid),
		EventType:        strings.TrimSpace(e.EventType),
		Action:           strings.TrimSpace(e.EventType),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.ActorSid),
		TargetExternalID: strings.TrimSpace(e.ResourceSid),
		TargetType:       strings.TrimSpace(e.ResourceType),
		IPAddress:        strings.TrimSpace(e.SourceIPAddr),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseTwilioAuditTime(s string) time.Time {
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

var _ access.AccessAuditor = (*TwilioAccessConnector)(nil)
