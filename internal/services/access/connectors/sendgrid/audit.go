package sendgrid

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
	sendgridAuditPageSize = 100
	sendgridAuditMaxPages = 200
)

// FetchAccessAuditLogs streams sendgrid audit events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v3/teammates/audit/log?limit=100&offset=N&start_time={iso}
//
// Audit access requires an org-admin scope on the supplied credential;
// lower scopes surface 401 / 403 / 404 which the connector soft-skips
// via access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *SendgridAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/v3/teammates/audit/log"

	var collected []sendgridAuditEvent
	for page := 0; page < sendgridAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", sendgridAuditPageSize))
		q.Set("offset", fmt.Sprintf("%d", page*sendgridAuditPageSize))
		if !since.IsZero() {
			q.Set("start_time", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("sendgrid: audit: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("sendgrid: audit: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope sendgridAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("sendgrid: decode audit: %w", err)
		}
		collected = append(collected, envelope.Data...)
		if len(envelope.Data) < sendgridAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapSendgridAuditEvent(&collected[i])
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

type sendgridAuditEvent struct {
	ID        string `json:"id"`
	EventType string `json:"event_type"`
	Action    string `json:"action"`
	Timestamp string `json:"timestamp"`
	Actor     struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"actor"`
	Target struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"target"`
}

type sendgridAuditPage struct {
	Data []sendgridAuditEvent `json:"data"`
}

func mapSendgridAuditEvent(e *sendgridAuditEvent) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	ts := parseSendgridAuditTime(e.Timestamp)
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
		ActorExternalID:  strings.TrimSpace(e.Actor.ID),
		ActorEmail:       strings.TrimSpace(e.Actor.Email),
		TargetExternalID: strings.TrimSpace(e.Target.ID),
		TargetType:       strings.TrimSpace(e.Target.Type),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseSendgridAuditTime(s string) time.Time {
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
	// Some provider API versions emit a non-colon timezone offset
	// (e.g. "+0000"), which RFC3339 parsing rejects; accept it too.
	if ts, err := time.Parse("2006-01-02T15:04:05-0700", s); err == nil {
		return ts.UTC()
	}
	return time.Time{}
}

var _ access.AccessAuditor = (*SendgridAccessConnector)(nil)
