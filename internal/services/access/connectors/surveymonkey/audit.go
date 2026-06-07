package surveymonkey

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
	"github.com/kennguy3n/fishbone-access/internal/services/access/httputil"
)

const (
	surveymonkeyAuditPageSize = 100
	surveymonkeyAuditMaxPages = 200
)

// FetchAccessAuditLogs streams SurveyMonkey audit-trail events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v3/audit/events?page=1&per_page=100&since={iso}
//
// The audit-events API is gated behind SurveyMonkey Enterprise; tokens
// without the entitlement surface 401 / 403 / 404 which the connector
// soft-skips via access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *SurveyMonkeyAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/v3/audit/events"

	var collected []surveymonkeyAuditEvent
	for page := 1; page <= surveymonkeyAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", surveymonkeyAuditPageSize))
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("surveymonkey: audit events: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("surveymonkey: audit events: status %d: %s", resp.StatusCode, httputil.SafeErrorBody(body))
		}
		var envelope surveymonkeyAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("surveymonkey: decode audit events: %w", err)
		}
		collected = append(collected, envelope.Data...)
		if len(envelope.Data) < surveymonkeyAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapSurveyMonkeyAuditEvent(&collected[i])
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

type surveymonkeyAuditEvent struct {
	ID         string `json:"id"`
	EventType  string `json:"event_type"`
	Action     string `json:"action"`
	OccurredAt string `json:"occurred_at"`
	UserID     string `json:"user_id"`
	UserEmail  string `json:"user_email"`
	SurveyID   string `json:"survey_id"`
	IPAddress  string `json:"ip_address"`
}

type surveymonkeyAuditPage struct {
	Data    []surveymonkeyAuditEvent `json:"data"`
	Page    int                      `json:"page"`
	PerPage int                      `json:"per_page"`
}

func mapSurveyMonkeyAuditEvent(e *surveymonkeyAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseSurveyMonkeyTime(e.OccurredAt)
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
		TargetExternalID: strings.TrimSpace(e.SurveyID),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseSurveyMonkeyTime(s string) time.Time {
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

var _ access.AccessAuditor = (*SurveyMonkeyAccessConnector)(nil)
