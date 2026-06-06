package sumo_logic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// sumoAuditMaxPages bounds a single audit sweep as a defense-in-depth
// guard against an upstream that perpetually returns a non-empty
// continuation token with non-empty data. Mirrors the explicit caps
// used by every sibling audit connector (sophosXGAuditMaxPages,
// splunkAuditMaxPages, stripeAuditMaxPages, surveymonkeyAuditMaxPages).
// Events are handed to the handler per page, so hitting the cap simply
// stops the sweep — already-yielded events are durably checkpointed.
const sumoAuditMaxPages = 200

// FetchAccessAuditLogs streams Sumo Logic audit events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v1/account/audit-events?from={iso}&to={iso}&limit=100&token={cursor}
//
// Audit-event access requires the `View Audit Index` capability on the
// service-account role. Tenants without the audit module receive
// 401/403/404 which the connector soft-skips via
// access.ErrAuditNotAvailable.
func (c *SumoLogicAccessConnector) FetchAccessAuditLogs(
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
	cursor := since
	token := ""
	base := c.baseURL(cfg) + "/api/v1/account/audit-events"
	for pages := 0; pages < sumoAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", "100")
		if !since.IsZero() {
			q.Set("from", since.UTC().Format(time.RFC3339))
		}
		if token != "" {
			q.Set("token", token)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("sumo_logic: audit events: %w", err)
		}
		body, readErr := readSumoBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("sumo_logic: audit events: status %d: %s", resp.StatusCode, string(body))
		}
		var p sumoAuditPage
		if err := json.Unmarshal(body, &p); err != nil {
			return fmt.Errorf("sumo_logic: decode audit events: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(p.Data))
		batchMax := cursor
		for i := range p.Data {
			entry := mapSumoAuditEvent(&p.Data[i])
			if entry == nil {
				continue
			}
			if entry.Timestamp.After(batchMax) {
				batchMax = entry.Timestamp
			}
			batch = append(batch, entry)
		}
		if err := handler(batch, batchMax, access.DefaultAuditPartition); err != nil {
			return err
		}
		cursor = batchMax
		token = strings.TrimSpace(p.Next)
		if token == "" || len(p.Data) == 0 {
			return nil
		}
	}
	// Cap reached: events seen so far were already passed to the
	// handler (and checkpointed) per page, so stop the sweep cleanly
	// rather than looping unbounded.
	return nil
}

type sumoAuditPage struct {
	Data []sumoAuditEvent `json:"data"`
	Next string           `json:"next"`
}

type sumoAuditEvent struct {
	ID         string                 `json:"id"`
	EventName  string                 `json:"eventName"`
	EventType  string                 `json:"eventType"`
	EventTime  string                 `json:"eventTime"`
	UserID     string                 `json:"userId"`
	UserEmail  string                 `json:"userEmail"`
	UserName   string                 `json:"userName"`
	TargetID   string                 `json:"targetId"`
	TargetName string                 `json:"targetName"`
	TargetType string                 `json:"targetType"`
	SourceIP   string                 `json:"sourceIp"`
	UserAgent  string                 `json:"userAgent"`
	StatusCode string                 `json:"statusCode"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

func mapSumoAuditEvent(e *sumoAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseSumoTime(e.EventTime)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	outcome := strings.TrimSpace(e.StatusCode)
	if outcome == "" {
		outcome = "success"
	}
	eventType := strings.TrimSpace(e.EventType)
	if eventType == "" {
		eventType = strings.TrimSpace(e.EventName)
	}
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        eventType,
		Action:           strings.TrimSpace(e.EventName),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.UserID),
		ActorEmail:       strings.TrimSpace(e.UserEmail),
		TargetExternalID: strings.TrimSpace(e.TargetID),
		TargetType:       strings.TrimSpace(e.TargetType),
		IPAddress:        strings.TrimSpace(e.SourceIP),
		UserAgent:        strings.TrimSpace(e.UserAgent),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func parseSumoTime(s string) time.Time {
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

func readSumoBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("sumo_logic: empty response")
	}
	defer resp.Body.Close()
	// Match the strict 1 MB cap that do() applies via io.LimitReader,
	// keeping the audit path consistent with the rest of the connector
	// (and avoiding the up-to-4 KB overshoot of a manual chunked read).
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

var _ access.AccessAuditor = (*SumoLogicAccessConnector)(nil)
