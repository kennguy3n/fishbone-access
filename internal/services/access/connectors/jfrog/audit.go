package jfrog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/access/httputil"
)

const (
	jfrogAuditPageSize = 100
	jfrogAuditMaxPages = 200
)

// FetchAccessAuditLogs streams JFrog Platform Access audit events into
// the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint (JFrog Platform Access):
//
//	GET /access/api/v2/events?limit=100&offset=N&since={iso}
//
// Authentication is a Platform Access bearer token. Access to the
// /events endpoint requires an admin or audit-reader role; tenants
// without the entitlement return 401 / 403 / 404 which the connector
// soft-skips via access.ErrAuditNotAvailable.
//
// To honour the AccessAuditor contract under multi-page sweeps the
// connector buffers every page before advancing the persisted
// cursor: if any page fails the cursor stays where it was, so a
// retry replays the same window rather than silently skipping older
// entries below the persisted cursor.
func (c *JFrogAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL(cfg) + "/access/api/v2/events"

	var collected []jfrogAuditEvent
	offset := 0
	for pages := 0; pages < jfrogAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", jfrogAuditPageSize))
		q.Set("offset", fmt.Sprintf("%d", offset))
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("jfrog: audit events: %w", err)
		}
		body, readErr := readJFrogBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("jfrog: audit events: status %d: %s", resp.StatusCode, string(body))
		}
		var p jfrogAuditPage
		if err := json.Unmarshal(body, &p); err != nil {
			return fmt.Errorf("jfrog: decode audit events: %w", err)
		}
		collected = append(collected, p.Events...)
		if len(p.Events) < jfrogAuditPageSize {
			break
		}
		offset += len(p.Events)
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapJFrogAuditEvent(&collected[i])
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

type jfrogAuditPage struct {
	Events []jfrogAuditEvent `json:"events"`
	Total  int               `json:"total"`
}

type jfrogAuditEvent struct {
	ID         string `json:"id"`
	EventType  string `json:"event_type"`
	Action     string `json:"action"`
	Timestamp  string `json:"timestamp"`
	Username   string `json:"username"`
	UserEmail  string `json:"user_email"`
	UserID     string `json:"user_id"`
	IPAddress  string `json:"ip_address"`
	UserAgent  string `json:"user_agent"`
	TargetID   string `json:"target_id"`
	TargetType string `json:"target_type"`
	Outcome    string `json:"outcome"`
}

func mapJFrogAuditEvent(e *jfrogAuditEvent) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	ts := parseJFrogAuditTime(e.Timestamp)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	id := strings.TrimSpace(e.ID)
	if id == "" {
		id = fmt.Sprintf("%s/%s", strings.TrimSpace(e.EventType), e.Timestamp)
	}
	outcome := strings.TrimSpace(e.Outcome)
	if outcome == "" {
		outcome = "success"
	}
	return &access.AuditLogEntry{
		EventID:          id,
		EventType:        strings.TrimSpace(e.EventType),
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  firstNonEmpty(e.UserID, e.Username),
		ActorEmail:       strings.TrimSpace(e.UserEmail),
		TargetExternalID: strings.TrimSpace(e.TargetID),
		TargetType:       strings.TrimSpace(e.TargetType),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		UserAgent:        strings.TrimSpace(e.UserAgent),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func parseJFrogAuditTime(s string) time.Time {
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

func readJFrogBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("jfrog: empty response")
	}
	defer resp.Body.Close()
	return httputil.ReadAllLimited(resp.Body, 0)
}

var _ access.AccessAuditor = (*JFrogAccessConnector)(nil)
