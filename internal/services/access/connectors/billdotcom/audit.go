package billdotcom

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
	billDotComAuditPageSize = 100
	billDotComAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Bill.com audit-trail events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v3/orgs/{org_id}/audit-trail?max=100&start=N&updatedAfter={iso}
//
// Audit trail access requires the `audit:read` permission on the API
// session; lower permissions return 401 / 403 / 404 which the connector
// soft-skips via access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *BillDotComAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/v3/orgs/" + url.PathEscape(strings.TrimSpace(cfg.OrgID)) + "/audit-trail"

	var collected []billDotComAuditEvent
	for page := 0; page < billDotComAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("max", fmt.Sprintf("%d", billDotComAuditPageSize))
		q.Set("start", fmt.Sprintf("%d", page*billDotComAuditPageSize))
		if !since.IsZero() {
			q.Set("updatedAfter", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("billdotcom: audit-trail: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("billdotcom: audit-trail: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope billDotComAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("billdotcom: decode audit-trail: %w", err)
		}
		collected = append(collected, envelope.Results...)
		if len(envelope.Results) < billDotComAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapBillDotComAuditEvent(&collected[i])
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

type billDotComAuditEvent struct {
	ID         string `json:"id"`
	EventType  string `json:"eventType"`
	Action     string `json:"action"`
	Timestamp  string `json:"timestamp"`
	UserID     string `json:"userId"`
	UserEmail  string `json:"userEmail"`
	EntityType string `json:"entityType"`
	EntityID   string `json:"entityId"`
	Outcome    string `json:"outcome"`
}

type billDotComAuditPage struct {
	Results []billDotComAuditEvent `json:"results"`
}

func mapBillDotComAuditEvent(e *billDotComAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseBillDotComTime(e.Timestamp)
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
	outcome := strings.TrimSpace(e.Outcome)
	if outcome == "" {
		outcome = "success"
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.ID),
		EventType:        strings.TrimSpace(e.EventType),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.UserID),
		ActorEmail:       strings.TrimSpace(e.UserEmail),
		TargetExternalID: strings.TrimSpace(e.EntityID),
		TargetType:       strings.TrimSpace(e.EntityType),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func parseBillDotComTime(s string) time.Time {
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

var _ access.AccessAuditor = (*BillDotComAccessConnector)(nil)
