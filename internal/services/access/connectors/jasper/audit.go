package jasper

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
	jasperAuditPageSize = 100
	jasperAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Jasper team audit-log records into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/audit-logs?page=1&per_page=100&since={iso}
//
// Bearer auth via JasperAccessConnector.newRequest; non-eligible
// tenants soft-skip via access.ErrAuditNotAvailable.
func (c *JasperAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/v1/audit-logs"

	cursor := since
	for page := 1; page <= jasperAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", jasperAuditPageSize))
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("jasper: audit logs: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			// Surface read failures instead of advancing the cursor on a
			// truncated body that could parse as a short page and end the
			// sweep early (matches jfrog/jira read-error handling).
			return fmt.Errorf("jasper: read audit logs body: %w", readErr)
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("jasper: audit logs: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope jasperAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("jasper: decode audit logs: %w", err)
		}
		// Emit each page as it is fetched so the caller persists nextSince
		// per page as a monotonic cursor (AccessAuditor contract). batchMax
		// starts at the running cursor so it never moves backward, and a
		// mid-stream handler failure only replays the un-acked tail.
		batch := make([]*access.AuditLogEntry, 0, len(envelope.Data))
		batchMax := cursor
		for i := range envelope.Data {
			entry := mapJasperAuditEvent(&envelope.Data[i])
			if entry == nil {
				continue
			}
			if entry.Timestamp.After(batchMax) {
				batchMax = entry.Timestamp
			}
			batch = append(batch, entry)
		}
		if len(batch) > 0 {
			if err := handler(batch, batchMax, access.DefaultAuditPartition); err != nil {
				return err
			}
			cursor = batchMax
		}
		if len(envelope.Data) < jasperAuditPageSize {
			break
		}
	}
	return nil
}

type jasperAuditEvent struct {
	ID         string `json:"id"`
	EventType  string `json:"event_type"`
	Action     string `json:"action"`
	OccurredAt string `json:"occurred_at"`
	ActorID    string `json:"actor_id"`
	ActorEmail string `json:"actor_email"`
	TargetID   string `json:"target_id"`
	IPAddress  string `json:"ip_address"`
}

type jasperAuditPage struct {
	Data []jasperAuditEvent `json:"data"`
}

func mapJasperAuditEvent(e *jasperAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseJasperTime(e.OccurredAt)
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

func parseJasperTime(s string) time.Time {
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

var _ access.AccessAuditor = (*JasperAccessConnector)(nil)
