package personio

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	personioAuditLimit    = 100
	personioAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Personio attendance / change events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/company/attendances?limit=100&offset=N
//
// Authenticates by exchanging client_id / client_secret for a bearer
// token (re-used per call). Tenants without the required scope return
// 401 / 403 / 404, soft-skipped via access.ErrAuditNotAvailable.
func (c *PersonioAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.authToken(ctx, secrets)
	if err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]

	var collected []personioAuditEvent
	for page := 0; page < personioAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		fullURL := fmt.Sprintf("%s/v1/company/attendances?limit=%d&offset=%d",
			c.baseURL(), personioAuditLimit, page*personioAuditLimit)
		req, err := c.newRequest(ctx, token, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("personio: audit log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("personio: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope struct {
			Data []personioAuditEvent `json:"data"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("personio: decode audit log: %w", err)
		}
		// Personio's attendances endpoint returns records in updated_at order,
		// so once a page contains an event at or before the cursor we can stop
		// paginating. This assumes that ordering; if Personio ever returns
		// out-of-order pages (e.g. a bulk update reshuffling updated_at), newer
		// events on later pages could be missed.
		olderThanCursor := false
		for i := range envelope.Data {
			ts := parsePersonioAuditTime(envelope.Data[i].Attributes.UpdatedAt)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, envelope.Data[i])
		}
		if olderThanCursor || len(envelope.Data) < personioAuditLimit {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapPersonioAuditEvent(&collected[i])
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

type personioAuditEvent struct {
	Type       string `json:"type"`
	Attributes struct {
		ID         json.Number `json:"id"`
		EmployeeID json.Number `json:"employee"`
		UpdatedAt  string      `json:"updated_at"`
		Comment    string      `json:"comment"`
		Status     string      `json:"status"`
	} `json:"attributes"`
}

func mapPersonioAuditEvent(e *personioAuditEvent) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	id := strings.TrimSpace(e.Attributes.ID.String())
	if id == "" {
		return nil
	}
	ts := parsePersonioAuditTime(e.Attributes.UpdatedAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          id,
		EventType:        strings.TrimSpace(e.Type),
		Action:           strings.TrimSpace(e.Type),
		Timestamp:        ts,
		TargetExternalID: strings.TrimSpace(e.Attributes.EmployeeID.String()),
		TargetType:       "employee",
		Outcome:          strings.TrimSpace(e.Attributes.Status),
		RawData:          rawMap,
	}
}

var _ access.AccessAuditor = (*PersonioAccessConnector)(nil)

func parsePersonioAuditTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
