package checkpoint

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
	checkpointAuditPageSize = 100
	checkpointAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Check Point Management API audit-log
// entries into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	POST /web_api/show-logs   { "offset": 0, "limit": 100, "new-query": true }
//
// Like every other /web_api/* call, show-logs is POST-only and takes its
// parameters in a JSON body (see newPostJSON); issuing a GET with query
// params yields 405 against the real Management API.
//
// The show-logs API requires a Management API session token with the
// "log access" permission; non-eligible sessions surface 401 / 403 / 404
// which the connector soft-skips via access.ErrAuditNotAvailable per
// docs/architecture.md §2.
func (c *CheckPointAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/web_api/show-logs"

	var collected []checkpointAuditEvent
	for page := 0; page < checkpointAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		params := map[string]interface{}{
			"offset": page * checkpointAuditPageSize,
			"limit":  checkpointAuditPageSize,
			// new-query starts a fresh server-side query; it must only be
			// set on the first page. Sending it on every page restarts the
			// query each time, so offsets walk a different result set and
			// pagination yields duplicate/unstable rows.
			"new-query": page == 0,
		}
		if !since.IsZero() {
			params["since"] = since.UTC().Format(time.RFC3339)
		}
		reqBody, _ := json.Marshal(params)
		req, err := c.newPostJSON(ctx, secrets, base, reqBody)
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("checkpoint: show-logs: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("checkpoint: show-logs: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope checkpointAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("checkpoint: decode show-logs: %w", err)
		}
		collected = append(collected, envelope.Logs...)
		if len(envelope.Logs) < checkpointAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapCheckPointAuditEvent(&collected[i])
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

type checkpointAuditEvent struct {
	ID        string `json:"id"`
	Action    string `json:"action"`
	Operation string `json:"operation"`
	Time      string `json:"time"`
	Origin    string `json:"origin"`
	Subject   string `json:"subject"`
	Admin     string `json:"administrator"`
	SourceIP  string `json:"src_ip"`
}

type checkpointAuditPage struct {
	Logs []checkpointAuditEvent `json:"logs"`
}

func mapCheckPointAuditEvent(e *checkpointAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseCheckPointTime(e.Time)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.Action)
	if action == "" {
		action = strings.TrimSpace(e.Operation)
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.ID),
		EventType:        strings.TrimSpace(e.Operation),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Admin),
		ActorEmail:       strings.TrimSpace(e.Admin),
		TargetExternalID: strings.TrimSpace(e.Subject),
		IPAddress:        strings.TrimSpace(e.SourceIP),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseCheckPointTime(s string) time.Time {
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

var _ access.AccessAuditor = (*CheckPointAccessConnector)(nil)
