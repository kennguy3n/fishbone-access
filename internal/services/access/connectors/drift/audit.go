package drift

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
	driftAuditPageSize = 100
	driftAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Drift audit events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/audit/list?limit=100&offset=N&start_ts={ms}
//
// Audit access requires an organisation-owner OAuth token; lower
// scopes surface 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *DriftAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/v1/audit/list"

	var collected []driftAuditEvent
	for page := 0; page < driftAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", driftAuditPageSize))
		q.Set("offset", fmt.Sprintf("%d", page*driftAuditPageSize))
		if !since.IsZero() {
			q.Set("start_ts", fmt.Sprintf("%d", since.UTC().UnixMilli()))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("drift: audit: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("drift: audit: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope driftAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("drift: decode audit: %w", err)
		}
		collected = append(collected, envelope.Data...)
		if len(envelope.Data) < driftAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapDriftAuditEvent(&collected[i])
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

type driftAuditEvent struct {
	ID        json.Number `json:"id"`
	EventType string      `json:"event_type"`
	Action    string      `json:"action"`
	Timestamp int64       `json:"timestamp"`
	Actor     struct {
		ID    json.Number `json:"id"`
		Email string      `json:"email"`
	} `json:"actor"`
	Target struct {
		ID   json.Number `json:"id"`
		Type string      `json:"type"`
	} `json:"target"`
}

type driftAuditPage struct {
	Data []driftAuditEvent `json:"data"`
}

func mapDriftAuditEvent(e *driftAuditEvent) *access.AuditLogEntry {
	if e == nil || e.Timestamp == 0 {
		return nil
	}
	ts := time.UnixMilli(e.Timestamp).UTC()
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.Action)
	if action == "" {
		action = strings.TrimSpace(e.EventType)
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.ID.String()),
		EventType:        strings.TrimSpace(e.EventType),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Actor.ID.String()),
		ActorEmail:       strings.TrimSpace(e.Actor.Email),
		TargetExternalID: strings.TrimSpace(e.Target.ID.String()),
		TargetType:       strings.TrimSpace(e.Target.Type),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

var _ access.AccessAuditor = (*DriftAccessConnector)(nil)
