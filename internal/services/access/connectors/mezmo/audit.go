package mezmo

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
	mezmoAuditPageSize = 100
	mezmoAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Mezmo audit events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/config/audit?from={epoch_ms}&size=100&offset=N
//
// Audit access requires an org-level service key; tenant-scoped keys
// surface 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *MezmoAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/v1/config/audit"

	var collected []mezmoAuditEvent
	for page := 0; page < mezmoAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("size", fmt.Sprintf("%d", mezmoAuditPageSize))
		q.Set("offset", fmt.Sprintf("%d", page*mezmoAuditPageSize))
		if !since.IsZero() {
			q.Set("from", fmt.Sprintf("%d", since.UTC().UnixMilli()))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("mezmo: audit: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("mezmo: audit: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope mezmoAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("mezmo: decode audit: %w", err)
		}
		collected = append(collected, envelope.Data...)
		if len(envelope.Data) < mezmoAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapMezmoAuditEvent(&collected[i])
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

type mezmoAuditEvent struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Action    string `json:"action"`
	Timestamp int64  `json:"timestamp"`
	Actor     struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"actor"`
	Target struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"target"`
}

type mezmoAuditPage struct {
	Data []mezmoAuditEvent `json:"data"`
}

func mapMezmoAuditEvent(e *mezmoAuditEvent) *access.AuditLogEntry {
	if e == nil || e.Timestamp == 0 {
		return nil
	}
	ts := time.UnixMilli(e.Timestamp).UTC()
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.Action)
	if action == "" {
		action = strings.TrimSpace(e.Type)
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.ID),
		EventType:        strings.TrimSpace(e.Type),
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

var _ access.AccessAuditor = (*MezmoAccessConnector)(nil)
