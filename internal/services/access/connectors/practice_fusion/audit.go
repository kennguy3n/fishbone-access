package practice_fusion

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
	practicefusionAuditPageSize = 100
	practicefusionAuditMaxPages = 200
)

// FetchAccessAuditLogs streams practice_fusion audit events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v1/audit?per_page=100&page=N&since={iso}
//
// Audit access requires an org-admin scope on the supplied credential;
// lower scopes surface 401 / 403 / 404 which the connector soft-skips
// via access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *PracticeFusionAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/api/v1/audit"

	var collected []practiceFusionAuditEvent
	for page := 0; page < practicefusionAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("per_page", fmt.Sprintf("%d", practicefusionAuditPageSize))
		q.Set("page", fmt.Sprintf("%d", page+1))
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("practice_fusion: audit: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("practice_fusion: audit: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope practiceFusionAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("practice_fusion: decode audit: %w", err)
		}
		collected = append(collected, envelope.Data...)
		if len(envelope.Data) < practicefusionAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapPracticeFusionAuditEvent(&collected[i])
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

type practiceFusionAuditEvent struct {
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

type practiceFusionAuditPage struct {
	Data []practiceFusionAuditEvent `json:"data"`
}

func mapPracticeFusionAuditEvent(e *practiceFusionAuditEvent) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	ts := parsePracticeFusionAuditTime(e.Timestamp)
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

func parsePracticeFusionAuditTime(s string) time.Time {
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

var _ access.AccessAuditor = (*PracticeFusionAccessConnector)(nil)
