package travis_ci

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
	travisAuditMaxPages = 200
	travisAuditPageSize = 100
)

// FetchAccessAuditLogs streams Travis CI audit events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET {endpoint}/audit_events?limit=100&offset=N&after={iso}
//
// Audit access requires an organisation owner token; lower scopes
// surface 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *TravisCIAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL(cfg) + "/audit_events"

	var collected []travisAuditEvent
	for page := 0; page < travisAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", travisAuditPageSize))
		q.Set("offset", fmt.Sprintf("%d", page*travisAuditPageSize))
		if !since.IsZero() {
			q.Set("after", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("travis_ci: audit_events: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("travis_ci: audit_events: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope travisAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("travis_ci: decode audit_events: %w", err)
		}
		collected = append(collected, envelope.AuditEvents...)
		if len(envelope.AuditEvents) < travisAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapTravisAuditEvent(&collected[i])
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

type travisAuditEvent struct {
	ID          json.Number `json:"id"`
	EventType   string      `json:"event_type"`
	Source      string      `json:"source"`
	ChangeType  string      `json:"change_type"`
	Description string      `json:"description"`
	OwnerType   string      `json:"owner_type"`
	OwnerID     json.Number `json:"owner_id"`
	OwnerName   string      `json:"owner_name"`
	Actor       struct {
		ID    json.Number `json:"id"`
		Login string      `json:"login"`
		Email string      `json:"email"`
	} `json:"actor"`
	CreatedAt string `json:"created_at"`
}

type travisAuditPage struct {
	AuditEvents []travisAuditEvent `json:"audit_events"`
}

func mapTravisAuditEvent(e *travisAuditEvent) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	ts := parseTravisTime(e.CreatedAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	eventType := strings.TrimSpace(e.EventType)
	if eventType == "" {
		eventType = strings.TrimSpace(e.ChangeType)
	}
	action := strings.TrimSpace(e.ChangeType)
	if action == "" {
		action = eventType
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.ID.String()),
		EventType:        eventType,
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Actor.ID.String()),
		ActorEmail:       strings.TrimSpace(e.Actor.Email),
		TargetExternalID: strings.TrimSpace(e.OwnerID.String()),
		TargetType:       strings.TrimSpace(e.OwnerType),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseTravisTime(s string) time.Time {
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

var _ access.AccessAuditor = (*TravisCIAccessConnector)(nil)
