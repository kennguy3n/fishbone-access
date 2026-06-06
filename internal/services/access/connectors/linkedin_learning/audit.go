package linkedin_learning

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
	linkedinlearningAuditPageSize = 100
	linkedinlearningAuditMaxPages = 200
)

// FetchAccessAuditLogs streams linkedin_learning audit events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v2/auditLogs?count=100&start=N&startTime={iso}
//
// Audit access requires an org-admin scope on the supplied credential;
// lower scopes surface 401 / 403 / 404 which the connector soft-skips
// via access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *LinkedInLearningAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/v2/auditLogs"

	var collected []linkedinLearningAuditEvent
	for page := 0; page < linkedinlearningAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("count", fmt.Sprintf("%d", linkedinlearningAuditPageSize))
		q.Set("start", fmt.Sprintf("%d", page*linkedinlearningAuditPageSize))
		if !since.IsZero() {
			q.Set("startTime", fmt.Sprintf("%d", since.UTC().UnixMilli()))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("linkedin_learning: audit: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("linkedin_learning: audit: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope linkedinLearningAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("linkedin_learning: decode audit: %w", err)
		}
		collected = append(collected, envelope.Data...)
		if len(envelope.Data) < linkedinlearningAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapLinkedInLearningAuditEvent(&collected[i])
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

type linkedinLearningAuditEvent struct {
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

type linkedinLearningAuditPage struct {
	Data []linkedinLearningAuditEvent `json:"data"`
}

func mapLinkedInLearningAuditEvent(e *linkedinLearningAuditEvent) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	ts := parseLinkedInLearningAuditTime(e.Timestamp)
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

func parseLinkedInLearningAuditTime(s string) time.Time {
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

var _ access.AccessAuditor = (*LinkedInLearningAccessConnector)(nil)
