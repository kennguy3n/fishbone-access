package openai

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
	openaiAuditPageSize = 100
	openaiAuditMaxPages = 200
)

// FetchAccessAuditLogs streams OpenAI organization audit-log records
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/organization/audit_logs?limit=100&effective_at[gte]={unix}&after={cursor}
//
// Bearer auth via OpenAIAccessConnector.newRequest; tenants without
// Enterprise/Teams plan eligibility surface 401/403/404 which
// soft-skip via access.ErrAuditNotAvailable.
func (c *OpenAIAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/v1/organization/audit_logs"

	var collected []openaiAuditEvent
	cursor := ""
	for page := 0; page < openaiAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", openaiAuditPageSize))
		if !since.IsZero() {
			q.Set("effective_at[gte]", fmt.Sprintf("%d", since.UTC().Unix()))
		}
		if cursor != "" {
			q.Set("after", cursor)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("openai: audit_logs: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("openai: audit_logs: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope openaiAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("openai: decode audit_logs: %w", err)
		}
		collected = append(collected, envelope.Data...)
		if !envelope.HasMore || envelope.LastID == "" {
			break
		}
		cursor = envelope.LastID
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapOpenAIAuditEvent(&collected[i])
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

type openaiAuditEvent struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	EffectiveAt int64  `json:"effective_at"`
	Actor       struct {
		Session struct {
			User struct {
				ID    string `json:"id"`
				Email string `json:"email"`
			} `json:"user"`
		} `json:"session"`
		APIKey struct {
			ID string `json:"id"`
		} `json:"api_key"`
	} `json:"actor"`
	Project struct {
		ID string `json:"id"`
	} `json:"project"`
}

type openaiAuditPage struct {
	Data    []openaiAuditEvent `json:"data"`
	HasMore bool               `json:"has_more"`
	LastID  string             `json:"last_id"`
}

func mapOpenAIAuditEvent(e *openaiAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	if e.EffectiveAt <= 0 {
		return nil
	}
	ts := time.Unix(e.EffectiveAt, 0).UTC()
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.ID),
		EventType:        strings.TrimSpace(e.Type),
		Action:           strings.TrimSpace(e.Type),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Actor.Session.User.ID),
		ActorEmail:       strings.TrimSpace(e.Actor.Session.User.Email),
		TargetExternalID: strings.TrimSpace(e.Project.ID),
		IPAddress:        "",
		Outcome:          "success",
		RawData:          rawMap,
	}
}

var _ access.AccessAuditor = (*OpenAIAccessConnector)(nil)
