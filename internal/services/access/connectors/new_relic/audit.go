package new_relic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const nrAuditGraphQLQuery = `query AuditEvents($since: EpochMilliseconds!, $cursor: String) {
  actor {
    organization {
      auditLogging {
        events(filter: {timestamp: {gte: $since}}, cursor: $cursor, limit: 100) {
          nextCursor
          results {
            id
            actionIdentifier
            createdAt
            actor { id email type }
            target { id type displayName }
            scopeId
            scopeType
            description
            outcome
          }
        }
      }
    }
  }
}`

const nrAuditMaxPages = 200

// FetchAccessAuditLogs streams New Relic audit-log events into the
// access audit pipeline via the NerdGraph API. Implements
// access.AccessAuditor.
//
// Endpoint:
//
//	POST /graphql  (NerdGraph) with header API-Key: <user-api-key>
//
// New Relic exposes audit log events via the NerdGraph
// actor.organization.auditLogging.events resolver. Access requires
// the "Organization Admin" entitlement; accounts without the
// entitlement receive a GraphQL error envelope (or 401 / 403) which
// the connector soft-skips via access.ErrAuditNotAvailable.
//
// The endpoint returns events newest-first and exposes a cursor
// (`nextCursor`). To honour the AccessAuditor contract the connector
// buffers the full sweep, then walks the collection oldest-first
// into the handler exactly once so `nextSince` covers every yielded
// event.
func (c *NewRelicAccessConnector) FetchAccessAuditLogs(
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
	sinceMs := int64(0)
	if !since.IsZero() {
		sinceMs = since.UTC().UnixMilli()
	}

	var collected []nrAuditEvent
	cursor := ""
	for pages := 0; pages < nrAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		resp, err := c.postAuditQuery(ctx, cfg, secrets, sinceMs, cursor)
		if err != nil {
			return err
		}
		if resp == nil {
			break
		}
		collected = append(collected, resp.Results...)
		if resp.NextCursor == "" || len(resp.Results) == 0 {
			break
		}
		cursor = resp.NextCursor
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	// NerdGraph returns newest-first; reverse into chronological order.
	for i := len(collected) - 1; i >= 0; i-- {
		entry := mapNRAuditEvent(&collected[i])
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

type nrAuditEventsBlock struct {
	NextCursor string         `json:"nextCursor"`
	Results    []nrAuditEvent `json:"results"`
}

type nrAuditEvent struct {
	ID               string `json:"id"`
	ActionIdentifier string `json:"actionIdentifier"`
	CreatedAt        string `json:"createdAt"`
	Actor            struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Type  string `json:"type"`
	} `json:"actor"`
	Target struct {
		ID          string `json:"id"`
		Type        string `json:"type"`
		DisplayName string `json:"displayName"`
	} `json:"target"`
	ScopeID     string `json:"scopeId"`
	ScopeType   string `json:"scopeType"`
	Description string `json:"description"`
	Outcome     string `json:"outcome"`
}

type nrAuditGraphQLResponse struct {
	Data struct {
		Actor struct {
			Organization struct {
				AuditLogging struct {
					Events nrAuditEventsBlock `json:"events"`
				} `json:"auditLogging"`
			} `json:"organization"`
		} `json:"actor"`
	} `json:"data"`
	Errors []struct {
		Message    string                 `json:"message"`
		Extensions map[string]interface{} `json:"extensions,omitempty"`
	} `json:"errors"`
}

func (c *NewRelicAccessConnector) postAuditQuery(
	ctx context.Context, cfg Config, secrets Secrets, sinceMs int64, cursor string,
) (*nrAuditEventsBlock, error) {
	payload := map[string]interface{}{
		"query": nrAuditGraphQLQuery,
		"variables": map[string]interface{}{
			"since":  sinceMs,
			"cursor": nil,
		},
	}
	if cursor != "" {
		payload["variables"].(map[string]interface{})["cursor"] = cursor
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL(cfg)+"/graphql", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("API-Key", strings.TrimSpace(secrets.APIKey))
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("new_relic: audit graphql: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return nil, access.ErrAuditNotAvailable
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("new_relic: audit graphql status %d: %s", resp.StatusCode, string(respBody))
	}
	var parsed nrAuditGraphQLResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("new_relic: decode audit graphql: %w", err)
	}
	if len(parsed.Errors) > 0 {
		msg := strings.ToLower(parsed.Errors[0].Message)
		if strings.Contains(msg, "not found") ||
			strings.Contains(msg, "not authorized") ||
			strings.Contains(msg, "not enabled") ||
			strings.Contains(msg, "not entitled") {
			return nil, access.ErrAuditNotAvailable
		}
		return nil, fmt.Errorf("new_relic: audit graphql error: %s", parsed.Errors[0].Message)
	}
	events := parsed.Data.Actor.Organization.AuditLogging.Events
	return &events, nil
}

func mapNRAuditEvent(e *nrAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseNRAuditTime(e.CreatedAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	outcome := strings.TrimSpace(e.Outcome)
	if outcome == "" {
		outcome = "success"
	}
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.ActionIdentifier),
		Action:           strings.TrimSpace(e.ActionIdentifier),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Actor.ID),
		ActorEmail:       strings.TrimSpace(e.Actor.Email),
		TargetExternalID: strings.TrimSpace(e.Target.ID),
		TargetType:       strings.TrimSpace(e.Target.Type),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func parseNRAuditTime(s string) time.Time {
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

var _ access.AccessAuditor = (*NewRelicAccessConnector)(nil)
