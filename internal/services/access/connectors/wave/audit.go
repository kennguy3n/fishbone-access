package wave

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

const (
	waveAuditPageSize = 100
	waveAuditMaxPages = 200
)

const waveAuditQuery = `query AuditLogs($first: Int!, $after: String, $since: DateTime) {
  auditLogs(first: $first, after: $after, since: $since) {
    pageInfo { hasNextPage endCursor }
    edges {
      node {
        id eventType action occurredAt outcome
        actor { id email }
        target { id type }
      }
    }
  }
}`

// FetchAccessAuditLogs streams Wave audit-log entries into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	POST /graphql/public  body: { query: <AuditLogs>, variables: {...} }
//
// Bearer-token auth. Tenants without audit-log entitlement return
// 401 / 403 / 404, soft-skipped via access.ErrAuditNotAvailable. Errors
// inside the GraphQL envelope are mapped via message-contains "unauthorized"
// / "forbidden" / "not enabled" to the same soft-skip.
func (c *WaveAccessConnector) FetchAccessAuditLogs(
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

	var collected []waveAuditNode
	after := ""
	for page := 0; page < waveAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		vars := map[string]interface{}{"first": waveAuditPageSize}
		if after != "" {
			vars["after"] = after
		} else {
			vars["after"] = nil
		}
		if !since.IsZero() {
			vars["since"] = since.UTC().Format(time.RFC3339)
		}
		payload, _ := json.Marshal(map[string]interface{}{"query": waveAuditQuery, "variables": vars})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			c.baseURL()+"/graphql/public", bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("wave: audit log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("wave: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope struct {
			Data struct {
				AuditLogs struct {
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
					Edges []struct {
						Node waveAuditNode `json:"node"`
					} `json:"edges"`
				} `json:"auditLogs"`
			} `json:"data"`
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("wave: decode audit log: %w", err)
		}
		if len(envelope.Errors) > 0 {
			msg := strings.ToLower(envelope.Errors[0].Message)
			if strings.Contains(msg, "unauthorized") ||
				strings.Contains(msg, "forbidden") ||
				strings.Contains(msg, "not enabled") ||
				strings.Contains(msg, "permission") {
				return access.ErrAuditNotAvailable
			}
			return fmt.Errorf("wave: audit log: graphql error: %s", envelope.Errors[0].Message)
		}
		for i := range envelope.Data.AuditLogs.Edges {
			collected = append(collected, envelope.Data.AuditLogs.Edges[i].Node)
		}
		if !envelope.Data.AuditLogs.PageInfo.HasNextPage {
			break
		}
		after = envelope.Data.AuditLogs.PageInfo.EndCursor
		if after == "" {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapWaveAuditNode(&collected[i])
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

type waveAuditNode struct {
	ID         string `json:"id"`
	EventType  string `json:"eventType"`
	Action     string `json:"action"`
	OccurredAt string `json:"occurredAt"`
	Outcome    string `json:"outcome"`
	Actor      struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"actor"`
	Target struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"target"`
}

func mapWaveAuditNode(n *waveAuditNode) *access.AuditLogEntry {
	if n == nil || strings.TrimSpace(n.ID) == "" {
		return nil
	}
	ts := parseWaveAuditTime(n.OccurredAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(n)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          n.ID,
		EventType:        strings.TrimSpace(n.EventType),
		Action:           strings.TrimSpace(n.Action),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(n.Actor.ID),
		ActorEmail:       strings.TrimSpace(n.Actor.Email),
		TargetExternalID: strings.TrimSpace(n.Target.ID),
		TargetType:       strings.TrimSpace(n.Target.Type),
		Outcome:          strings.TrimSpace(n.Outcome),
		RawData:          rawMap,
	}
}

func parseWaveAuditTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
