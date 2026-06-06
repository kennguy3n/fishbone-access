package liquidplanner

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
	liquidPlannerAuditPageSize = 100
	liquidPlannerAuditMaxPages = 200
)

// FetchAccessAuditLogs streams LiquidPlanner workspace audit events
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v1/workspaces/{workspace_id}/audit_events?page=N&per_page=100
//
// The audit-events endpoint requires admin scope on the workspace;
// non-admin tokens receive 401 / 403 / 404 which the connector
// soft-skips via access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *LiquidPlannerAccessConnector) FetchAccessAuditLogs(
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
	base := fmt.Sprintf("%s/api/v1/workspaces/%s/audit_events",
		c.baseURL(), url.PathEscape(strings.TrimSpace(cfg.WorkspaceID)))

	var collected []liquidPlannerAuditEvent
	for page := 1; page <= liquidPlannerAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", liquidPlannerAuditPageSize))
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("liquidplanner: audit log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("liquidplanner: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var events []liquidPlannerAuditEvent
		if err := json.Unmarshal(body, &events); err != nil {
			return fmt.Errorf("liquidplanner: decode audit log: %w", err)
		}
		olderThanCursor := false
		for i := range events {
			ts := parseLiquidPlannerAuditTime(events[i].CreatedAt)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, events[i])
		}
		if olderThanCursor || len(events) < liquidPlannerAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapLiquidPlannerAuditEvent(&collected[i])
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

type liquidPlannerAuditEvent struct {
	ID          int64  `json:"id"`
	Event       string `json:"event"`
	CreatedAt   string `json:"created_at"`
	MemberID    int64  `json:"member_id"`
	MemberEmail string `json:"member_email"`
	TargetType  string `json:"target_type"`
	TargetID    int64  `json:"target_id"`
	IPAddress   string `json:"ip_address"`
}

func mapLiquidPlannerAuditEvent(e *liquidPlannerAuditEvent) *access.AuditLogEntry {
	if e == nil || e.ID == 0 {
		return nil
	}
	ts := parseLiquidPlannerAuditTime(e.CreatedAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          fmt.Sprintf("%d", e.ID),
		EventType:        strings.TrimSpace(e.Event),
		Action:           strings.TrimSpace(e.Event),
		Timestamp:        ts,
		ActorExternalID:  fmt.Sprintf("%d", e.MemberID),
		ActorEmail:       strings.TrimSpace(e.MemberEmail),
		TargetExternalID: fmt.Sprintf("%d", e.TargetID),
		TargetType:       strings.TrimSpace(e.TargetType),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseLiquidPlannerAuditTime(s string) time.Time {
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
