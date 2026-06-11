package digitalocean

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/access/httputil"
)

const (
	doAuditPageSize = 100
	doAuditMaxPages = 200
)

// FetchAccessAuditLogs streams DigitalOcean account "actions"
// (resource-mutation audit events) into the access audit pipeline.
// Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v2/actions?page=N&per_page=100
//
// DigitalOcean exposes per-account event history via the /v2/actions
// API with bearer auth. Tokens without the `actions:read` scope receive
// 401 / 403 / 404, which the connector soft-skips via
// access.ErrAuditNotAvailable.
//
// The endpoint returns actions newest-first; the connector buffers
// every page (filtered by `started_at > since` to honour the
// persisted cursor) before advancing nextSince so a request failure
// leaves the cursor untouched.
func (c *DigitalOceanAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	secrets, err := c.decodeBoth(secretsRaw)
	if err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]

	var collected []doAction
	page := 1
	for pages := 0; pages < doAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", doAuditPageSize))
		req, err := c.newRequest(ctx, secrets, http.MethodGet, "/v2/actions?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("digitalocean: audit log: %w", err)
		}
		body, readErr := readDOAuditBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("digitalocean: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var parsed doActionsResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return fmt.Errorf("digitalocean: decode audit log: %w", err)
		}
		olderThanCursor := false
		for i := range parsed.Actions {
			ts := parseDOAuditTime(parsed.Actions[i].StartedAt)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, parsed.Actions[i])
		}
		if olderThanCursor || parsed.Links.Pages.Next == "" || len(parsed.Actions) < doAuditPageSize {
			break
		}
		page++
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapDOAction(&collected[i])
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

type doActionsResponse struct {
	Actions []doAction `json:"actions"`
	Links   struct {
		Pages struct {
			Next string `json:"next,omitempty"`
		} `json:"pages"`
	} `json:"links"`
}

type doAction struct {
	ID           int64  `json:"id"`
	Status       string `json:"status"`
	Type         string `json:"type"`
	StartedAt    string `json:"started_at"`
	CompletedAt  string `json:"completed_at"`
	ResourceID   int64  `json:"resource_id"`
	ResourceType string `json:"resource_type"`
	Region       string `json:"region_slug"`
}

func mapDOAction(e *doAction) *access.AuditLogEntry {
	if e == nil || e.ID == 0 {
		return nil
	}
	ts := parseDOAuditTime(e.StartedAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	outcome := "success"
	switch strings.ToLower(strings.TrimSpace(e.Status)) {
	case "errored", "failed":
		outcome = "failure"
	case "in-progress", "pending":
		outcome = "pending"
	}
	target := ""
	if e.ResourceID != 0 {
		target = fmt.Sprintf("%d", e.ResourceID)
	}
	return &access.AuditLogEntry{
		EventID:          fmt.Sprintf("%d", e.ID),
		EventType:        strings.TrimSpace(e.Type),
		Action:           strings.TrimSpace(e.Type),
		Timestamp:        ts,
		TargetExternalID: target,
		TargetType:       strings.TrimSpace(e.ResourceType),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func parseDOAuditTime(s string) time.Time {
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

func readDOAuditBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("digitalocean: empty response")
	}
	defer resp.Body.Close()
	return httputil.ReadAllLimited(resp.Body, 0)
}

var _ access.AccessAuditor = (*DigitalOceanAccessConnector)(nil)
