package snyk

import (
	"bytes"
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

// FetchAccessAuditLogs streams Snyk org audit log events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	POST /rest/orgs/{org_id}/audit_logs/search?version={apiVersion}
//	Body: {"filters":{"from":"{since}","to":"{now}"}}
//
// Snyk paginates by `links.next`; the handler is called once per
// provider page in chronological order so callers can persist the
// monotonic `nextSince` cursor between runs.
func (c *SnykAccessConnector) FetchAccessAuditLogs(
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
	cursor := since

	q := url.Values{}
	q.Set("version", apiVersion)
	q.Set("size", fmt.Sprintf("%d", pageLimit))
	nextURL := fmt.Sprintf("%s/rest/orgs/%s/audit_logs/search?%s", c.baseURL(), url.PathEscape(cfg.OrgID), q.Encode())

	payload := map[string]interface{}{}
	if !since.IsZero() {
		payload["filters"] = map[string]interface{}{
			"from": since.UTC().Format(time.RFC3339),
			"to":   time.Now().UTC().Format(time.RFC3339),
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("snyk: marshal audit search: %w", err)
	}

	for nextURL != "" {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, nextURL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/vnd.api+json")
		req.Header.Set("Content-Type", "application/vnd.api+json")
		req.Header.Set("Authorization", "token "+strings.TrimSpace(secrets.APIToken))
		respBody, status, err := snykDoRaw(c, req)
		if err != nil {
			switch status {
			case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
				return access.ErrAuditNotAvailable
			}
			return err
		}
		var page snykAuditPage
		if err := json.Unmarshal(respBody, &page); err != nil {
			return fmt.Errorf("snyk: decode audit logs: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Data))
		batchMax := cursor
		for i := range page.Data {
			entry := mapSnykAuditEvent(&page.Data[i])
			if entry == nil {
				continue
			}
			if entry.Timestamp.After(batchMax) {
				batchMax = entry.Timestamp
			}
			batch = append(batch, entry)
		}
		if err := handler(batch, batchMax, access.DefaultAuditPartition); err != nil {
			return err
		}
		cursor = batchMax
		next := strings.TrimSpace(page.Links.Next)
		if next == "" {
			return nil
		}
		nextURL = rewriteSnykNext(next, c.baseURL())
	}
	return nil
}

func snykDoRaw(c *SnykAccessConnector, req *http.Request) ([]byte, int, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("snyk: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	// Match the strict 1 MB cap the rest of the connector applies via
	// io.LimitReader, keeping the audit path consistent with stripe/
	// sumo_logic/tailscale and avoiding the up-to-16 KB overshoot of a
	// manual chunked read.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("snyk: %s %s: read body: %w", req.Method, req.URL.Path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, fmt.Errorf("snyk: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, resp.StatusCode, nil
}

type snykAuditPage struct {
	Data  []snykAuditEvent `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

type snykAuditEvent struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		CreatedAt string                 `json:"created_at"`
		Event     string                 `json:"event"`
		UserID    string                 `json:"user_id"`
		ProjectID string                 `json:"project_id"`
		Content   map[string]interface{} `json:"content"`
	} `json:"attributes"`
}

func mapSnykAuditEvent(e *snykAuditEvent) *access.AuditLogEntry {
	if e == nil || e.ID == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, e.Attributes.CreatedAt)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, e.Attributes.CreatedAt)
	}
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        e.Attributes.Event,
		Action:           e.Attributes.Event,
		Timestamp:        ts,
		ActorExternalID:  e.Attributes.UserID,
		TargetExternalID: e.Attributes.ProjectID,
		Outcome:          "success",
		RawData:          rawMap,
	}
}

var _ access.AccessAuditor = (*SnykAccessConnector)(nil)
