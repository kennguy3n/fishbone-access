package terraform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// terraformAuditPageSize matches Terraform Cloud's documented default
// page size for the organization audit-trail API.
const terraformAuditPageSize = 100

// terraformAuditMaxPages bounds a single sweep to ~10k audit-trail
// entries. The `since` partition cursor narrows subsequent sweeps to
// the events emitted since the last successful run.
const terraformAuditMaxPages = 100

// FetchAccessAuditLogs streams Terraform Cloud audit-trail entries
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint (HashiCorp Terraform Cloud):
//
//	GET /api/v2/organization/{org}/audit-trail?since={rfc3339}&page[number]=N&page[size]=100
//
// Authentication is a user / team token (Bearer). Audit-trail access
// requires the "Manage Organization" entitlement; tenants on Free /
// Team plans receive 401 / 403 / 404 which the connector soft-skips
// via access.ErrAuditNotAvailable.
//
// The endpoint is chronological (oldest first) and exposes JSON:API
// pagination via the `page[number]` / `page[size]` query-string
// parameters plus a `meta.pagination.total-pages` cursor.
//
// To honour the AccessAuditor contract under multi-page sweeps the
// connector buffers every page before advancing the persisted
// cursor: if any page fails the cursor stays where it was, so a
// retry replays the same window rather than silently skipping
// older entries below the persisted cursor.
func (c *TerraformAccessConnector) FetchAccessAuditLogs(
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
	base := fmt.Sprintf("%s/api/v2/organization/%s/audit-trail",
		c.baseURL(), url.PathEscape(strings.TrimSpace(cfg.Organization)))

	var collected []terraformAuditEvent
	page := 1
	for pages := 0; pages < terraformAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page[number]", fmt.Sprintf("%d", page))
		q.Set("page[size]", fmt.Sprintf("%d", terraformAuditPageSize))
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("terraform: audit-trail: %w", err)
		}
		body, readErr := readTerraformBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("terraform: audit-trail: status %d: %s", resp.StatusCode, string(body))
		}
		var p terraformAuditPage
		if err := json.Unmarshal(body, &p); err != nil {
			return fmt.Errorf("terraform: decode audit-trail: %w", err)
		}
		collected = append(collected, p.Data...)
		total := p.Meta.Pagination.TotalPages
		if total == 0 || page >= total || len(p.Data) == 0 {
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
		entry := mapTerraformAuditEvent(&collected[i])
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

type terraformAuditPage struct {
	Data []terraformAuditEvent `json:"data"`
	Meta struct {
		Pagination struct {
			CurrentPage int `json:"current-page"`
			TotalPages  int `json:"total-pages"`
			TotalCount  int `json:"total-count"`
		} `json:"pagination"`
	} `json:"meta"`
}

type terraformAuditEvent struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Action    string                 `json:"action"`
		Timestamp string                 `json:"timestamp"`
		Actor     map[string]interface{} `json:"actor"`
		Target    map[string]interface{} `json:"target"`
		Source    map[string]interface{} `json:"source"`
		Meta      map[string]interface{} `json:"meta,omitempty"`
		Outcome   string                 `json:"outcome,omitempty"`
	} `json:"attributes"`
}

func mapTerraformAuditEvent(e *terraformAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseTerraformAuditTime(e.Attributes.Timestamp)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	actorID, actorEmail := extractTerraformActor(e.Attributes.Actor)
	targetID, targetType := extractTerraformTarget(e.Attributes.Target)
	ip, agent := extractTerraformSource(e.Attributes.Source)
	outcome := strings.TrimSpace(e.Attributes.Outcome)
	if outcome == "" {
		outcome = "success"
	}
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Attributes.Action),
		Action:           strings.TrimSpace(e.Attributes.Action),
		Timestamp:        ts,
		ActorExternalID:  actorID,
		ActorEmail:       actorEmail,
		TargetExternalID: targetID,
		TargetType:       targetType,
		IPAddress:        ip,
		UserAgent:        agent,
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func extractTerraformActor(m map[string]interface{}) (string, string) {
	if m == nil {
		return "", ""
	}
	id, _ := m["id"].(string)
	email, _ := m["email"].(string)
	if id == "" {
		if v, ok := m["external-id"].(string); ok {
			id = v
		}
	}
	return strings.TrimSpace(id), strings.TrimSpace(email)
}

func extractTerraformTarget(m map[string]interface{}) (string, string) {
	if m == nil {
		return "", ""
	}
	id, _ := m["id"].(string)
	typ, _ := m["type"].(string)
	if id == "" {
		if v, ok := m["external-id"].(string); ok {
			id = v
		}
	}
	return strings.TrimSpace(id), strings.TrimSpace(typ)
}

func extractTerraformSource(m map[string]interface{}) (string, string) {
	if m == nil {
		return "", ""
	}
	ip, _ := m["ip"].(string)
	agent, _ := m["user-agent"].(string)
	return strings.TrimSpace(ip), strings.TrimSpace(agent)
}

func parseTerraformAuditTime(s string) time.Time {
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

func readTerraformBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("terraform: empty response")
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

var _ access.AccessAuditor = (*TerraformAccessConnector)(nil)
