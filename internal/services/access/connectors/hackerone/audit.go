package hackerone

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

// FetchAccessAuditLogs streams HackerOne organization audit log entries
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/organizations/{org_id}/audit_logs?page[size]=100&page[number]=N
//	    &filter[created_at__gt]={iso}
//
// HackerOne returns JSON:API envelopes with pagination links under
// `links.next`. Audit-log access requires the organization-admin scope;
// non-admin tokens receive 401/403 which the connector soft-skips via
// access.ErrAuditNotAvailable.
func (c *HackerOneAccessConnector) FetchAccessAuditLogs(
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
	page := 1
	base := fmt.Sprintf("%s/v1/organizations/%s/audit_logs",
		c.baseURL(), url.PathEscape(strings.TrimSpace(cfg.OrgID)))
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page[size]", "100")
		q.Set("page[number]", fmt.Sprintf("%d", page))
		if !since.IsZero() {
			q.Set("filter[created_at__gt]", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("hackerone: audit log: %w", err)
		}
		body, readErr := readHackerOneBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("hackerone: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var p hackerOneAuditPage
		if err := json.Unmarshal(body, &p); err != nil {
			return fmt.Errorf("hackerone: decode audit log: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(p.Data))
		batchMax := cursor
		for i := range p.Data {
			entry := mapHackerOneAudit(&p.Data[i])
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
		if strings.TrimSpace(p.Links.Next) == "" || len(p.Data) == 0 {
			return nil
		}
		page++
	}
}

type hackerOneAuditPage struct {
	Data  []hackerOneAuditEntry `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

type hackerOneAuditEntry struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Action      string `json:"action"`
		ActionType  string `json:"action_type"`
		CreatedAt   string `json:"created_at"`
		ActorID     string `json:"actor_id"`
		ActorEmail  string `json:"actor_email"`
		TargetID    string `json:"target_id"`
		TargetType  string `json:"target_type"`
		IPAddress   string `json:"ip_address"`
		UserAgent   string `json:"user_agent"`
		Outcome     string `json:"outcome"`
		Description string `json:"description"`
	} `json:"attributes"`
}

func mapHackerOneAudit(e *hackerOneAuditEntry) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseHackerOneTime(e.Attributes.CreatedAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	outcome := strings.TrimSpace(e.Attributes.Outcome)
	if outcome == "" {
		outcome = "success"
	}
	eventType := strings.TrimSpace(e.Attributes.ActionType)
	if eventType == "" {
		eventType = strings.TrimSpace(e.Attributes.Action)
	}
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        eventType,
		Action:           strings.TrimSpace(e.Attributes.Action),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Attributes.ActorID),
		ActorEmail:       strings.TrimSpace(e.Attributes.ActorEmail),
		TargetExternalID: strings.TrimSpace(e.Attributes.TargetID),
		TargetType:       strings.TrimSpace(e.Attributes.TargetType),
		IPAddress:        strings.TrimSpace(e.Attributes.IPAddress),
		UserAgent:        strings.TrimSpace(e.Attributes.UserAgent),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func parseHackerOneTime(s string) time.Time {
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

func readHackerOneBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("hackerone: empty response")
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

var _ access.AccessAuditor = (*HackerOneAccessConnector)(nil)
