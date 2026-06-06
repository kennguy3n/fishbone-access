package meraki

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
	merakiAuditPageSize = 100
	merakiAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Cisco Meraki organization action-batch
// events into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v1/organizations/{organization_id}/actionBatches?perPage=100&startingAfter={cursor}
//
// The action-batches API requires the dashboard "Organization read" role;
// non-eligible API keys surface 401 / 403 / 404 which the connector
// soft-skips via access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *MerakiAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	orgID := merakiOrgIDFromConfig(configRaw)
	if orgID == "" {
		return fmt.Errorf("meraki: organization_id is required")
	}
	since := sincePartitions[access.DefaultAuditPartition]
	base := fmt.Sprintf("%s/api/v1/organizations/%s/actionBatches",
		c.baseURL(), url.PathEscape(orgID))

	var collected []merakiAuditEvent
	startingAfter := ""
	for page := 0; page < merakiAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("perPage", fmt.Sprintf("%d", merakiAuditPageSize))
		if startingAfter != "" {
			q.Set("startingAfter", startingAfter)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("meraki: actionBatches: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("meraki: actionBatches: status %d: %s", resp.StatusCode, string(body))
		}
		var batches []merakiAuditEvent
		if err := json.Unmarshal(body, &batches); err != nil {
			return fmt.Errorf("meraki: decode actionBatches: %w", err)
		}
		// since-filtering is client-side because the endpoint has no since
		// query parameter; we still page fully so the last cursor advances.
		for i := range batches {
			ts := parseMerakiTime(batches[i].CreatedAt)
			if !since.IsZero() && !ts.After(since) {
				continue
			}
			collected = append(collected, batches[i])
		}
		if len(batches) < merakiAuditPageSize {
			break
		}
		startingAfter = strings.TrimSpace(batches[len(batches)-1].ID)
		if startingAfter == "" {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapMerakiAuditEvent(&collected[i])
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

type merakiAuditEvent struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	Confirmed      bool   `json:"confirmed"`
	Synchronous    bool   `json:"synchronous"`
	Status         struct {
		Completed bool `json:"completed"`
		Failed    bool `json:"failed"`
	} `json:"status"`
	CreatedAt string `json:"createdAt"`
	Submitter string `json:"submitter"`
	Comment   string `json:"comment"`
}

func mapMerakiAuditEvent(e *merakiAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseMerakiTime(e.CreatedAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	outcome := "success"
	if e.Status.Failed {
		outcome = "failure"
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.ID),
		EventType:        "actionBatch",
		Action:           "submit",
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Submitter),
		TargetExternalID: strings.TrimSpace(e.OrganizationID),
		TargetType:       "organization",
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func parseMerakiTime(s string) time.Time {
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

func merakiOrgIDFromConfig(raw map[string]interface{}) string {
	if raw == nil {
		return ""
	}
	if v, ok := raw["organization_id"].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

var _ access.AccessAuditor = (*MerakiAccessConnector)(nil)
