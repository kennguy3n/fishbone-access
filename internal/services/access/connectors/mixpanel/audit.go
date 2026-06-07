package mixpanel

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

// FetchAccessAuditLogs streams Mixpanel organization audit events into
// the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint (Enterprise plan only):
//
//	GET /api/app/organizations/{org_id}/audit?limit=100
//	    &from_date={iso}&cursor={c}
//
// Mixpanel exposes an organization-scoped audit feed on the Enterprise
// plan via the service-account API. Non-Enterprise tenants receive
// 401/403/404 which the connector soft-skips via
// access.ErrAuditNotAvailable.
func (c *MixpanelAccessConnector) FetchAccessAuditLogs(
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
	pageCursor := ""
	base := c.baseURL() + "/api/app/organizations/" + url.PathEscape(strings.TrimSpace(cfg.OrganizationID)) + "/audit"
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", "100")
		if !since.IsZero() {
			q.Set("from_date", since.UTC().Format(time.RFC3339))
		}
		if pageCursor != "" {
			q.Set("cursor", pageCursor)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("mixpanel: audit log: %w", err)
		}
		body, readErr := readMixpanelBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("mixpanel: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var p mixpanelAuditPage
		if err := json.Unmarshal(body, &p); err != nil {
			return fmt.Errorf("mixpanel: decode audit log: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(p.Results))
		batchMax := cursor
		for i := range p.Results {
			entry := mapMixpanelAuditEvent(&p.Results[i])
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
		pageCursor = strings.TrimSpace(p.Cursor)
		if pageCursor == "" || len(p.Results) == 0 {
			return nil
		}
	}
}

type mixpanelAuditPage struct {
	Results []mixpanelAuditEvent `json:"results"`
	Cursor  string               `json:"cursor"`
}

type mixpanelAuditEvent struct {
	ID         string                 `json:"id"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	ResourceID string                 `json:"resource_id"`
	Time       string                 `json:"time"`
	Actor      mixpanelPrincipal      `json:"actor"`
	IPAddress  string                 `json:"ip_address,omitempty"`
	Outcome    string                 `json:"outcome,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type mixpanelPrincipal struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Type  string `json:"type,omitempty"`
}

func mapMixpanelAuditEvent(e *mixpanelAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseMixpanelTime(e.Time)
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
		EventType:        strings.TrimSpace(e.Resource + "." + e.Action),
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Actor.ID),
		ActorEmail:       strings.TrimSpace(e.Actor.Email),
		TargetExternalID: strings.TrimSpace(e.ResourceID),
		TargetType:       strings.TrimSpace(e.Resource),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func parseMixpanelTime(s string) time.Time {
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

func readMixpanelBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("mixpanel: empty response")
	}
	defer resp.Body.Close()
	// Cap the read at 1 MiB using the standard idiom shared by every other
	// connector in this package, which enforces the bound exactly rather than
	// overshooting by up to one chunk.
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

var _ access.AccessAuditor = (*MixpanelAccessConnector)(nil)
