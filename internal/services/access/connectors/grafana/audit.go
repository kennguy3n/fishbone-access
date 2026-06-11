package grafana

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

// auditPageSize is the per-page count requested from the Grafana audit
// endpoint. The pagination loop also uses it as the "last page" signal
// (a short page means no more results), so both the query parameter and
// the termination check must reference this single constant to stay in
// lock-step.
const auditPageSize = 100

// FetchAccessAuditLogs streams Grafana audit-log entries into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint (Grafana Enterprise / Cloud audit add-on):
//
//	GET /api/audit?perPage=100&page=N&from={iso}
//
// Open-source Grafana does not expose this endpoint; Cloud /
// Enterprise tenants without the audit add-on receive 401/403/404
// which the connector soft-skips via access.ErrAuditNotAvailable.
func (c *GrafanaAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL(cfg) + "/api/audit"
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("perPage", fmt.Sprintf("%d", auditPageSize))
		q.Set("page", fmt.Sprintf("%d", page))
		if !since.IsZero() {
			q.Set("from", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("grafana: audit log: %w", err)
		}
		body, readErr := readGrafanaBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("grafana: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var p grafanaAuditPage
		if err := json.Unmarshal(body, &p); err != nil {
			return fmt.Errorf("grafana: decode audit log: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(p.Items))
		batchMax := cursor
		for i := range p.Items {
			entry := mapGrafanaAuditEvent(&p.Items[i])
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
		if len(p.Items) < auditPageSize {
			return nil
		}
		page++
	}
}

type grafanaAuditPage struct {
	Items []grafanaAuditEvent `json:"items"`
	Total int                 `json:"total"`
}

type grafanaAuditEvent struct {
	ID         int64                  `json:"id"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	ResourceID string                 `json:"resourceID"`
	UserID     string                 `json:"userId"`
	UserLogin  string                 `json:"userLogin"`
	UserEmail  string                 `json:"userEmail"`
	OrgID      int64                  `json:"orgId"`
	Timestamp  string                 `json:"timestamp"`
	IPAddress  string                 `json:"ipAddress"`
	UserAgent  string                 `json:"userAgent"`
	Outcome    string                 `json:"outcome"`
	Request    map[string]interface{} `json:"request,omitempty"`
}

func mapGrafanaAuditEvent(e *grafanaAuditEvent) *access.AuditLogEntry {
	if e == nil || e.ID == 0 {
		return nil
	}
	ts := parseGrafanaTime(e.Timestamp)
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
		EventID:          fmt.Sprintf("%d", e.ID),
		EventType:        strings.TrimSpace(e.Resource + "." + e.Action),
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.UserID),
		ActorEmail:       strings.TrimSpace(e.UserEmail),
		TargetExternalID: strings.TrimSpace(e.ResourceID),
		TargetType:       strings.TrimSpace(e.Resource),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		UserAgent:        strings.TrimSpace(e.UserAgent),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func parseGrafanaTime(s string) time.Time {
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

func readGrafanaBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("grafana: empty response")
	}
	defer resp.Body.Close()
	return httputil.ReadAllLimited(resp.Body, 0)
}

var _ access.AccessAuditor = (*GrafanaAccessConnector)(nil)
