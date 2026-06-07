package sonarcloud

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
)

const (
	sonarcloudAuditPageSize = 100
	sonarcloudAuditMaxPages = 200
)

// FetchAccessAuditLogs streams SonarCloud organisation audit-log
// entries into the access audit pipeline. Implements
// access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/audit_logs/search?organization={org}&from={iso}&p=N&ps=100
//
// Authentication is the bearer token (same token the existing
// /api/organizations/search_members probe uses). The /audit_logs
// endpoint requires the "Administer Organization" entitlement;
// non-paid plans and unprivileged tokens receive 401 / 403 / 404
// which the connector soft-skips via access.ErrAuditNotAvailable.
func (c *SonarCloudAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/api/audit_logs/search"

	var collected []sonarcloudAuditEntry
	page := 1
	for pages := 0; pages < sonarcloudAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("organization", strings.TrimSpace(cfg.Organization))
		q.Set("p", fmt.Sprintf("%d", page))
		q.Set("ps", fmt.Sprintf("%d", sonarcloudAuditPageSize))
		if !since.IsZero() {
			q.Set("from", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("sonarcloud: audit log: %w", err)
		}
		body, readErr := readSonarcloudAuditBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("sonarcloud: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var p sonarcloudAuditPage
		if err := json.Unmarshal(body, &p); err != nil {
			return fmt.Errorf("sonarcloud: decode audit log: %w", err)
		}
		collected = append(collected, p.AuditLogs...)
		total := p.Paging.Total
		fetched := page * sonarcloudAuditPageSize
		if total == 0 || fetched >= total || len(p.AuditLogs) == 0 {
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
		entry := mapSonarcloudAuditEntry(&collected[i])
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

type sonarcloudAuditPage struct {
	AuditLogs []sonarcloudAuditEntry `json:"auditLogs"`
	Paging    struct {
		PageIndex int `json:"pageIndex"`
		PageSize  int `json:"pageSize"`
		Total     int `json:"total"`
	} `json:"paging"`
}

type sonarcloudAuditEntry struct {
	ID         string `json:"id"`
	Category   string `json:"category"`
	Action     string `json:"action"`
	UserLogin  string `json:"userLogin"`
	UserName   string `json:"userName"`
	Date       string `json:"date"`
	TargetKey  string `json:"targetKey,omitempty"`
	TargetType string `json:"targetType,omitempty"`
}

func mapSonarcloudAuditEntry(e *sonarcloudAuditEntry) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseSonarcloudAuditTime(e.Date)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.Action)
	if action == "" {
		action = strings.TrimSpace(e.Category)
	}
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Category),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.UserLogin),
		TargetExternalID: strings.TrimSpace(e.TargetKey),
		TargetType:       strings.TrimSpace(e.TargetType),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseSonarcloudAuditTime(s string) time.Time {
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
	if ts, err := time.Parse("2006-01-02T15:04:05-0700", s); err == nil {
		return ts.UTC()
	}
	return time.Time{}
}

func readSonarcloudAuditBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("sonarcloud: empty response")
	}
	defer resp.Body.Close()
	const max = 1 << 20
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) >= max {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

var _ access.AccessAuditor = (*SonarCloudAccessConnector)(nil)
