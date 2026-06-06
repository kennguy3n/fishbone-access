package zoho_crm

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

// FetchAccessAuditLogs streams Zoho CRM audit-log records into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /crm/v5/settings/audit_log?page=N&per_page=200&datetime={iso}
//
// Audit-log access requires the `ZohoCRM.settings.audit_log.READ` OAuth
// scope; tokens without it receive 401/403 which the connector
// soft-skips via access.ErrAuditNotAvailable. Pagination uses Zoho's
// `info.more_records` envelope.
func (c *ZohoCRMAccessConnector) FetchAccessAuditLogs(
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
	cursor := since
	page := 1
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("per_page", "200")
		q.Set("page", fmt.Sprintf("%d", page))
		if !since.IsZero() {
			q.Set("datetime", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, "/settings/audit_log?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("zoho_crm: audit log: %w", err)
		}
		body, readErr := readZohoBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		case http.StatusNoContent:
			return nil
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("zoho_crm: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var p zohoAuditPage
		if err := json.Unmarshal(body, &p); err != nil {
			return fmt.Errorf("zoho_crm: decode audit log: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(p.AuditLog))
		batchMax := cursor
		for i := range p.AuditLog {
			entry := mapZohoAuditEvent(&p.AuditLog[i])
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
		if !p.Info.MoreRecords || len(p.AuditLog) == 0 {
			return nil
		}
		page++
	}
}

type zohoAuditPage struct {
	AuditLog []zohoAuditEvent `json:"audit_log"`
	Info     struct {
		PerPage     int  `json:"per_page"`
		Page        int  `json:"page"`
		MoreRecords bool `json:"more_records"`
	} `json:"info"`
}

type zohoAuditEvent struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Module string `json:"module"`
	DoneBy struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"done_by"`
	DisplayMessage string `json:"display_message"`
	AuditedTime    string `json:"audited_time"`
	IPAddress      string `json:"ip_address"`
	RecordID       string `json:"record_id"`
}

func mapZohoAuditEvent(e *zohoAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseZohoTime(e.AuditedTime)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Module + "." + e.Action),
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.DoneBy.ID),
		ActorEmail:       strings.TrimSpace(e.DoneBy.Email),
		TargetExternalID: strings.TrimSpace(e.RecordID),
		TargetType:       strings.TrimSpace(e.Module),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseZohoTime(s string) time.Time {
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

func readZohoBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("zoho_crm: empty response")
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

var _ access.AccessAuditor = (*ZohoCRMAccessConnector)(nil)
