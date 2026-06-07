package magento

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
	magentoAuditPageSize = 100
	magentoAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Magento `/rest/V1/logging/entries`
// records into the access audit pipeline. Implements
// access.AccessAuditor.
//
// Endpoint:
//
//	GET /rest/V1/logging/entries?searchCriteria[pageSize]=100
//	    &searchCriteria[currentPage]=N
//	    &searchCriteria[filter_groups][0][filters][0][field]=time
//	    &searchCriteria[filter_groups][0][filters][0][value]={iso}
//	    &searchCriteria[filter_groups][0][filters][0][condition_type]=gteq
//
// The logging module is part of the Magento Commerce (Adobe Commerce)
// distribution; Magento Open Source instances return 401/403/404,
// which the connector soft-skips via access.ErrAuditNotAvailable per
// docs/architecture.md §2.
func (c *MagentoAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL(cfg) + "/rest/V1/logging/entries"

	var collected []magentoLoggingEntry
	for page := 1; page <= magentoAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("searchCriteria[pageSize]", fmt.Sprintf("%d", magentoAuditPageSize))
		q.Set("searchCriteria[currentPage]", fmt.Sprintf("%d", page))
		if !since.IsZero() {
			q.Set("searchCriteria[filter_groups][0][filters][0][field]", "time")
			q.Set("searchCriteria[filter_groups][0][filters][0][value]", since.UTC().Format(time.RFC3339))
			q.Set("searchCriteria[filter_groups][0][filters][0][condition_type]", "gteq")
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("magento: audit: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("magento: audit: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope magentoLoggingPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("magento: decode audit: %w", err)
		}
		collected = append(collected, envelope.Items...)
		if len(envelope.Items) < magentoAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapMagentoLoggingEntry(&collected[i])
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

type magentoLoggingEntry struct {
	ID             json.Number `json:"id"`
	UserID         json.Number `json:"user_id"`
	Username       string      `json:"username"`
	EventCode      string      `json:"event_code"`
	Action         string      `json:"action"`
	IPAddress      string      `json:"ip"`
	Status         string      `json:"status"`
	Time           string      `json:"time"`
	FullActionName string      `json:"fullaction"`
}

type magentoLoggingPage struct {
	Items      []magentoLoggingEntry `json:"items"`
	TotalCount int                   `json:"total_count"`
}

func mapMagentoLoggingEntry(e *magentoLoggingEntry) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	rawTS := strings.TrimSpace(e.Time)
	ts, err := time.Parse(time.RFC3339, rawTS)
	if err != nil {
		// Magento sometimes uses MySQL DATETIME format.
		ts, err = time.Parse("2006-01-02 15:04:05", rawTS)
		if err != nil {
			return nil
		}
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	outcome := strings.ToLower(strings.TrimSpace(e.Status))
	if outcome == "" {
		outcome = "success"
	}
	return &access.AuditLogEntry{
		EventID:         strings.TrimSpace(e.ID.String()),
		EventType:       strings.TrimSpace(e.EventCode),
		Action:          strings.TrimSpace(e.Action),
		Timestamp:       ts.UTC(),
		ActorExternalID: strings.TrimSpace(e.UserID.String()),
		ActorEmail:      strings.TrimSpace(e.Username),
		IPAddress:       strings.TrimSpace(e.IPAddress),
		Outcome:         outcome,
		RawData:         rawMap,
	}
}

var _ access.AccessAuditor = (*MagentoAccessConnector)(nil)
