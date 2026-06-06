package salesforce

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams Salesforce EventLogFile records into the
// access audit pipeline via the SOQL REST API. Implements
// access.AccessAuditor.
//
// Endpoint:
//
//	GET /services/data/v59.0/query?q=SELECT+Id,EventType,LogDate,LogFileLength
//	 +FROM+EventLogFile+WHERE+LogDate+>+{since}
//	 +ORDER+BY+LogDate+ASC
//
// Pagination uses Salesforce's `nextRecordsUrl` field; the handler is
// called per page in chronological LogDate order; `nextSince` is the
// timestamp of the newest LogDate in the batch.
func (c *SalesforceAccessConnector) FetchAccessAuditLogs(
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
	base := c.instanceBase(cfg)

	soql := "SELECT Id,EventType,LogDate,LogFileLength FROM EventLogFile"
	if !since.IsZero() {
		soql += " WHERE LogDate > " + since.UTC().Format(time.RFC3339)
	}
	soql += " ORDER BY LogDate ASC"

	q := url.Values{}
	q.Set("q", soql)
	nextURL := base + "/services/data/" + defaultAPIVersion + "/query?" + q.Encode()

	cursor := since
	for nextURL != "" {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var page sfEventLogPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("salesforce: decode event log page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Records))
		batchMax := cursor
		for i := range page.Records {
			entry := mapSalesforceEventLog(&page.Records[i])
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
		next := strings.TrimSpace(page.NextRecordsURL)
		if next == "" {
			return nil
		}
		// nextRecordsUrl is a path relative to the instance host;
		// resolve it through instanceBase so urlOverride works in tests.
		if strings.HasPrefix(next, "/") {
			nextURL = base + next
		} else {
			nextURL = next
		}
	}
	return nil
}

type sfEventLogPage struct {
	Done           bool               `json:"done"`
	TotalSize      int                `json:"totalSize"`
	NextRecordsURL string             `json:"nextRecordsUrl"`
	Records        []sfEventLogRecord `json:"records"`
}

type sfEventLogRecord struct {
	Attributes struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"attributes"`
	ID            string `json:"Id"`
	EventType     string `json:"EventType"`
	LogDate       string `json:"LogDate"`
	LogFileLength int64  `json:"LogFileLength"`
}

func mapSalesforceEventLog(r *sfEventLogRecord) *access.AuditLogEntry {
	if r == nil || r.ID == "" {
		return nil
	}
	ts, _ := parseSalesforceTime(r.LogDate)
	return &access.AuditLogEntry{
		EventID:   r.ID,
		EventType: r.EventType,
		Action:    r.EventType,
		Timestamp: ts,
		Outcome:   "success",
		RawData: map[string]interface{}{
			"log_file_length": r.LogFileLength,
			"log_file_url":    r.Attributes.URL,
		},
	}
}

// salesforceTimeLayouts is the ordered list of timestamp formats the
// Salesforce REST API is known to emit for LogDate. The canonical
// format is "2024-01-01T10:00:00.000+0000" — note the offset has no
// colon and milliseconds appear in the middle, so time.RFC3339
// ("...Z07:00") cannot parse it and silently returns zero time. Try
// the Salesforce-native shapes first, then fall back to RFC3339 for
// safety against future API changes.
var salesforceTimeLayouts = []string{
	"2006-01-02T15:04:05.000-0700",
	"2006-01-02T15:04:05-0700",
	time.RFC3339Nano,
	time.RFC3339,
}

// parseSalesforceTime tries each known Salesforce timestamp layout in
// order and returns the first successful parse. It exists so cursor
// advancement in FetchAccessAuditLogs doesn't silently stall when the
// API returns its non-RFC3339 LogDate format.
func parseSalesforceTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	var lastErr error
	for _, layout := range salesforceTimeLayouts {
		if ts, err := time.Parse(layout, s); err == nil {
			return ts, nil
		} else {
			lastErr = err
		}
	}
	return time.Time{}, fmt.Errorf("salesforce: unrecognized LogDate %q: %w", s, lastErr)
}

var _ access.AccessAuditor = (*SalesforceAccessConnector)(nil)
