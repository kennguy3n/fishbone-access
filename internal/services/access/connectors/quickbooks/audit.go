package quickbooks

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

// FetchAccessAuditLogs streams QuickBooks Online Change Data Capture
// (CDC) entity-update events into the access audit pipeline. Implements
// access.AccessAuditor.
//
// Endpoint:
//
//	GET /v3/company/{realmID}/cdc?entities=Employee&changedSince={since}
//
// QuickBooks Online does not expose a generic activity log API, but the
// `cdc` endpoint returns one delta page per entity type, with each
// changed object carrying a `MetaData.LastUpdatedTime`. We treat each
// returned object as one audit-log entry (`EventType=entity_changed`,
// timestamp = `MetaData.LastUpdatedTime`).
//
// On HTTP 401/403 the connector returns access.ErrAuditNotAvailable
// so callers treat the company as plan-gated rather than failing the
// whole sync. CDC is a delta endpoint and does not paginate — a single
// request returns all changes since `changedSince`; the handler is
// invoked once per call.
func (c *QuickBooksAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]
	if since.IsZero() {
		since = time.Now().Add(-30 * 24 * time.Hour)
	}
	q := url.Values{}
	q.Set("entities", "Employee,CompanyInfo,Vendor,Customer")
	q.Set("changedSince", since.UTC().Format(time.RFC3339))
	q.Set("minorversion", "65")
	full := fmt.Sprintf("%s/v3/company/%s/cdc?%s", c.baseURL(), cfg.RealmID, q.Encode())
	req, err := c.newRequest(ctx, secrets, http.MethodGet, full)
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		if isAuditNotAvailable(err) {
			return access.ErrAuditNotAvailable
		}
		return err
	}
	var resp quickbooksCDCResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("quickbooks: decode cdc: %w", err)
	}
	batch := make([]*access.AuditLogEntry, 0)
	batchMax := since
	for _, group := range resp.CDCResponse {
		for _, qr := range group.QueryResponse {
			for _, e := range qr.Employee {
				entry := mapQuickBooksEntity("Employee", e.ID, e.MetaData, e.Raw())
				if entry != nil {
					if entry.Timestamp.After(batchMax) {
						batchMax = entry.Timestamp
					}
					batch = append(batch, entry)
				}
			}
			for _, e := range qr.Customer {
				entry := mapQuickBooksEntity("Customer", e.ID, e.MetaData, e.Raw())
				if entry != nil {
					if entry.Timestamp.After(batchMax) {
						batchMax = entry.Timestamp
					}
					batch = append(batch, entry)
				}
			}
			for _, e := range qr.Vendor {
				entry := mapQuickBooksEntity("Vendor", e.ID, e.MetaData, e.Raw())
				if entry != nil {
					if entry.Timestamp.After(batchMax) {
						batchMax = entry.Timestamp
					}
					batch = append(batch, entry)
				}
			}
		}
	}
	return handler(batch, batchMax, access.DefaultAuditPartition)
}

type quickbooksCDCResponse struct {
	CDCResponse []quickbooksCDCGroup `json:"CDCResponse"`
}

type quickbooksCDCGroup struct {
	QueryResponse []quickbooksQueryResponse `json:"QueryResponse"`
}

type quickbooksQueryResponse struct {
	Employee []quickbooksEntity `json:"Employee,omitempty"`
	Customer []quickbooksEntity `json:"Customer,omitempty"`
	Vendor   []quickbooksEntity `json:"Vendor,omitempty"`
}

type quickbooksEntity struct {
	ID          string             `json:"Id"`
	DisplayName string             `json:"DisplayName,omitempty"`
	Active      *bool              `json:"Active,omitempty"`
	MetaData    quickbooksMetaData `json:"MetaData"`
}

func (e quickbooksEntity) Raw() map[string]interface{} {
	b, _ := json.Marshal(e)
	out := map[string]interface{}{}
	_ = json.Unmarshal(b, &out)
	return out
}

type quickbooksMetaData struct {
	CreateTime      string `json:"CreateTime"`
	LastUpdatedTime string `json:"LastUpdatedTime"`
}

func mapQuickBooksEntity(kind, id string, md quickbooksMetaData, raw map[string]interface{}) *access.AuditLogEntry {
	stamp := strings.TrimSpace(md.LastUpdatedTime)
	if stamp == "" {
		stamp = strings.TrimSpace(md.CreateTime)
	}
	if stamp == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, stamp)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, stamp)
	}
	return &access.AuditLogEntry{
		EventID:          fmt.Sprintf("%s|%s|%s", kind, id, stamp),
		EventType:        "entity_changed",
		Action:           "update",
		Timestamp:        ts,
		TargetExternalID: id,
		TargetType:       kind,
		Outcome:          "success",
		RawData:          raw,
	}
}

func isAuditNotAvailable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "status 401") || strings.Contains(msg, "status 403")
}

var _ access.AccessAuditor = (*QuickBooksAccessConnector)(nil)
