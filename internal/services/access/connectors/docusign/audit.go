package docusign

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams DocuSign API diagnostics request logs
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /restapi/v2.1/diagnostics/request_logs
//
// DocuSign's diagnostics logging endpoint returns request logs the
// account has buffered for debugging API calls. The list is bounded
// (DocuSign trims to the most recent 50 entries) and not paginated,
// so the handler is invoked once. Multi-page Monitor API
// (`/api/v2.0/datasets/monitor/stream`) is reserved for the
// dedicated streaming worker; this batch ships the diagnostics
// endpoint, which is universally available on every Production /
// Demo account that has request logging enabled.
//
// On HTTP 401/403 the connector returns access.ErrAuditNotAvailable
// so callers treat the account as plan- or feature-gated rather than
// failing the whole sync.
func (c *DocuSignAccessConnector) FetchAccessAuditLogs(
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
	full := c.baseURL(cfg) + "/restapi/v2.1/diagnostics/request_logs"
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
	var page docusignRequestLogResponse
	if err := json.Unmarshal(body, &page); err != nil {
		return fmt.Errorf("docusign: decode request_logs: %w", err)
	}
	batch := make([]*access.AuditLogEntry, 0, len(page.RequestLogs))
	batchMax := since
	for i := range page.RequestLogs {
		entry := mapDocuSignRequestLog(&page.RequestLogs[i])
		if entry == nil {
			continue
		}
		if !since.IsZero() && !entry.Timestamp.After(since) {
			continue
		}
		if entry.Timestamp.After(batchMax) {
			batchMax = entry.Timestamp
		}
		batch = append(batch, entry)
	}
	return handler(batch, batchMax, access.DefaultAuditPartition)
}

type docusignRequestLogResponse struct {
	RequestLogs []docusignRequestLog `json:"requestLogs"`
}

type docusignRequestLog struct {
	RequestLogID string `json:"requestLogId"`
	CreatedDate  string `json:"createdDate"`
	Description  string `json:"description"`
	Status       string `json:"status"`
	Function     string `json:"function"`
	Method       string `json:"method"`
	AccountID    string `json:"accountId"`
	UserName     string `json:"userName"`
}

func mapDocuSignRequestLog(r *docusignRequestLog) *access.AuditLogEntry {
	if r == nil || strings.TrimSpace(r.CreatedDate) == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, r.CreatedDate)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, r.CreatedDate)
	}
	raw, _ := json.Marshal(r)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	eventType := strings.TrimSpace(r.Function)
	if eventType == "" {
		eventType = strings.TrimSpace(r.Method)
	}
	if eventType == "" {
		eventType = "api_request"
	}
	outcome := "success"
	if strings.HasPrefix(strings.TrimSpace(r.Status), "4") || strings.HasPrefix(strings.TrimSpace(r.Status), "5") {
		outcome = "failure"
	}
	return &access.AuditLogEntry{
		EventID:         strings.TrimSpace(r.RequestLogID),
		EventType:       eventType,
		Action:          strings.TrimSpace(r.Method),
		Timestamp:       ts,
		ActorEmail:      strings.TrimSpace(r.UserName),
		ActorExternalID: strings.TrimSpace(r.AccountID),
		Outcome:         outcome,
		RawData:         rawMap,
	}
}

func isAuditNotAvailable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "status 401") || strings.Contains(msg, "status 403")
}

var _ access.AccessAuditor = (*DocuSignAccessConnector)(nil)
