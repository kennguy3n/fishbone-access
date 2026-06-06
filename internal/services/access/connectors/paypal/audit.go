package paypal

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
	paypalAuditPageSize = 100
	paypalAuditMaxPages = 200

	// paypalAuditBackfill bounds the first-ever audit run (no persisted
	// cursor). The PayPal Transaction Search API rejects any start_date/
	// end_date span longer than 31 days, so unlike Okta/1Password we cannot
	// reach back further in a single window — 31 days is the provider's
	// maximum and therefore the widest correct first-run backfill. The
	// previous 24h default silently dropped up to 30 days of history.
	// Subsequent runs resume from the persisted cursor.
	paypalAuditBackfill = 31 * 24 * time.Hour
)

// FetchAccessAuditLogs streams PayPal transaction/activity events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/reporting/transactions?start_date={iso}&end_date={iso}
//	    &page_size=100&page=N
//
// Requires the `https://uri.paypal.com/services/reporting/search/read`
// scope obtained via the existing OAuth2 client-credentials flow. Lower
// scopes return 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *PayPalAccessConnector) FetchAccessAuditLogs(
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
	if since.IsZero() {
		since = time.Now().UTC().Add(-paypalAuditBackfill)
	}
	base := c.baseURL(cfg) + "/v1/reporting/transactions"

	var collected []paypalAuditEvent
	for page := 1; page <= paypalAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Fetch the token per page (cached) so a long audit pull refreshes
		// the bearer as it nears expiry rather than reusing one token for
		// the entire multi-page scan.
		token, err := c.accessToken(ctx, cfg, secrets)
		if err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("page_size", fmt.Sprintf("%d", paypalAuditPageSize))
		q.Set("start_date", since.UTC().Format(time.RFC3339))
		q.Set("end_date", time.Now().UTC().Format(time.RFC3339))
		req, err := c.newRequest(ctx, token, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.doHTTP(req)
		if err != nil {
			return fmt.Errorf("paypal: transactions: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("paypal: transactions: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope paypalAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("paypal: decode transactions: %w", err)
		}
		collected = append(collected, envelope.TransactionDetails...)
		if envelope.Page >= envelope.TotalPages || len(envelope.TransactionDetails) < paypalAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapPayPalAuditEvent(&collected[i])
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

type paypalAuditEvent struct {
	TransactionInfo struct {
		TransactionID             string `json:"transaction_id"`
		TransactionEventCode      string `json:"transaction_event_code"`
		TransactionUpdatedDate    string `json:"transaction_updated_date"`
		TransactionInitiationDate string `json:"transaction_initiation_date"`
		TransactionStatus         string `json:"transaction_status"`
	} `json:"transaction_info"`
	PayerInfo struct {
		AccountID    string `json:"account_id"`
		EmailAddress string `json:"email_address"`
	} `json:"payer_info"`
}

type paypalAuditPage struct {
	TransactionDetails []paypalAuditEvent `json:"transaction_details"`
	Page               int                `json:"page"`
	TotalPages         int                `json:"total_pages"`
}

func mapPayPalAuditEvent(e *paypalAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.TransactionInfo.TransactionID) == "" {
		return nil
	}
	tsRaw := e.TransactionInfo.TransactionUpdatedDate
	if strings.TrimSpace(tsRaw) == "" {
		tsRaw = e.TransactionInfo.TransactionInitiationDate
	}
	ts := parsePayPalTime(tsRaw)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	outcome := "success"
	if status := strings.ToUpper(strings.TrimSpace(e.TransactionInfo.TransactionStatus)); status == "F" || status == "D" {
		outcome = "failure"
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.TransactionInfo.TransactionID),
		EventType:        strings.TrimSpace(e.TransactionInfo.TransactionEventCode),
		Action:           strings.TrimSpace(e.TransactionInfo.TransactionEventCode),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.PayerInfo.AccountID),
		ActorEmail:       strings.TrimSpace(e.PayerInfo.EmailAddress),
		TargetExternalID: strings.TrimSpace(e.TransactionInfo.TransactionID),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func parsePayPalTime(s string) time.Time {
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

var _ access.AccessAuditor = (*PayPalAccessConnector)(nil)
