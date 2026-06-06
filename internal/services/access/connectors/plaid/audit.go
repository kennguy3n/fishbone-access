package plaid

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	plaidAuditPageSize = 100
	plaidAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Plaid audit-trail events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	POST /team/audit_trail/list
//	body { client_id, secret, count, offset, modified_after }
//
// Audit-trail access requires the `audit_trail:read` scope; lower scopes
// return 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *PlaidAccessConnector) FetchAccessAuditLogs(
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
	endpoint := c.baseURL(cfg) + "/team/audit_trail/list"

	var collected []plaidAuditEvent
	for page := 0; page < plaidAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		payload := map[string]interface{}{
			"client_id": strings.TrimSpace(secrets.ClientID),
			"secret":    strings.TrimSpace(secrets.Secret),
			"count":     plaidAuditPageSize,
			"offset":    page * plaidAuditPageSize,
		}
		if !since.IsZero() {
			payload["modified_after"] = since.UTC().Format(time.RFC3339)
		}
		body, _ := json.Marshal(payload)
		respBody, status, rerr := c.postAudit(ctx, endpoint, body)
		if rerr != nil {
			return rerr
		}
		switch status {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if status < 200 || status >= 300 {
			return fmt.Errorf("plaid: audit_trail: status %d: %s", status, string(respBody))
		}
		var envelope plaidAuditPage
		if err := json.Unmarshal(respBody, &envelope); err != nil {
			return fmt.Errorf("plaid: decode audit_trail: %w", err)
		}
		collected = append(collected, envelope.AuditTrail...)
		if len(envelope.AuditTrail) < plaidAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapPlaidAuditEvent(&collected[i])
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

func (c *PlaidAccessConnector) postAudit(ctx context.Context, endpoint string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("plaid: audit_trail post: %w", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return out, resp.StatusCode, nil
}

type plaidAuditEvent struct {
	ID         string `json:"id"`
	EventType  string `json:"event_type"`
	Action     string `json:"action"`
	Timestamp  string `json:"timestamp"`
	UserID     string `json:"user_id"`
	UserEmail  string `json:"user_email"`
	ResourceID string `json:"resource_id"`
	Outcome    string `json:"outcome"`
}

type plaidAuditPage struct {
	AuditTrail []plaidAuditEvent `json:"audit_trail"`
}

func mapPlaidAuditEvent(e *plaidAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parsePlaidTime(e.Timestamp)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.Action)
	if action == "" {
		action = strings.TrimSpace(e.EventType)
	}
	outcome := strings.TrimSpace(e.Outcome)
	if outcome == "" {
		outcome = "success"
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.ID),
		EventType:        strings.TrimSpace(e.EventType),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.UserID),
		ActorEmail:       strings.TrimSpace(e.UserEmail),
		TargetExternalID: strings.TrimSpace(e.ResourceID),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func parsePlaidTime(s string) time.Time {
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

var _ access.AccessAuditor = (*PlaidAccessConnector)(nil)
