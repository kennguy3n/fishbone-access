package monday

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams Monday.com Enterprise audit-log events
// into the access audit pipeline via the GraphQL `audit_log` query.
// Implements access.AccessAuditor.
//
// Monday's GraphQL endpoint paginates audit events by `page`/`limit`;
// iteration stops when a page returns fewer than `pageSize` rows. The
// query gates on `from` so the worker can advance the cursor without
// reprocessing. Workspaces that aren't on the Enterprise tier return a
// GraphQL error containing "audit"/"enterprise" tokens, which collapses
// to access.ErrAuditNotAvailable so the worker soft-skips the tenant.
func (c *MondayAccessConnector) FetchAccessAuditLogs(
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
	const limit = 100
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		query := buildMondayAuditQuery(since, page, limit)
		body, status, postErr := c.postAudit(ctx, secrets, query)
		if postErr != nil {
			return postErr
		}
		switch status {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if status < 200 || status >= 300 {
			return fmt.Errorf("monday: audit_log: status %d: %s", status, string(body))
		}
		var resp mondayAuditResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("monday: decode audit page: %w", err)
		}
		if len(resp.Errors) > 0 {
			if mondayAuditErrorIsUnsupported(resp.Errors) {
				return access.ErrAuditNotAvailable
			}
			return fmt.Errorf("monday: audit_log graphql: %s", resp.Errors[0].Message)
		}
		entries := resp.Data.AuditLog
		batch := make([]*access.AuditLogEntry, 0, len(entries))
		batchMax := cursor
		for i := range entries {
			entry := mapMondayAuditEvent(&entries[i])
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
		if len(entries) < limit {
			return nil
		}
		page++
	}
}

func buildMondayAuditQuery(since time.Time, page, limit int) string {
	var b strings.Builder
	b.WriteString("query { audit_log(")
	if !since.IsZero() {
		b.WriteString(fmt.Sprintf("from: %q, ", since.UTC().Format(time.RFC3339)))
	}
	b.WriteString(fmt.Sprintf("page: %d, limit: %d", page, limit))
	b.WriteString(") { id event timestamp user_id user_email account_id ip_address user_agent } }")
	return b.String()
}

func (c *MondayAccessConnector) postAudit(ctx context.Context, secrets Secrets, query string) ([]byte, int, error) {
	payload, err := json.Marshal(graphQLRequest{Query: query})
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL(), bytes.NewReader(payload))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", strings.TrimSpace(secrets.APIToken))
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("monday: audit_log: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return body, resp.StatusCode, nil
}

type mondayAuditResponse struct {
	Data struct {
		AuditLog []mondayAuditEvent `json:"audit_log"`
	} `json:"data"`
	Errors []graphQLError `json:"errors,omitempty"`
}

type mondayAuditEvent struct {
	ID        json.Number `json:"id"`
	Event     string      `json:"event"`
	Timestamp string      `json:"timestamp"`
	UserID    json.Number `json:"user_id"`
	UserEmail string      `json:"user_email"`
	AccountID json.Number `json:"account_id"`
	IPAddress string      `json:"ip_address"`
	UserAgent string      `json:"user_agent"`
}

func mapMondayAuditEvent(e *mondayAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID.String()) == "" {
		return nil
	}
	ts := parseMondayTime(e.Timestamp)
	if ts.IsZero() {
		return nil
	}
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(e)
	_ = json.Unmarshal(raw, &rawMap)
	actorID := strings.TrimSpace(e.UserID.String())
	if actorID == "0" {
		actorID = ""
	}
	return &access.AuditLogEntry{
		EventID:         e.ID.String(),
		EventType:       strings.TrimSpace(e.Event),
		Action:          strings.TrimSpace(e.Event),
		Timestamp:       ts,
		ActorExternalID: actorID,
		ActorEmail:      strings.TrimSpace(e.UserEmail),
		IPAddress:       strings.TrimSpace(e.IPAddress),
		UserAgent:       strings.TrimSpace(e.UserAgent),
		Outcome:         "success",
		RawData:         rawMap,
	}
}

// parseMondayTime parses Monday.com's GraphQL audit-log timestamps,
// trying RFC3339Nano first and falling back to plain RFC3339 / numeric
// epoch seconds (some clusters surface the latter).
func parseMondayTime(s string) time.Time {
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
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
		// Treat very large numbers as ms; otherwise assume seconds.
		if n > 1_000_000_000_000 {
			return time.UnixMilli(n).UTC()
		}
		return time.Unix(n, 0).UTC()
	}
	return time.Time{}
}

func mondayAuditErrorIsUnsupported(errs []graphQLError) bool {
	for _, e := range errs {
		lower := strings.ToLower(e.Message)
		if strings.Contains(lower, "enterprise") ||
			strings.Contains(lower, "not authorized") ||
			strings.Contains(lower, "permission") ||
			strings.Contains(lower, "audit log") {
			return true
		}
	}
	return false
}

var _ access.AccessAuditor = (*MondayAccessConnector)(nil)
