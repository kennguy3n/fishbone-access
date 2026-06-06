package auth0

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

// FetchAccessAuditLogs streams Auth0 tenant log events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v2/logs?q=date:[{since} TO *]&sort=date:1&from={log_id}&take=100
//
// Auth0 paginates by `from={log_id}` (checkpoint via the previous
// page's last log_id) rather than offset; the handler is called per
// page in chronological order. Outcomes map from the leading "s"
// (success) or "f" (failure) prefix on Auth0's `type` field.
func (c *Auth0AccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return err
	}

	since := sincePartitions[access.DefaultAuditPartition]
	cursor := since
	from := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("take", "100")
		q.Set("sort", "date:1")
		if !since.IsZero() {
			q.Set("q", fmt.Sprintf("date:[%s TO *]", since.UTC().Format(time.RFC3339)))
		}
		if from != "" {
			q.Set("from", from)
		}
		path := "/api/v2/logs?" + q.Encode()
		req, err := c.newAuthedRequest(ctx, cfg, token, http.MethodGet, path, nil)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var page []auth0AuditLogEvent
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("auth0: decode logs page: %w", err)
		}
		if len(page) == 0 {
			return nil
		}
		batch := make([]*access.AuditLogEntry, 0, len(page))
		batchMax := cursor
		for i := range page {
			entry := mapAuth0Log(&page[i])
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
		from = page[len(page)-1].LogID
		if from == "" {
			return nil
		}
	}
}

type auth0AuditLogEvent struct {
	LogID       string `json:"log_id"`
	Date        string `json:"date"`
	Type        string `json:"type"`
	Description string `json:"description"`
	ClientID    string `json:"client_id"`
	ClientName  string `json:"client_name"`
	IP          string `json:"ip"`
	UserAgent   string `json:"user_agent"`
	UserID      string `json:"user_id"`
	UserName    string `json:"user_name"`
	Connection  string `json:"connection"`
}

func mapAuth0Log(e *auth0AuditLogEvent) *access.AuditLogEntry {
	if e == nil || e.LogID == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339, e.Date)
	outcome := "success"
	if t := strings.ToLower(strings.TrimSpace(e.Type)); strings.HasPrefix(t, "f") {
		outcome = "failure"
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:         e.LogID,
		EventType:       e.Type,
		Action:          e.Description,
		Timestamp:       ts,
		ActorExternalID: e.UserID,
		ActorEmail:      e.UserName,
		IPAddress:       e.IP,
		UserAgent:       e.UserAgent,
		Outcome:         outcome,
		RawData:         rawMap,
	}
}

var _ access.AccessAuditor = (*Auth0AccessConnector)(nil)
