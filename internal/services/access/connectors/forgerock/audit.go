package forgerock

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
	forgerockAuditPageSize = 100
	forgerockAuditMaxPages = 200
)

// FetchAccessAuditLogs streams ForgeRock IDM audit/access records into
// the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /openidm/audit/access?_queryFilter=true&_pageSize=100&_pagedResultsCookie={cookie}
//
// Bearer auth via ForgeRockAccessConnector.newRequest; non-eligible
// realms soft-skip via access.ErrAuditNotAvailable.
func (c *ForgeRockAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL(cfg) + "/openidm/audit/access"

	var collected []forgerockAuditEvent
	cookie := ""
	for page := 0; page < forgerockAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("_queryFilter", "true")
		q.Set("_pageSize", fmt.Sprintf("%d", forgerockAuditPageSize))
		if cookie != "" {
			q.Set("_pagedResultsCookie", cookie)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("forgerock: audit access: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("forgerock: audit access: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope forgerockAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("forgerock: decode audit access: %w", err)
		}
		collected = append(collected, envelope.Result...)
		if envelope.PagedResultsCookie == "" || len(envelope.Result) < forgerockAuditPageSize {
			break
		}
		cookie = envelope.PagedResultsCookie
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapForgeRockAuditEvent(&collected[i])
		if entry == nil {
			continue
		}
		if entry.Timestamp.Before(since) {
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

type forgerockAuditEvent struct {
	ID        string `json:"_id"`
	Timestamp string `json:"timestamp"`
	EventName string `json:"eventName"`
	UserID    string `json:"userId"`
	Principal string `json:"principal"`
	Component string `json:"component"`
	Client    struct {
		IP string `json:"ip"`
	} `json:"client"`
}

type forgerockAuditPage struct {
	Result             []forgerockAuditEvent `json:"result"`
	PagedResultsCookie string                `json:"pagedResultsCookie"`
}

func mapForgeRockAuditEvent(e *forgerockAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseForgeRockTime(e.Timestamp)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.EventName)
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.ID),
		EventType:        strings.TrimSpace(e.EventName),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.UserID),
		ActorEmail:       strings.TrimSpace(e.Principal),
		TargetExternalID: strings.TrimSpace(e.Component),
		IPAddress:        strings.TrimSpace(e.Client.IP),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseForgeRockTime(s string) time.Time {
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

var _ access.AccessAuditor = (*ForgeRockAccessConnector)(nil)
