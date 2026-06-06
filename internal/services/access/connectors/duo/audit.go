package duo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams Duo Security authentication-log events
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /admin/v2/logs/authentication?mintime={epochms}&limit=1000
//
// Duo v2 authentication logs are filtered by `mintime` (Unix epoch
// milliseconds) and bounded by `limit`. The handler is called once
// per provider page in chronological order so callers can persist
// `nextSince` (the newest timestamp seen so far) as a monotonic
// cursor.
//
// Authentication uses HMAC-SHA1 request signing via the existing
// `signDuoRequest` helper. On HTTP 401/403 the connector returns
// access.ErrAuditNotAvailable so callers treat Duo Free tenants
// (without admin API access) as plan-gated rather than failing the
// whole sync.
func (c *DuoAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]
	cursor := since
	const path = "/admin/v2/logs/authentication"
	mintime := since
	if mintime.IsZero() {
		// Duo's v2 auth-log endpoint requires a non-zero mintime;
		// default to "last 24h" on cold start.
		mintime = c.now().Add(-24 * time.Hour)
	}
	// nextOffset is the opaque pagination cursor returned by Duo. When
	// non-empty it must be passed back as the next_offset query param;
	// it encodes (timestamp, txid) so events at the same millisecond as
	// the previous page-max are not lost. mintime is only used on the
	// first page to bound the lookback window.
	nextOffset := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		params := map[string]string{
			"mintime": strconv.FormatInt(mintime.UTC().UnixMilli(), 10),
			"limit":   "1000",
		}
		if nextOffset != "" {
			params["next_offset"] = nextOffset
		}
		status, body, err := c.signedRaw(ctx, cfg, secrets, http.MethodGet, path, params)
		if err != nil {
			return err
		}
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			return access.ErrAuditNotAvailable
		}
		if status < 200 || status >= 300 {
			return fmt.Errorf("duo_security: %s status %d: %s", path, status, string(body))
		}
		var page duoAuthLogResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("duo_security: decode auth log: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Response.Authlogs))
		batchMax := cursor
		for i := range page.Response.Authlogs {
			entry := mapDuoAuthLog(&page.Response.Authlogs[i])
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
		nextOffset = strings.TrimSpace(page.Response.Metadata.NextOffset)
		if nextOffset == "" || len(page.Response.Authlogs) == 0 {
			return nil
		}
	}
}

type duoAuthLogResponse struct {
	Response struct {
		Authlogs []duoAuthLog `json:"authlogs"`
		Metadata duoAuthMeta  `json:"metadata"`
	} `json:"response"`
	Stat string `json:"stat"`
}

type duoAuthMeta struct {
	NextOffset string `json:"next_offset"`
	TotalCount int    `json:"total_objects"`
}

type duoAuthLog struct {
	Timestamp    int64                 `json:"timestamp"`
	ISOTimestamp string                `json:"isotimestamp"`
	Txid         string                `json:"txid"`
	EventType    string                `json:"event_type"`
	Result       string                `json:"result"`
	User         duoAuthLogUser        `json:"user"`
	AccessDevice duoAuthLogDevice      `json:"access_device"`
	Application  duoAuthLogApplication `json:"application"`
	Reason       string                `json:"reason"`
	Factor       string                `json:"factor"`
}

type duoAuthLogUser struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type duoAuthLogDevice struct {
	IP string `json:"ip"`
}

type duoAuthLogApplication struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

func mapDuoAuthLog(a *duoAuthLog) *access.AuditLogEntry {
	if a == nil {
		return nil
	}
	var ts time.Time
	if strings.TrimSpace(a.ISOTimestamp) != "" {
		ts, _ = time.Parse(time.RFC3339Nano, a.ISOTimestamp)
		if ts.IsZero() {
			ts, _ = time.Parse(time.RFC3339, a.ISOTimestamp)
		}
	}
	if ts.IsZero() && a.Timestamp > 0 {
		ts = time.Unix(a.Timestamp, 0).UTC()
	}
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(a)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	eventType := strings.TrimSpace(a.EventType)
	if eventType == "" {
		eventType = "authentication"
	}
	outcome := "success"
	if !strings.EqualFold(strings.TrimSpace(a.Result), "success") && strings.TrimSpace(a.Result) != "" {
		outcome = "failure"
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(a.Txid),
		EventType:        eventType,
		Action:           eventType,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(a.User.Key),
		ActorEmail:       strings.TrimSpace(a.User.Name),
		TargetExternalID: strings.TrimSpace(a.Application.Key),
		TargetType:       strings.TrimSpace(a.Application.Name),
		IPAddress:        strings.TrimSpace(a.AccessDevice.IP),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

var _ access.AccessAuditor = (*DuoAccessConnector)(nil)
