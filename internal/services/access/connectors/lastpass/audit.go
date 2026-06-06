package lastpass

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams LastPass Enterprise audit-log events
// (cmd=reporting) into the access audit pipeline. Implements
// access.AccessAuditor.
//
// Endpoint:
//
//	POST /enterpriseapi.php
//	body: {"cid":..., "provhash":..., "cmd":"reporting",
//	       "data":{"from":..., "to":..., "user":"allusers"}}
//
// LastPass's Enterprise reporting endpoint accepts a `from` / `to`
// window (UTC, format YYYY-MM-DD hh:mm:ss) and returns one row per
// event in a JSON object keyed by sequence number. The endpoint
// returns up to 500 events per call; callers advance `from` past the
// newest seen event for incremental pulls. The handler is invoked
// once per batch.
//
// On HTTP 401/403, or on a LastPass `status:"FAIL"` response whose
// error message names a permission/plan condition (e.g. "not
// authorized", "license required", "subscription required"), the
// connector returns access.ErrAuditNotAvailable so callers treat
// non-Enterprise tenants as plan-gated. All other `status:"FAIL"`
// responses (transient errors, rate limits, invalid params, etc.)
// bubble up as ordinary errors so the sync retries rather than
// silently classifying the connector as plan-gated.
func (c *LastPassAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]
	from := since
	if from.IsZero() {
		from = time.Now().Add(-24 * time.Hour)
	}
	to := time.Now()
	payload := buildPayload(cfg, secrets, "reporting", map[string]interface{}{
		"from": from.UTC().Format("2006-01-02 15:04:05"),
		"to":   to.UTC().Format("2006-01-02 15:04:05"),
		"user": "allusers",
	})
	body, err := c.postJSON(ctx, payload)
	if err != nil {
		if isAuditNotAvailable(err) {
			return access.ErrAuditNotAvailable
		}
		return err
	}
	events, err := decodeLastPassAuditLog(body)
	if err != nil {
		return err
	}
	batch := make([]*access.AuditLogEntry, 0, len(events))
	batchMax := since
	for _, e := range events {
		entry := mapLastPassAuditEvent(e)
		if entry == nil {
			continue
		}
		if entry.Timestamp.After(batchMax) {
			batchMax = entry.Timestamp
		}
		batch = append(batch, entry)
	}
	return handler(batch, batchMax, access.DefaultAuditPartition)
}

// decodeLastPassAuditLog handles the two response shapes LastPass uses
// for cmd=reporting: a JSON array, or a JSON object keyed by sequence
// number ("0", "1", ...).
func decodeLastPassAuditLog(body []byte) ([]lastpassAuditEvent, error) {
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "[") {
		var arr []lastpassAuditEvent
		if err := json.Unmarshal(body, &arr); err != nil {
			return nil, fmt.Errorf("lastpass: decode reporting (array): %w", err)
		}
		return arr, nil
	}
	var keyed map[string]lastpassAuditEvent
	if err := json.Unmarshal(body, &keyed); err != nil {
		return nil, fmt.Errorf("lastpass: decode reporting (map): %w", err)
	}
	out := make([]lastpassAuditEvent, 0, len(keyed))
	for k, v := range keyed {
		if v.SeqNumber == "" {
			v.SeqNumber = k
		}
		out = append(out, v)
	}
	return out, nil
}

type lastpassAuditEvent struct {
	SeqNumber string `json:"-"`
	Time      string `json:"Time"`
	Username  string `json:"Username"`
	IPAddress string `json:"IP_Address"`
	Action    string `json:"Action"`
	Data      string `json:"Data"`
}

func mapLastPassAuditEvent(e lastpassAuditEvent) *access.AuditLogEntry {
	if strings.TrimSpace(e.Time) == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, e.Time)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, e.Time)
	}
	if ts.IsZero() {
		// LastPass also serves "2024-01-01 12:34:56" UTC strings.
		ts, _ = time.Parse("2006-01-02 15:04:05", e.Time)
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	eventType := strings.TrimSpace(e.Action)
	if eventType == "" {
		eventType = "lastpass_event"
	}
	return &access.AuditLogEntry{
		EventID:    strings.TrimSpace(e.SeqNumber),
		EventType:  eventType,
		Action:     eventType,
		Timestamp:  ts,
		ActorEmail: strings.TrimSpace(e.Username),
		IPAddress:  strings.TrimSpace(e.IPAddress),
		Outcome:    "success",
		RawData:    rawMap,
	}
}

// auditNotAvailableMarkers names the substrings that indicate a LastPass
// `status:"FAIL"` response is plan-gated (cmd=reporting not available on
// this account) rather than a transient/operational failure. Match is
// case-insensitive against the full error string returned by postJSON,
// which already embeds the LastPass response body.
var auditNotAvailableMarkers = []string{
	"not authorized",
	"unauthorized",
	"not allowed",
	"no permission",
	"permission denied",
	"insufficient privileges",
	"license required",
	"subscription required",
	"not enterprise",
	"enterprise required",
	"feature not available",
	"reporting not available",
}

func isAuditNotAvailable(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "status 401") || strings.Contains(msg, "status 403") {
		return true
	}
	// Only treat a LastPass-level `status:"FAIL"` as plan-gated when
	// the message names a known permission/plan condition. Generic
	// FAIL responses (rate limits, invalid params, transient backend
	// errors) must bubble up so the sync retries instead of silently
	// classifying the tenant as plan-gated.
	if !strings.Contains(msg, "api fail") {
		return false
	}
	for _, m := range auditNotAvailableMarkers {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}

var _ access.AccessAuditor = (*LastPassAccessConnector)(nil)
