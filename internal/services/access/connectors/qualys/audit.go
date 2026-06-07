package qualys

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams Qualys VMDR activity-log records into
// the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/2.0/fo/activity_log/?action=list&since_datetime={iso}
//
// HTTP Basic + X-Requested-With + XML envelope. Non-eligible
// subscriptions surface 401/403/404 which soft-skip via
// access.ErrAuditNotAvailable.
func (c *QualysAccessConnector) FetchAccessAuditLogs(
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
	q := url.Values{}
	q.Set("action", "list")
	q.Set("truncation_limit", "1000")
	if !since.IsZero() {
		q.Set("since_datetime", since.UTC().Format("2006-01-02T15:04:05Z"))
	}
	endpoint := c.baseURL(cfg) + "/api/2.0/fo/activity_log/?" + q.Encode()
	req, err := c.newRequest(ctx, secrets, http.MethodGet, endpoint)
	if err != nil {
		return err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("qualys: activity_log: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return access.ErrAuditNotAvailable
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("qualys: activity_log: status %d: %s", resp.StatusCode, string(body))
	}

	var envelope qualysActivityLogOutput
	if err := xml.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("qualys: decode activity_log: %w", err)
	}
	records := envelope.Response.ActivityLogList.ActivityLog
	if len(records) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(records))
	batchMax := since
	for i := range records {
		entry := mapQualysActivityLog(&records[i])
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

type qualysActivityLog struct {
	ID       string `xml:"ID"`
	Action   string `xml:"Action"`
	Module   string `xml:"Module"`
	Date     string `xml:"Date"`
	Username string `xml:"Username"`
	Details  string `xml:"Details"`
	UserIP   string `xml:"User_IP"`
}

type qualysActivityLogOutput struct {
	XMLName  xml.Name `xml:"ACTIVITY_LOG_OUTPUT"`
	Response struct {
		ActivityLogList struct {
			ActivityLog []qualysActivityLog `xml:"ACTIVITY_LOG"`
		} `xml:"ACTIVITY_LOG_LIST"`
	} `xml:"RESPONSE"`
}

func mapQualysActivityLog(e *qualysActivityLog) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseQualysTime(e.Date)
	if ts.IsZero() {
		return nil
	}
	rawMap := map[string]interface{}{
		"id":       strings.TrimSpace(e.ID),
		"action":   strings.TrimSpace(e.Action),
		"module":   strings.TrimSpace(e.Module),
		"date":     strings.TrimSpace(e.Date),
		"username": strings.TrimSpace(e.Username),
		"details":  strings.TrimSpace(e.Details),
		"user_ip":  strings.TrimSpace(e.UserIP),
	}
	action := strings.TrimSpace(e.Action)
	if action == "" {
		action = strings.TrimSpace(e.Module)
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.ID),
		EventType:        strings.TrimSpace(e.Module),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Username),
		ActorEmail:       "",
		TargetExternalID: strings.TrimSpace(e.Module),
		IPAddress:        strings.TrimSpace(e.UserIP),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseQualysTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if ts, err := time.Parse("2006-01-02T15:04:05Z", s); err == nil {
		return ts.UTC()
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts.UTC()
	}
	return time.Time{}
}

var _ access.AccessAuditor = (*QualysAccessConnector)(nil)
