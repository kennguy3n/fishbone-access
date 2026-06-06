package hibob

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

// FetchAccessAuditLogs streams Bob people change-log entries into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	POST /v1/people/search    body: {showInactive: true, fields: [...], modifiedSince: <RFC3339>}
//
// Bob does not expose a dedicated audit-log endpoint on the standard
// plan; the change-log variant of `/v1/people/search` is the closest
// integration surface. Tenants without the required scope return
// 401 / 403 / 404, soft-skipped via access.ErrAuditNotAvailable.
func (c *HibobAccessConnector) FetchAccessAuditLogs(
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
	body := map[string]interface{}{
		"showInactive": true,
		"fields":       []string{"id", "displayName", "email", "internal.lifecycleStatus", "internal.terminationDate"},
	}
	if !since.IsZero() {
		body["modifiedSince"] = since.UTC().Format(time.RFC3339)
	}
	payload, _ := json.Marshal(body)

	req, err := c.newAuditRequest(ctx, secrets, payload)
	if err != nil {
		return err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("hibob: audit log: %w", err)
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return access.ErrAuditNotAvailable
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("hibob: audit log: status %d: %s", resp.StatusCode, string(bodyBytes))
	}
	var envelope struct {
		Employees []hibobAuditPerson `json:"employees"`
	}
	if err := json.Unmarshal(bodyBytes, &envelope); err != nil {
		return fmt.Errorf("hibob: decode audit log: %w", err)
	}
	if len(envelope.Employees) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(envelope.Employees))
	batchMax := since
	for i := range envelope.Employees {
		entry := mapHibobAuditPerson(&envelope.Employees[i])
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

func (c *HibobAccessConnector) newAuditRequest(ctx context.Context, secrets Secrets, payload []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL()+"/v1/people/search", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Basic "+strings.TrimSpace(secrets.APIToken))
	return req, nil
}

type hibobAuditPerson struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Internal    struct {
		LifecycleStatus  string `json:"lifecycleStatus"`
		TerminationDate  string `json:"terminationDate"`
		LastModification string `json:"lastModification"`
	} `json:"internal"`
}

func mapHibobAuditPerson(p *hibobAuditPerson) *access.AuditLogEntry {
	if p == nil || strings.TrimSpace(p.ID) == "" {
		return nil
	}
	ts := parseHibobAuditTime(p.Internal.LastModification)
	if ts.IsZero() {
		ts = parseHibobAuditTime(p.Internal.TerminationDate)
	}
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(p)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          fmt.Sprintf("%s-%s", p.ID, ts.UTC().Format("20060102T150405Z")),
		EventType:        "people.modified",
		Action:           "modified",
		Timestamp:        ts,
		TargetExternalID: p.ID,
		TargetType:       "employee",
		Outcome:          strings.TrimSpace(p.Internal.LifecycleStatus),
		RawData:          rawMap,
	}
}

func parseHibobAuditTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
