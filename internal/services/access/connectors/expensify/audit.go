package expensify

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

// FetchAccessAuditLogs streams Expensify policy audit-trail events into
// the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	POST /Integration-Server/ExpensifyIntegrations
//	form: requestJobDescription={ "type":"get",
//	                              "credentials":{partnerUserID,partnerUserSecret},
//	                              "inputSettings":{"type":"policyAuditTrail",
//	                                               "policyID":..,
//	                                               "since":<RFC3339>} }
//
// Audit access is gated on Control-tier policies; lower tiers and
// non-admins return errors with auth/permission markers, which the
// connector soft-skips via access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *ExpensifyAccessConnector) FetchAccessAuditLogs(
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
	payload := map[string]interface{}{
		"type": "get",
		"credentials": map[string]string{
			"partnerUserID":     strings.TrimSpace(secrets.PartnerUserID),
			"partnerUserSecret": strings.TrimSpace(secrets.PartnerUserSecret),
		},
		"inputSettings": map[string]interface{}{
			"type":     "policyAuditTrail",
			"policyID": strings.TrimSpace(cfg.PolicyID),
		},
	}
	if !since.IsZero() {
		payload["inputSettings"].(map[string]interface{})["since"] = since.UTC().Format(time.RFC3339)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	form := url.Values{"requestJobDescription": []string{string(body)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL()+"/Integration-Server/ExpensifyIntegrations",
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("expensify: audit-trail: %w", err)
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return access.ErrAuditNotAvailable
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("expensify: audit-trail: status %d: %s", resp.StatusCode, string(respBody))
	}
	var envelope expensifyAuditEnvelope
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return fmt.Errorf("expensify: decode audit-trail: %w", err)
	}
	// Soft-skip when the API returns an auth/permission failure payload.
	if envelope.ResponseCode != 0 && envelope.ResponseCode != 200 &&
		expensifyAuditAuthDenied(envelope.ResponseMessage) {
		return access.ErrAuditNotAvailable
	}
	if len(envelope.Events) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(envelope.Events))
	batchMax := since
	for i := range envelope.Events {
		entry := mapExpensifyAuditEvent(&envelope.Events[i])
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

type expensifyAuditEvent struct {
	ID         string `json:"id"`
	EventType  string `json:"eventType"`
	Action     string `json:"action"`
	Timestamp  string `json:"timestamp"`
	UserID     string `json:"userID"`
	UserEmail  string `json:"userEmail"`
	EntityType string `json:"entityType"`
	EntityID   string `json:"entityID"`
	Outcome    string `json:"outcome"`
}

type expensifyAuditEnvelope struct {
	ResponseCode    int                   `json:"responseCode"`
	ResponseMessage string                `json:"responseMessage"`
	Events          []expensifyAuditEvent `json:"events"`
}

func mapExpensifyAuditEvent(e *expensifyAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseExpensifyTime(e.Timestamp)
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
		TargetExternalID: strings.TrimSpace(e.EntityID),
		TargetType:       strings.TrimSpace(e.EntityType),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func parseExpensifyTime(s string) time.Time {
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

func expensifyAuditAuthDenied(msg string) bool {
	low := strings.ToLower(strings.TrimSpace(msg))
	return strings.Contains(low, "unauthorized") ||
		strings.Contains(low, "permission") ||
		strings.Contains(low, "forbidden")
}

var _ access.AccessAuditor = (*ExpensifyAccessConnector)(nil)
