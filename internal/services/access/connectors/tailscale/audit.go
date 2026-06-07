package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams Tailscale tailnet "configuration audit"
// log entries into the access audit pipeline. Implements
// access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v2/tailnet/{tailnet}/logging/configuration?start={iso}&end={iso}
//
// Tailscale exposes the audit log over the standard tailnet API and
// authenticates with HTTP Basic where the API key is the username and
// the password is empty — the same auth model as the rest of this
// connector.
//
// Tailnets without configuration-audit access (free / personal plans)
// return 401 / 403 / 404, which the connector soft-skips via
// access.ErrAuditNotAvailable.
func (c *TailscaleAccessConnector) FetchAccessAuditLogs(
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
	path := "/api/v2/tailnet/" + url.PathEscape(cfg.Tailnet) + "/logging/configuration"
	q := url.Values{}
	if !since.IsZero() {
		q.Set("start", since.UTC().Format(time.RFC3339))
		q.Set("end", c.now().UTC().Format(time.RFC3339))
	}
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
	if err != nil {
		return err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("tailscale: audit log: %w", err)
	}
	body, readErr := readTSAuditBody(resp)
	if readErr != nil {
		return readErr
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return access.ErrAuditNotAvailable
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("tailscale: audit log: status %d: %s", resp.StatusCode, string(body))
	}
	var resp1 tsAuditResponse
	if err := json.Unmarshal(body, &resp1); err != nil {
		return fmt.Errorf("tailscale: decode audit log: %w", err)
	}
	events := resp1.Logs
	if len(events) == 0 && len(resp1.Events) > 0 {
		events = resp1.Events
	}
	if len(events) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(events))
	batchMax := since
	for i := range events {
		entry := mapTSAuditEvent(&events[i])
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

func (c *TailscaleAccessConnector) now() time.Time {
	if c.timeOverride != nil {
		return c.timeOverride()
	}
	return time.Now()
}

type tsAuditResponse struct {
	Logs   []tsAuditEvent `json:"logs"`
	Events []tsAuditEvent `json:"events"`
}

type tsAuditEvent struct {
	EventID    string `json:"eventId"`
	EventGroup string `json:"eventGroupID"`
	Action     string `json:"action"`
	Origin     string `json:"origin"`
	Actor      struct {
		ID          string `json:"id"`
		LoginName   string `json:"loginName"`
		DisplayName string `json:"displayName"`
		Type        string `json:"type"`
	} `json:"actor"`
	Target struct {
		ID   string `json:"id"`
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"target"`
	EventTime string                 `json:"eventTime"`
	Raw       map[string]interface{} `json:"-"`
}

func mapTSAuditEvent(e *tsAuditEvent) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	id := strings.TrimSpace(e.EventID)
	if id == "" {
		id = strings.TrimSpace(e.EventGroup)
	}
	if id == "" {
		return nil
	}
	ts := parseTSAuditTime(e.EventTime)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	actorEmail := ""
	if strings.Contains(e.Actor.LoginName, "@") {
		actorEmail = e.Actor.LoginName
	}
	return &access.AuditLogEntry{
		EventID:          id,
		EventType:        strings.TrimSpace(e.Action),
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Actor.ID),
		ActorEmail:       actorEmail,
		TargetExternalID: strings.TrimSpace(e.Target.ID),
		TargetType:       strings.TrimSpace(e.Target.Type),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseTSAuditTime(s string) time.Time {
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

func readTSAuditBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("tailscale: empty response")
	}
	defer resp.Body.Close()
	// Strict byte-exact 1 MB bound; the earlier chunked read could
	// overshoot by up to one 4 KB buffer before the post-append guard
	// tripped. Matches readSplunkBody in splunk/audit.go.
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

var _ access.AccessAuditor = (*TailscaleAccessConnector)(nil)
