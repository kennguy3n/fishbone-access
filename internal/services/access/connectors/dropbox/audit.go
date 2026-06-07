package dropbox

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// dropboxAuditMaxPages bounds a single audit sweep so a provider that
// keeps returning has_more=true (or a server-side cursor bug) cannot
// spin the pagination loop forever; mirrors the cap used by the other
// paginated audit connectors in this family.
const dropboxAuditMaxPages = 200

// FetchAccessAuditLogs streams Dropbox Business team-log events into
// the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	POST /2/team_log/get_events       (initial)
//	POST /2/team_log/get_events/continue (subsequent pages, with cursor)
//
// Dropbox paginates by `has_more`/`cursor`; the handler is called
// once per page in chronological order. The `time.start_time`
// parameter is the lower bound; we omit it when `since` is zero to
// let the provider return its default retention window.
func (c *DropboxAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL()

	// First page.
	body := map[string]interface{}{"limit": 1000}
	if !since.IsZero() {
		body["time"] = map[string]interface{}{
			"start_time": since.UTC().Format(time.RFC3339),
			"end_time":   time.Now().UTC().Format(time.RFC3339),
		}
	}
	first := true
	pageCursor := ""
	for pageNum := 0; pageNum < dropboxAuditMaxPages; pageNum++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		var endpoint string
		var payload interface{}
		if first {
			endpoint = base + "/2/team_log/get_events"
			payload = body
			first = false
		} else {
			endpoint = base + "/2/team_log/get_events/continue"
			payload = map[string]string{"cursor": pageCursor}
		}
		respBody, err := c.postJSON(ctx, secrets, endpoint, payload)
		if err != nil {
			if strings.Contains(err.Error(), "status 403") {
				return access.ErrAuditNotAvailable
			}
			return err
		}
		var page dropboxEventsPage
		if err := json.Unmarshal(respBody, &page); err != nil {
			return fmt.Errorf("dropbox: decode team log events: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Events))
		batchMax := cursor
		for i := range page.Events {
			entry := mapDropboxEvent(&page.Events[i])
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
		if !page.HasMore || strings.TrimSpace(page.Cursor) == "" {
			return nil
		}
		pageCursor = page.Cursor
	}
	return nil
}

type dropboxEventsPage struct {
	Events  []dropboxEvent `json:"events"`
	Cursor  string         `json:"cursor"`
	HasMore bool           `json:"has_more"`
}

type dropboxEvent struct {
	Timestamp     string                 `json:"timestamp"`
	EventCategory map[string]interface{} `json:"event_category"`
	EventType     struct {
		Tag         string `json:".tag"`
		Description string `json:"description"`
	} `json:"event_type"`
	Actor        map[string]interface{}   `json:"actor"`
	Origin       map[string]interface{}   `json:"origin"`
	Context      map[string]interface{}   `json:"context"`
	Participants []map[string]interface{} `json:"participants"`
	Assets       []map[string]interface{} `json:"assets"`
}

func mapDropboxEvent(e *dropboxEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.EventType.Tag) == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, e.Timestamp)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, e.Timestamp)
	}
	if ts.IsZero() {
		// An unparseable timestamp would emit a zero Timestamp that
		// poisons the watermark cursor and forces an infinite
		// re-fetch; skip the entry instead.
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	var actorEmail, actorID, ipAddr string
	if user, ok := e.Actor["user"].(map[string]interface{}); ok {
		actorEmail, _ = user["email"].(string)
		actorID, _ = user["account_id"].(string)
	}
	if origin, ok := e.Origin["geo_location"].(map[string]interface{}); ok {
		ipAddr, _ = origin["ip_address"].(string)
	}
	return &access.AuditLogEntry{
		EventID:         e.EventType.Tag + "|" + e.Timestamp + "|" + actorID,
		EventType:       e.EventType.Tag,
		Action:          e.EventType.Description,
		Timestamp:       ts,
		ActorExternalID: actorID,
		ActorEmail:      actorEmail,
		IPAddress:       ipAddr,
		Outcome:         "success",
		RawData:         rawMap,
	}
}

var _ access.AccessAuditor = (*DropboxAccessConnector)(nil)
