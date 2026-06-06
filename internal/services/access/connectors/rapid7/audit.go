package rapid7

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

// FetchAccessAuditLogs streams Rapid7 InsightVM administration log
// events into the access audit pipeline. Implements
// access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/3/administration/log?page={n}&size=100
//
// Rapid7 paginates by page/size; the handler is called once per
// provider page in chronological order so callers can persist
// `nextSince` (the newest `date` timestamp seen so far) as a
// monotonic cursor.
//
// On HTTP 401/403 the connector returns access.ErrAuditNotAvailable
// so callers treat the tenant as plan- or role-gated rather than
// failing the whole sync.
func (c *Rapid7AccessConnector) FetchAccessAuditLogs(
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
	cursor := since
	page := 0
	base := c.baseURL(cfg)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("size", "100")
		full := base + "/api/3/administration/log?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, full)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			if isAuditNotAvailable(err) {
				return access.ErrAuditNotAvailable
			}
			return err
		}
		var resp rapid7AuditPage
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("rapid7: decode audit log: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(resp.Resources))
		batchMax := cursor
		for i := range resp.Resources {
			entry := mapRapid7AuditEvent(&resp.Resources[i])
			if entry == nil {
				continue
			}
			if !since.IsZero() && !entry.Timestamp.After(since) {
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
		if resp.Page.TotalPages <= page+1 || len(resp.Resources) == 0 {
			return nil
		}
		page++
	}
}

type rapid7AuditPage struct {
	Resources []rapid7AuditEvent `json:"resources"`
	Page      struct {
		Number     int `json:"number"`
		Size       int `json:"size"`
		TotalPages int `json:"totalPages"`
		TotalCount int `json:"totalResources"`
	} `json:"page"`
}

type rapid7AuditEvent struct {
	ID      string `json:"id"`
	Action  string `json:"action"`
	Date    string `json:"date"`
	Source  string `json:"source"`
	User    string `json:"user"`
	Address string `json:"address"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

func mapRapid7AuditEvent(e *rapid7AuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.Date) == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, e.Date)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, e.Date)
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	outcome := "success"
	if strings.EqualFold(strings.TrimSpace(e.Status), "failure") || strings.EqualFold(strings.TrimSpace(e.Status), "denied") {
		outcome = "failure"
	}
	return &access.AuditLogEntry{
		EventID:    strings.TrimSpace(e.ID),
		EventType:  strings.TrimSpace(e.Action),
		Action:     strings.TrimSpace(e.Action),
		Timestamp:  ts,
		ActorEmail: strings.TrimSpace(e.User),
		IPAddress:  strings.TrimSpace(e.Address),
		Outcome:    outcome,
		RawData:    rawMap,
	}
}

func isAuditNotAvailable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "status 401") || strings.Contains(msg, "status 403")
}

var _ access.AccessAuditor = (*Rapid7AccessConnector)(nil)
