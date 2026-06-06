package salesloft

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
	salesloftAuditPageSize = 100
	salesloftAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Salesloft activity events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v2/activities?per_page=100&page=N&updated_at[gt]={iso}
//
// Activity access requires team-admin scope on the OAuth token; lower
// scopes surface 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *SalesloftAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/v2/activities"

	var collected []salesloftActivity
	for page := 1; page <= salesloftAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", salesloftAuditPageSize))
		if !since.IsZero() {
			q.Set("updated_at[gt]", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("salesloft: activities: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("salesloft: activities: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope salesloftActivityPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("salesloft: decode activities: %w", err)
		}
		collected = append(collected, envelope.Data...)
		if envelope.Metadata.Paging.NextPage == 0 || len(envelope.Data) < salesloftAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapSalesloftActivity(&collected[i])
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

type salesloftActivity struct {
	ID        int64  `json:"id"`
	Type      string `json:"type"`
	Action    string `json:"action"`
	UpdatedAt string `json:"updated_at"`
	CreatedAt string `json:"created_at"`
	User      struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
	Person struct {
		ID int64 `json:"id"`
	} `json:"person"`
	Subject string `json:"subject"`
}

type salesloftActivityPage struct {
	Data     []salesloftActivity `json:"data"`
	Metadata salesloftMetadata   `json:"metadata"`
}

func mapSalesloftActivity(a *salesloftActivity) *access.AuditLogEntry {
	if a == nil || a.ID == 0 {
		return nil
	}
	tsRaw := a.UpdatedAt
	if strings.TrimSpace(tsRaw) == "" {
		tsRaw = a.CreatedAt
	}
	ts := parseSalesloftTime(tsRaw)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(a)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(a.Action)
	if action == "" {
		action = strings.TrimSpace(a.Type)
	}
	return &access.AuditLogEntry{
		EventID:          fmt.Sprintf("%d", a.ID),
		EventType:        strings.TrimSpace(a.Type),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  fmt.Sprintf("%d", a.User.ID),
		ActorEmail:       strings.TrimSpace(a.User.Email),
		TargetExternalID: fmt.Sprintf("%d", a.Person.ID),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseSalesloftTime(s string) time.Time {
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

var _ access.AccessAuditor = (*SalesloftAccessConnector)(nil)
