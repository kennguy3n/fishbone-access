package crowdstrike

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

// FetchAccessAuditLogs streams CrowdStrike user-login-history events
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint (two phases):
//
//  1. GET /user-management/queries/user-login-history/v1?offset={n}&limit=100
//     returns a slice of `resources` IDs to expand.
//  2. GET /user-management/entities/user-login-history/v1?ids={ids}
//     returns the full event payloads.
//
// The handler is called once per provider page in chronological order.
// CrowdStrike returns ErrAuditNotAvailable for tenants whose API key
// lacks the `usermgmt:read` scope (403).
func (c *CrowdStrikeAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.fetchToken(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]
	cursor := since
	base := c.baseURL(cfg)

	offset := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		queryURL := fmt.Sprintf("%s/user-management/queries/user-login-history/v1?offset=%d&limit=%d", base, offset, pageLimit)
		qb, err := c.authedDo(ctx, token, http.MethodGet, queryURL, nil, "")
		if err != nil {
			if strings.Contains(err.Error(), "status 403") {
				return access.ErrAuditNotAvailable
			}
			return err
		}
		var queryResp csQueryResp
		if err := json.Unmarshal(qb, &queryResp); err != nil {
			return fmt.Errorf("crowdstrike: decode user-login-history query: %w", err)
		}
		if len(queryResp.Resources) == 0 {
			return nil
		}
		idsQ := url.Values{}
		for _, id := range queryResp.Resources {
			idsQ.Add("ids", id)
		}
		entitiesURL := base + "/user-management/entities/user-login-history/v1?" + idsQ.Encode()
		eb, err := c.authedDo(ctx, token, http.MethodGet, entitiesURL, nil, "")
		if err != nil {
			return err
		}
		var entities csLoginHistoryResp
		if err := json.Unmarshal(eb, &entities); err != nil {
			return fmt.Errorf("crowdstrike: decode user-login-history entities: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(entities.Resources))
		batchMax := cursor
		for i := range entities.Resources {
			for j := range entities.Resources[i].UserLogins {
				entry := mapCrowdStrikeLogin(&entities.Resources[i], &entities.Resources[i].UserLogins[j])
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
		}
		if err := handler(batch, batchMax, access.DefaultAuditPartition); err != nil {
			return err
		}
		cursor = batchMax
		offset += len(queryResp.Resources)
		if offset >= queryResp.Meta.Pagination.Total || len(queryResp.Resources) < pageLimit {
			return nil
		}
	}
}

type csQueryResp struct {
	Resources []string `json:"resources"`
	Meta      struct {
		Pagination struct {
			Offset int `json:"offset"`
			Limit  int `json:"limit"`
			Total  int `json:"total"`
		} `json:"pagination"`
	} `json:"meta"`
	Errors []map[string]interface{} `json:"errors"`
}

type csLoginHistoryResp struct {
	Resources []csUserLoginHistory `json:"resources"`
}

type csUserLoginHistory struct {
	UUID       string        `json:"UUID"`
	UID        string        `json:"uid"`
	UserLogins []csUserLogin `json:"user_logins"`
}

type csUserLogin struct {
	UserUUID  string `json:"user_uuid"`
	LoginTime string `json:"login_time"`
	Success   bool   `json:"success"`
}

func mapCrowdStrikeLogin(parent *csUserLoginHistory, e *csUserLogin) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.LoginTime) == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, e.LoginTime)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, e.LoginTime)
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	outcome := "success"
	if !e.Success {
		outcome = "failure"
	}
	return &access.AuditLogEntry{
		EventID:         parent.UUID + "|" + e.LoginTime,
		EventType:       "user.login",
		Action:          "login",
		Timestamp:       ts,
		ActorExternalID: parent.UUID,
		ActorEmail:      parent.UID,
		Outcome:         outcome,
		RawData:         rawMap,
	}
}

var _ access.AccessAuditor = (*CrowdStrikeAccessConnector)(nil)
