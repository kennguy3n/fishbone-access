package salesforce

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// RevokeUserSessions implements access.SessionRevoker for
// Salesforce. The Tooling API exposes a SessionManagement endpoint
// (/services/data/v59.0/sobjects/AuthSession) which lists active
// sessions per user; the connector enumerates them by user ID and
// issues DELETE on each row, terminating the session and
// invalidating refresh tokens.
//
// userExternalID is the Salesforce Id (the SyncIdentities-emitted
// external_id). 200 / 204 from the DELETE means propagated; an
// empty result set or 404 means there were no sessions to revoke,
// both treated as success per the idempotent kill-switch contract.
// Any other status returns a non-nil err so the leaver flow logs
// it but continues.
func (c *SalesforceAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("salesforce: session revoke: userExternalID is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	base := c.instanceBase(cfg)
	queryURL := base + "/services/data/v59.0/query?q=" +
		"SELECT+Id+FROM+AuthSession+WHERE+UsersId='" + url.QueryEscape(escapeSOQLLiteral(userExternalID)) + "'+AND+SessionType='STANDARD'"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, queryURL)
	if err != nil {
		return err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("salesforce: session revoke list: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("salesforce: session revoke list status %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		Records []struct {
			ID string `json:"Id"`
		} `json:"records"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("salesforce: decode AuthSession list: %w", err)
	}
	for _, rec := range payload.Records {
		delReq, derr := c.newRequest(ctx, secrets, http.MethodDelete,
			base+"/services/data/v59.0/sobjects/AuthSession/"+rec.ID)
		if derr != nil {
			return derr
		}
		dresp, dErr := c.client().Do(delReq)
		if dErr != nil {
			return fmt.Errorf("salesforce: session revoke delete %s: %w", rec.ID, dErr)
		}
		_ = dresp.Body.Close()
		if dresp.StatusCode >= 200 && dresp.StatusCode < 300 {
			continue
		}
		if dresp.StatusCode == http.StatusNotFound {
			continue
		}
		return fmt.Errorf("salesforce: session revoke delete %s: status %d", rec.ID, dresp.StatusCode)
	}
	return nil
}
