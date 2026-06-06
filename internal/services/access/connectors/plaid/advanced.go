package plaid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// advanced-capability mapping for Plaid:
//
//   - ProvisionAccess  -> POST /team/update   {action:"assign",  user_id, role_id}
//   - RevokeAccess     -> POST /team/update   {action:"remove",  user_id, role_id}
//   - ListEntitlements -> POST /team/list     {user_id} -> roles[]
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Plaid team member id
//   - grant.ResourceExternalID -> Plaid role id
//
// client_id + secret JSON body auth (no bearer).

func plaidValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("plaid: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("plaid: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *PlaidAccessConnector) doJSONRaw(ctx context.Context, fullURL string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("plaid: post: %w", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, out, nil
}

func (c *PlaidAccessConnector) teamUpdate(ctx context.Context, secrets Secrets, cfg Config, action, userID, roleID string) (int, []byte, error) {
	payload := map[string]string{
		"client_id": strings.TrimSpace(secrets.ClientID),
		"secret":    strings.TrimSpace(secrets.Secret),
		"action":    action,
		"user_id":   userID,
		"role_id":   roleID,
	}
	body, _ := json.Marshal(payload)
	return c.doJSONRaw(ctx, c.baseURL(cfg)+"/team/update", body)
}

func (c *PlaidAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := plaidValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	status, respBody, err := c.teamUpdate(ctx, secrets, cfg, "assign",
		strings.TrimSpace(grant.UserExternalID),
		strings.TrimSpace(grant.ResourceExternalID))
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentProvisionStatus(status, respBody):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("plaid: provision transient status %d: %s", status, string(respBody))
	default:
		return fmt.Errorf("plaid: provision status %d: %s", status, string(respBody))
	}
}

func (c *PlaidAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := plaidValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	status, respBody, err := c.teamUpdate(ctx, secrets, cfg, "remove",
		strings.TrimSpace(grant.UserExternalID),
		strings.TrimSpace(grant.ResourceExternalID))
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentRevokeStatus(status, respBody):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("plaid: revoke transient status %d: %s", status, string(respBody))
	default:
		return fmt.Errorf("plaid: revoke status %d: %s", status, string(respBody))
	}
}

func (c *PlaidAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("plaid: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{
		"client_id": strings.TrimSpace(secrets.ClientID),
		"secret":    strings.TrimSpace(secrets.Secret),
		"user_id":   user,
	})
	status, respBody, err := c.doJSONRaw(ctx, c.baseURL(cfg)+"/team/list", body)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("plaid: list roles status %d: %s", status, string(respBody))
	}
	var envelope struct {
		Roles []struct {
			ID   interface{} `json:"id"`
			Name string      `json:"name"`
		} `json:"roles"`
	}
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return nil, fmt.Errorf("plaid: decode roles: %w", err)
	}
	out := make([]access.Entitlement, 0, len(envelope.Roles))
	for _, r := range envelope.Roles {
		id := strings.TrimSpace(fmt.Sprintf("%v", r.ID))
		if id == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: id,
			Role:               strings.TrimSpace(r.Name),
			Source:             "direct",
		})
	}
	return out, nil
}
