package mailchimp

import (
	"context"
	// gosec G501 false positive: Mailchimp's REST API uses
	// the MD5 of the lowercased subscriber email as the user
	// identifier ("subscriber hash"). Protocol requirement,
	// not a cryptographic strength choice.
	"crypto/md5" // #nosec G501
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// advanced-capability mapping for mailchimp:
//
//   - ProvisionAccess  -> PUT    /3.0/lists/{list_id}/members/{subscriber_hash}
//                         with {email_address, status_if_new:"subscribed"}
//   - RevokeAccess     -> DELETE /3.0/lists/{list_id}/members/{subscriber_hash}
//   - ListEntitlements -> GET    /3.0/lists/{list_id}/members/{subscriber_hash}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> subscriber email
//   - grant.ResourceExternalID -> list id (overrides cfg.ListID when set)
//
// HTTP Basic auth "anystring:<api_key>" with datacenter routing per
// the existing connector. Idempotent on
// (UserExternalID, ResourceExternalID): PUT is idempotent by design,
// DELETE returns 404 on already-removed members.

func mailchimpValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("mailchimp: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("mailchimp: grant.ResourceExternalID is required")
	}
	return nil
}

func subscriberHash(email string) string {
	// gosec G401: MD5 is the documented Mailchimp subscriber
	// identifier scheme. Not a cryptographic-integrity use.
	sum := md5.Sum([]byte(strings.ToLower(strings.TrimSpace(email)))) // #nosec G401
	return hex.EncodeToString(sum[:])
}

func (c *MailchimpAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("mailchimp: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *MailchimpAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if len(body) > 0 {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	creds := "anystring:" + strings.TrimSpace(secrets.APIKey)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func mailchimpMemberURL(base, listID, hash string) string {
	return base + "/3.0/lists/" + url.PathEscape(strings.TrimSpace(listID)) + "/members/" + url.PathEscape(hash)
}

func (c *MailchimpAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := mailchimpValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	email := strings.TrimSpace(grant.UserExternalID)
	listID := strings.TrimSpace(grant.ResourceExternalID)
	payload, _ := json.Marshal(map[string]interface{}{
		"email_address": email,
		"status_if_new": "subscribed",
		"status":        "subscribed",
	})
	endpoint := mailchimpMemberURL(c.baseURL(secrets), listID, subscriberHash(email))
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPut, endpoint, payload)
	if err != nil {
		return err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentProvisionStatus(status, body):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("mailchimp: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("mailchimp: provision status %d: %s", status, string(body))
	}
}

func (c *MailchimpAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := mailchimpValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	email := strings.TrimSpace(grant.UserExternalID)
	listID := strings.TrimSpace(grant.ResourceExternalID)
	endpoint := mailchimpMemberURL(c.baseURL(secrets), listID, subscriberHash(email))
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentRevokeStatus(status, body):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("mailchimp: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("mailchimp: revoke status %d: %s", status, string(body))
	}
}

func (c *MailchimpAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	email := strings.TrimSpace(userExternalID)
	if email == "" {
		return nil, errors.New("mailchimp: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	listID := strings.TrimSpace(cfg.ListID)
	if listID == "" {
		return nil, errors.New("mailchimp: list_id is required for list entitlements")
	}
	endpoint := mailchimpMemberURL(c.baseURL(secrets), listID, subscriberHash(email))
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("mailchimp: list entitlements status %d: %s", status, string(body))
	}
	var member struct {
		Email  string `json:"email_address"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &member); err != nil {
		return nil, fmt.Errorf("mailchimp: decode entitlements: %w", err)
	}
	if strings.ToLower(strings.TrimSpace(member.Status)) != "subscribed" {
		return nil, nil
	}
	return []access.Entitlement{{
		ResourceExternalID: listID,
		Role:               "subscribed",
		Source:             "direct",
	}}, nil
}
