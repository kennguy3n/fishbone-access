package cloudsigma

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// advanced-capability mapping for cloudsigma:
//
//   - ProvisionAccess  -> POST   /api/2.0/acl/
//   - RevokeAccess     -> DELETE /api/2.0/acl/{uuid}/
//   - ListEntitlements -> GET    /api/2.0/acl/?owner={userId}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> CloudSigma owner uuid
//   - grant.ResourceExternalID -> ACL uuid (or new ACL name on provision)
//
// HTTP Basic auth (email + password) per the existing connector.
// Idempotent on (UserExternalID, ResourceExternalID).

func csValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("cloudsigma: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("cloudsigma: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *CloudSigmaAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("cloudsigma: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *CloudSigmaAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("Authorization", basicAuthHeader(secrets.Email, secrets.Password))
	return req, nil
}

func (c *CloudSigmaAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := csValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"objects": []map[string]interface{}{{
			"name":  strings.TrimSpace(grant.ResourceExternalID),
			"owner": map[string]string{"uuid": strings.TrimSpace(grant.UserExternalID)},
		}},
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.baseURL(cfg)+"/api/2.0/acl/", payload)
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
		return fmt.Errorf("cloudsigma: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("cloudsigma: provision status %d: %s", status, string(body))
	}
}

func (c *CloudSigmaAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := csValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := c.baseURL(cfg) + "/api/2.0/acl/" + url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)) + "/"
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
		return fmt.Errorf("cloudsigma: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("cloudsigma: revoke status %d: %s", status, string(body))
	}
}

func (c *CloudSigmaAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("cloudsigma: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("owner", user)
	endpoint := c.baseURL(cfg) + "/api/2.0/acl/?" + q.Encode()
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
		return nil, fmt.Errorf("cloudsigma: list entitlements status %d: %s", status, string(body))
	}
	var envelope struct {
		Objects []struct {
			UUID  string `json:"uuid"`
			Name  string `json:"name"`
			Owner struct {
				UUID string `json:"uuid"`
			} `json:"owner"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("cloudsigma: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0, len(envelope.Objects))
	for _, o := range envelope.Objects {
		if strings.TrimSpace(o.Owner.UUID) != user {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: strings.TrimSpace(o.UUID),
			Role:               strings.TrimSpace(o.Name),
			Source:             "direct",
		})
	}
	return out, nil
}
