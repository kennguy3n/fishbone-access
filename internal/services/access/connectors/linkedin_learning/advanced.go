package linkedin_learning

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

// advanced-capability mapping for LinkedIn Learning Enterprise:
//
//   - ProvisionAccess  -> POST   /v2/learningEnterpriseUsers
//   - RevokeAccess     -> DELETE /v2/learningEnterpriseUsers/{id}
//   - ListEntitlements -> GET    /v2/learningEnterpriseUsers/{id}
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func linkedinLearningValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("linkedin_learning: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("linkedin_learning: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *LinkedInLearningAccessConnector) usersURL() string {
	return c.baseURL() + "/v2/learningEnterpriseUsers"
}

func (c *LinkedInLearningAccessConnector) userURL(id string) string {
	return c.baseURL() + "/v2/learningEnterpriseUsers/" + url.PathEscape(strings.TrimSpace(id))
}

func (c *LinkedInLearningAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *LinkedInLearningAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("linkedin_learning: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *LinkedInLearningAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := linkedinLearningValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"email":       strings.TrimSpace(grant.UserExternalID),
		"licenseTier": strings.TrimSpace(grant.ResourceExternalID),
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.usersURL(), payload)
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
		return fmt.Errorf("linkedin_learning: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("linkedin_learning: provision status %d: %s", status, string(body))
	}
}

func (c *LinkedInLearningAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := linkedinLearningValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, c.userURL(grant.UserExternalID), nil)
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
		return fmt.Errorf("linkedin_learning: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("linkedin_learning: revoke status %d: %s", status, string(body))
	}
}

func (c *LinkedInLearningAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("linkedin_learning: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.userURL(user), nil)
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
		return nil, fmt.Errorf("linkedin_learning: list entitlements status %d: %s", status, string(body))
	}
	var resp struct {
		Email       string `json:"email"`
		ID          string `json:"id"`
		LicenseTier string `json:"licenseTier"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("linkedin_learning: decode entitlements: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(resp.Email), user) &&
		strings.TrimSpace(resp.ID) != user {
		return nil, nil
	}
	tier := strings.TrimSpace(resp.LicenseTier)
	if tier == "" {
		return []access.Entitlement{}, nil
	}
	return []access.Entitlement{{
		ResourceExternalID: tier,
		Role:               tier,
		Source:             "direct",
	}}, nil
}
