package teamwork

import (
	"bytes"
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

// advanced-capability mapping for Teamwork:
//
//   - ProvisionAccess  -> PUT    /projects/api/v3/projects/{project_id}/people.json
//                         body { add: [user_id] }
//   - RevokeAccess     -> PUT    /projects/api/v3/projects/{project_id}/people.json
//                         body { remove: [user_id] }
//   - ListEntitlements -> GET    /projects/api/v3/projects/{project_id}/people.json
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Teamwork person id
//   - grant.ResourceExternalID -> Teamwork project id
//
// HTTP Basic auth via TeamworkAccessConnector.newRequest.

func teamworkValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("teamwork: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("teamwork: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *TeamworkAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	teamworkSetBasicAuth(req, secrets)
	return req, nil
}

func (c *TeamworkAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("teamwork: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func teamworkSetBasicAuth(req *http.Request, secrets Secrets) {
	req.SetBasicAuth(strings.TrimSpace(secrets.APIKey), "xxx")
}

func (c *TeamworkAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := teamworkValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"add": []string{strings.TrimSpace(grant.UserExternalID)},
	})
	endpoint := fmt.Sprintf("%s/projects/api/v3/projects/%s/people.json",
		c.baseURL(cfg),
		url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPut, endpoint, payload)
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
		return fmt.Errorf("teamwork: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("teamwork: provision status %d: %s", status, string(body))
	}
}

func (c *TeamworkAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := teamworkValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"remove": []string{strings.TrimSpace(grant.UserExternalID)},
	})
	endpoint := fmt.Sprintf("%s/projects/api/v3/projects/%s/people.json",
		c.baseURL(cfg),
		url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPut, endpoint, payload)
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
		return fmt.Errorf("teamwork: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("teamwork: revoke status %d: %s", status, string(body))
	}
}

func (c *TeamworkAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("teamwork: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	projectID := teamworkOptionalProjectID(configRaw)
	if projectID == "" {
		return nil, errors.New("teamwork: project_id is required in config for ListEntitlements")
	}
	endpoint := fmt.Sprintf("%s/projects/api/v3/projects/%s/people.json",
		c.baseURL(cfg), url.PathEscape(projectID))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, endpoint)
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
		return nil, fmt.Errorf("teamwork: list people status %d: %s", status, string(body))
	}
	var envelope struct {
		People []struct {
			ID        json.Number `json:"id"`
			EmailAddr string      `json:"email-address"`
			Email     string      `json:"email"`
			Admin     bool        `json:"administrator"`
		} `json:"people"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("teamwork: decode people: %w", err)
	}
	for i := range envelope.People {
		p := envelope.People[i]
		idStr := p.ID.String()
		if strings.EqualFold(strings.TrimSpace(idStr), user) ||
			strings.EqualFold(strings.TrimSpace(p.EmailAddr), user) ||
			strings.EqualFold(strings.TrimSpace(p.Email), user) {
			role := "member"
			if p.Admin {
				role = "admin"
			}
			return []access.Entitlement{{
				ResourceExternalID: projectID,
				Role:               role,
				Source:             "direct",
			}}, nil
		}
	}
	return nil, nil
}

func teamworkOptionalProjectID(raw map[string]interface{}) string {
	if raw == nil {
		return ""
	}
	if v, ok := raw["project_id"].(string); ok {
		return strings.TrimSpace(v)
	}
	if v, ok := raw["project_id"].(float64); ok {
		return fmt.Sprintf("%d", int64(v))
	}
	return ""
}
