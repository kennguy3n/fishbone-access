package travis_ci

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

// advanced-capability mapping for Travis CI:
//
// Travis CI does not expose "groups" or "teams" via its public API;
// the user/resource relationship that operators actually manage is
// "repo enabled in Travis for the user". The mapping is therefore:
//
//   - ProvisionAccess  -> POST /repo/{repo_id}/activate
//   - RevokeAccess     -> POST /repo/{repo_id}/deactivate
//   - ListEntitlements -> GET  /user/{user_id}/repos?repository.active=true
//
// AccessGrant maps:
//   - grant.UserExternalID     -> {user_id}   (Travis numeric id)
//   - grant.ResourceExternalID -> {repo_id}   (Travis numeric repo id or slug)
//
// All mutations are idempotent: re-activating an already-active repo
// or deactivating an inactive repo is treated as success per
// docs/architecture.md §2.

func travisValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("travis_ci: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("travis_ci: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *TravisCIAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("Travis-API-Version", "3")
	req.Header.Set("Authorization", "token "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *TravisCIAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("travis_ci: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

// ProvisionAccess activates the repo identified by
// grant.ResourceExternalID. 409 / 422 / 200-with-"already-active" are
// treated as idempotent success.
func (c *TravisCIAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := travisValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	repo := url.PathEscape(strings.TrimSpace(grant.ResourceExternalID))
	full := fmt.Sprintf("%s/repo/%s/activate", c.baseURL(cfg), repo)
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPost, full, nil)
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
		return fmt.Errorf("travis_ci: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("travis_ci: provision status %d: %s", status, string(body))
	}
}

// RevokeAccess deactivates the repo. 404 / 422 / already-deactivated
// is treated as idempotent success per docs/architecture.md §2.
func (c *TravisCIAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := travisValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	repo := url.PathEscape(strings.TrimSpace(grant.ResourceExternalID))
	full := fmt.Sprintf("%s/repo/%s/deactivate", c.baseURL(cfg), repo)
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPost, full, nil)
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
		return fmt.Errorf("travis_ci: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("travis_ci: revoke status %d: %s", status, string(body))
	}
}

// ListEntitlements returns the active repos visible to userExternalID.
func (c *TravisCIAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("travis_ci: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	base := c.baseURL(cfg)
	escUser := url.PathEscape(user)
	out := make([]access.Entitlement, 0)
	// maxEntitlementPages bounds the loop defensively so a provider that never
	// signals completion cannot drive an unbounded fetch.
	const maxEntitlementPages = 1000
	for offset, page := 0, 0; page < maxEntitlementPages; page++ {
		full := fmt.Sprintf("%s/user/%s/repos?repository.active=true&limit=%d&offset=%d",
			base, escUser, pageSize, offset)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, full)
		if err != nil {
			return nil, err
		}
		status, body, err := c.doRaw(req)
		if err != nil {
			return nil, err
		}
		if status == http.StatusNotFound {
			return out, nil
		}
		if status < 200 || status >= 300 {
			return nil, fmt.Errorf("travis_ci: list entitlements status %d: %s", status, string(body))
		}
		var resp travisReposResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("travis_ci: decode repos: %w", err)
		}
		for _, r := range resp.Repositories {
			id := strings.TrimSpace(r.ID.String())
			if id == "" {
				continue
			}
			out = append(out, access.Entitlement{
				ResourceExternalID: id,
				Role:               r.Slug,
				Source:             "direct",
			})
		}
		if len(resp.Repositories) < pageSize || offset+pageSize >= resp.At.Count {
			return out, nil
		}
		offset += pageSize
	}
	return out, nil
}

type travisReposResponse struct {
	Repositories []travisRepo `json:"repositories"`
	At           struct {
		Limit  int `json:"limit"`
		Offset int `json:"offset"`
		Count  int `json:"count"`
	} `json:"@pagination"`
}

type travisRepo struct {
	ID     json.Number `json:"id"`
	Slug   string      `json:"slug"`
	Active bool        `json:"active"`
}
