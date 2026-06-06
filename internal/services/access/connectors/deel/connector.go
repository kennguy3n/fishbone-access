// Package deel implements the access.AccessConnector contract for the
// Deel /rest/v2/contracts API.
//
// Deel does not have a single "list workers" endpoint; the canonical
// way to enumerate people who have ongoing engagements is to walk the
// contracts list and project worker fields out of each contract.
package deel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName = "deel"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("deel: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	Token string `json:"token"`
}

type DeelAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *DeelAccessConnector { return &DeelAccessConnector{} }
func init()                     { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("deel: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("deel: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (Config) validate() error { return nil }

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("deel: token is required")
	}
	return nil
}

func (c *DeelAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return err
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return err
	}
	return s.validate()
}

func (c *DeelAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.letsdeel.com"
}

func (c *DeelAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *DeelAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *DeelAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("deel: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("deel: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *DeelAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return Config{}, Secrets{}, err
	}
	if err := cfg.validate(); err != nil {
		return Config{}, Secrets{}, err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return Config{}, Secrets{}, err
	}
	if err := s.validate(); err != nil {
		return Config{}, Secrets{}, err
	}
	return cfg, s, nil
}

func (c *DeelAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := fmt.Sprintf("%s/rest/v2/contracts?page=1&page_size=1", c.baseURL())
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("deel: connect probe: %w", err)
	}
	return nil
}

func (c *DeelAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type deelContract struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Worker struct {
		ID        string `json:"id"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
	} `json:"worker"`
}

type deelListResponse struct {
	Data []deelContract `json:"data"`
	Page struct {
		Number int `json:"page"`
		Size   int `json:"page_size"`
		Total  int `json:"total_pages"`
	} `json:"page"`
	Total int `json:"total"`
}

func (c *DeelAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *DeelAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	page := 1
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &page)
		if page < 1 {
			page = 1
		}
	}
	base := c.baseURL()
	seen := make(map[string]struct{})
	for {
		path := fmt.Sprintf("%s/rest/v2/contracts?page=%d&page_size=%d", base, page, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp deelListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("deel: decode contracts: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Data))
		for _, ct := range resp.Data {
			extID := ct.Worker.ID
			if extID == "" {
				continue
			}
			if _, dup := seen[extID]; dup {
				continue
			}
			seen[extID] = struct{}{}
			display := strings.TrimSpace(ct.Worker.FirstName + " " + ct.Worker.LastName)
			if display == "" {
				display = ct.Worker.Email
			}
			status := "active"
			if ct.Status != "" {
				status = strings.ToLower(ct.Status)
			}
			identities = append(identities, &access.Identity{
				ExternalID:  extID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       ct.Worker.Email,
				Status:      status,
				RawData:     map[string]interface{}{"contract_id": ct.ID},
			})
		}
		next := ""
		hasMore := false
		if resp.Page.Total > 0 {
			hasMore = page < resp.Page.Total
		} else if len(resp.Data) == pageSize {
			hasMore = true
		}
		if hasMore && len(resp.Data) > 0 {
			next = fmt.Sprintf("%d", page+1)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		page++
	}
}

// Deel SSO federation. When `sso_metadata_url` is blank the helper returns
// (nil, nil) and the caller gracefully downgrades.
func (c *DeelAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *DeelAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "bearer",
		"token_short": shortToken(secrets.Token),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*DeelAccessConnector)(nil)
