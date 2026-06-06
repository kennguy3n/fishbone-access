// Package sage_intacct implements the access.AccessConnector contract for the
// Sage Intacct XML API users endpoint.
package sage_intacct

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName = "sage_intacct"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("sage_intacct: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	CompanyID string `json:"company_id"`
}

type Secrets struct {
	SenderID       string `json:"sender_id"`
	SenderPassword string `json:"sender_password"`
	UserID         string `json:"user_id"`
	UserPassword   string `json:"user_password"`
}

type SageIntacctAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *SageIntacctAccessConnector { return &SageIntacctAccessConnector{} }
func init()                            { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("sage_intacct: config is nil")
	}
	var cfg Config
	if v, ok := raw["company_id"].(string); ok {
		cfg.CompanyID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("sage_intacct: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["sender_id"].(string); ok {
		s.SenderID = v
	}
	if v, ok := raw["sender_password"].(string); ok {
		s.SenderPassword = v
	}
	if v, ok := raw["user_id"].(string); ok {
		s.UserID = v
	}
	if v, ok := raw["user_password"].(string); ok {
		s.UserPassword = v
	}
	return s, nil
}

func (c Config) validate() error {
	id := strings.TrimSpace(c.CompanyID)
	if id == "" {
		return errors.New("sage_intacct: company_id is required")
	}
	for _, r := range id {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '-' || r == '_') {
			return errors.New("sage_intacct: company_id must be alphanumeric")
		}
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.SenderID) == "" {
		return errors.New("sage_intacct: sender_id is required")
	}
	if strings.TrimSpace(s.SenderPassword) == "" {
		return errors.New("sage_intacct: sender_password is required")
	}
	if strings.TrimSpace(s.UserID) == "" {
		return errors.New("sage_intacct: user_id is required")
	}
	if strings.TrimSpace(s.UserPassword) == "" {
		return errors.New("sage_intacct: user_password is required")
	}
	return nil
}

func (c *SageIntacctAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *SageIntacctAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.intacct.com"
}

func (c *SageIntacctAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *SageIntacctAccessConnector) buildXML(cfg Config, secrets Secrets, offset int) string {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString(`<request><control><senderid>`)
	_ = xml.EscapeText(&sb, []byte(strings.TrimSpace(secrets.SenderID)))
	sb.WriteString(`</senderid><password>`)
	_ = xml.EscapeText(&sb, []byte(strings.TrimSpace(secrets.SenderPassword)))
	sb.WriteString(`</password></control><operation><authentication><login><userid>`)
	_ = xml.EscapeText(&sb, []byte(strings.TrimSpace(secrets.UserID)))
	sb.WriteString(`</userid><companyid>`)
	_ = xml.EscapeText(&sb, []byte(strings.TrimSpace(cfg.CompanyID)))
	sb.WriteString(`</companyid><password>`)
	_ = xml.EscapeText(&sb, []byte(strings.TrimSpace(secrets.UserPassword)))
	sb.WriteString(`</password></login></authentication><content><function controlid="users"><readByQuery><object>USERINFO</object><query></query><pagesize>`)
	fmt.Fprintf(&sb, "%d", pageSize)
	sb.WriteString(`</pagesize><offset>`)
	fmt.Fprintf(&sb, "%d", offset)
	sb.WriteString(`</offset></readByQuery></function></content></operation></request>`)
	return sb.String()
}

func (c *SageIntacctAccessConnector) doXML(ctx context.Context, body string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL()+"/ia/xml/xmlgw.phtml", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Accept", "application/xml")
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("sage_intacct: post: %w", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("sage_intacct: status %d: %s", resp.StatusCode, string(out))
	}
	return out, nil
}

func (c *SageIntacctAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *SageIntacctAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if _, err := c.doXML(ctx, c.buildXML(cfg, secrets, 0)); err != nil {
		return fmt.Errorf("sage_intacct: connect probe: %w", err)
	}
	return nil
}

func (c *SageIntacctAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type sageUser struct {
	UserID    string `xml:"USERID"`
	FirstName string `xml:"FIRSTNAME"`
	LastName  string `xml:"LASTNAME"`
	Email     string `xml:"CONTACT_EMAIL1"`
	Status    string `xml:"STATUS"`
}

type sageData struct {
	Users []sageUser `xml:"USERINFO"`
}

type sageResult struct {
	Status string   `xml:"status"`
	Data   sageData `xml:"data"`
}

type sageOperation struct {
	Result sageResult `xml:"result"`
}

type sageResponse struct {
	XMLName   xml.Name      `xml:"response"`
	Operation sageOperation `xml:"operation"`
}

func (c *SageIntacctAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *SageIntacctAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offset := 0
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &offset)
		if offset < 0 {
			offset = 0
		}
	}
	for {
		out, err := c.doXML(ctx, c.buildXML(cfg, secrets, offset))
		if err != nil {
			return err
		}
		var resp sageResponse
		if err := xml.Unmarshal(out, &resp); err != nil {
			return fmt.Errorf("sage_intacct: decode users: %w", err)
		}
		users := resp.Operation.Result.Data.Users
		identities := make([]*access.Identity, 0, len(users))
		for _, u := range users {
			display := strings.TrimSpace(strings.TrimSpace(u.FirstName) + " " + strings.TrimSpace(u.LastName))
			if display == "" {
				display = strings.TrimSpace(u.UserID)
			}
			status := "active"
			if u.Status != "" && !strings.EqualFold(strings.TrimSpace(u.Status), "active") {
				status = "inactive"
			}
			extID := strings.TrimSpace(u.UserID)
			if extID == "" {
				extID = u.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  extID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      status,
			})
		}
		next := ""
		if len(users) == pageSize {
			next = fmt.Sprintf("%d", offset+pageSize)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset += pageSize
	}
}

// GetSSOMetadata returns the operator-supplied SAML metadata URL if
// configured. Sage Intacct federates SSO via SAML 2.0 with metadata
// hosted by the customer's IdP; when `sso_metadata_url` is blank the
// helper returns nil so callers gracefully downgrade.
func (c *SageIntacctAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *SageIntacctAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":     ProviderName,
		"auth_type":    "session_xml",
		"sender_short": shortToken(secrets.SenderID),
		"user_short":   shortToken(secrets.UserID),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*SageIntacctAccessConnector)(nil)
