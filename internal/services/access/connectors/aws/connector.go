// Package aws implements the access.AccessConnector contract for AWS IAM.
//
// The IAM API is a query-style service: every operation is a POST to
// https://iam.amazonaws.com/ with Action=… in the form body. We use a
// minimal, hand-rolled SigV4 signer (sigv4.go) so we don't pull in the
// full aws-sdk-go-v2 module just for three APIs.
package aws

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName = "aws"
	// IAM is a global service that lives in us-east-1.
	defaultBaseURL = "https://iam.amazonaws.com/"
	defaultRegion  = "us-east-1"
	iamAPIVersion  = "2010-05-08"
)

// ErrNotImplemented is retained for any future capability that is not yet
// implemented; ProvisionAccess / RevokeAccess / ListEntitlements no longer
// return it now that the advanced capabilities are implemented.
var ErrNotImplemented = fmt.Errorf("aws: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Region    string `json:"aws_region"`
	AccountID string `json:"aws_account_id"`

	// SSOSAMLMetadataURL is the AWS IAM Identity Center SAML metadata
	// document URL pasted from the Identity Center console. When set
	// the connector advertises SAML federation metadata via
	// GetSSOMetadata so the access platform can broker AWS SSO via
	// iam-core.
	SSOSAMLMetadataURL string `json:"sso_saml_metadata_url,omitempty"`
	// SSOSAMLEntityID is the SAML entity ID configured for the
	// Identity Center instance (often the start URL). Optional —
	// when empty the metadata URL is used.
	SSOSAMLEntityID string `json:"sso_saml_entity_id,omitempty"`
	// SSOLoginURL is the AWS SSO sign-in URL (e.g.
	// https://d-1234567890.awsapps.com/start). Optional.
	SSOLoginURL string `json:"sso_login_url,omitempty"`
}

type Secrets struct {
	AccessKeyID     string `json:"aws_access_key_id"`
	SecretAccessKey string `json:"aws_secret_access_key"`
}

type AWSAccessConnector struct {
	httpClient   func() httpDoer
	urlOverride  string
	timeOverride func() time.Time
}

func New() *AWSAccessConnector { return &AWSAccessConnector{} }
func init()                    { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("aws: config is nil")
	}
	var cfg Config
	if v, ok := raw["aws_region"].(string); ok {
		cfg.Region = v
	}
	if v, ok := raw["aws_account_id"].(string); ok {
		cfg.AccountID = v
	}
	if v, ok := raw["sso_saml_metadata_url"].(string); ok {
		cfg.SSOSAMLMetadataURL = v
	}
	if v, ok := raw["sso_saml_entity_id"].(string); ok {
		cfg.SSOSAMLEntityID = v
	}
	if v, ok := raw["sso_login_url"].(string); ok {
		cfg.SSOLoginURL = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("aws: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["aws_access_key_id"].(string); ok {
		s.AccessKeyID = v
	}
	if v, ok := raw["aws_secret_access_key"].(string); ok {
		s.SecretAccessKey = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Region) == "" {
		return errors.New("aws: aws_region is required")
	}
	if !looksLikeAWSRegion(c.Region) {
		return errors.New("aws: aws_region does not look like a valid AWS region (expected e.g. us-east-1)")
	}
	if strings.TrimSpace(c.AccountID) != "" && len(c.AccountID) != 12 {
		return errors.New("aws: aws_account_id must be a 12-digit account ID when set")
	}
	return nil
}

func looksLikeAWSRegion(region string) bool {
	parts := strings.Split(region, "-")
	if len(parts) < 3 {
		return false
	}
	// Reject obviously bogus values; the actual list of regions changes
	// over time, so we only enforce a syntactic shape: a 2–6 letter
	// lowercase geo-prefix, then at least two more dash-separated segments.
	prefix := parts[0]
	if len(prefix) < 2 || len(prefix) > 6 {
		return false
	}
	for _, ch := range prefix {
		if ch < 'a' || ch > 'z' {
			return false
		}
	}
	return true
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessKeyID) == "" {
		return errors.New("aws: aws_access_key_id is required")
	}
	if strings.TrimSpace(s.SecretAccessKey) == "" {
		return errors.New("aws: aws_secret_access_key is required")
	}
	return nil
}

func (c *AWSAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *AWSAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/") + "/"
	}
	return defaultBaseURL
}

func (c *AWSAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *AWSAccessConnector) now() time.Time {
	if c.timeOverride != nil {
		return c.timeOverride()
	}
	return time.Now()
}

func (c *AWSAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *AWSAccessConnector) callIAM(ctx context.Context, cfg Config, secrets Secrets, params url.Values) ([]byte, error) {
	if params.Get("Version") == "" {
		params.Set("Version", iamAPIVersion)
	}
	body := params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL(), strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Accept", "application/xml")
	if err := signRequestSigV4(req, secrets.AccessKeyID, secrets.SecretAccessKey, defaultRegion, "iam", c.now()); err != nil {
		return nil, fmt.Errorf("aws: sign: %w", err)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("aws: %s: %w", params.Get("Action"), err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("aws: %s: status %d: %s", params.Get("Action"), resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

func (c *AWSAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	params := url.Values{}
	params.Set("Action", "GetAccountSummary")
	if _, err := c.callIAM(ctx, cfg, secrets, params); err != nil {
		return fmt.Errorf("aws: connect probe: %w", err)
	}
	return nil
}

func (c *AWSAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type getAccountSummaryResult struct {
	XMLName                 xml.Name `xml:"GetAccountSummaryResponse"`
	GetAccountSummaryResult struct {
		SummaryMap struct {
			Entries []struct {
				Key   string `xml:"key"`
				Value int    `xml:"value"`
			} `xml:"entry"`
		} `xml:"SummaryMap"`
	} `xml:"GetAccountSummaryResult"`
}

func (c *AWSAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	params := url.Values{}
	params.Set("Action", "GetAccountSummary")
	body, err := c.callIAM(ctx, cfg, secrets, params)
	if err != nil {
		return 0, err
	}
	var result getAccountSummaryResult
	if err := xml.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("aws: decode GetAccountSummary: %w", err)
	}
	for _, e := range result.GetAccountSummaryResult.SummaryMap.Entries {
		if e.Key == "Users" {
			return e.Value, nil
		}
	}
	return 0, nil
}

type listUsersResponse struct {
	XMLName         xml.Name `xml:"ListUsersResponse"`
	ListUsersResult struct {
		IsTruncated bool   `xml:"IsTruncated"`
		Marker      string `xml:"Marker"`
		Users       []struct {
			UserName   string `xml:"UserName"`
			UserID     string `xml:"UserId"`
			Arn        string `xml:"Arn"`
			Path       string `xml:"Path"`
			CreateDate string `xml:"CreateDate"`
		} `xml:"Users>member"`
	} `xml:"ListUsersResult"`
}

func (c *AWSAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	marker := checkpoint
	for {
		params := url.Values{}
		params.Set("Action", "ListUsers")
		params.Set("MaxItems", "100")
		if marker != "" {
			params.Set("Marker", marker)
		}
		body, err := c.callIAM(ctx, cfg, secrets, params)
		if err != nil {
			return err
		}
		var resp listUsersResponse
		if err := xml.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("aws: decode ListUsers: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.ListUsersResult.Users))
		for _, u := range resp.ListUsersResult.Users {
			identities = append(identities, &access.Identity{
				ExternalID:  u.UserName,
				Type:        access.IdentityTypeUser,
				DisplayName: u.UserName,
				Email:       "",
				Status:      "active",
				RawData:     map[string]interface{}{"arn": u.Arn, "path": u.Path, "create_date": u.CreateDate, "user_id": u.UserID, "user_name": u.UserName},
			})
		}
		next := ""
		if resp.ListUsersResult.IsTruncated {
			next = resp.ListUsersResult.Marker
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		marker = next
	}
}

// ProvisionAccess attaches an IAM managed policy to the user via
// iam:AttachUserPolicy. The grant's UserExternalID is treated as the IAM
// UserName and ResourceExternalID as the policy ARN. EntityAlreadyExists
// (the IAM error returned when the policy is already attached) is treated
// as idempotent success.
func (c *AWSAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if err := validateGrantPair(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	params := url.Values{}
	params.Set("Action", "AttachUserPolicy")
	params.Set("UserName", grant.UserExternalID)
	params.Set("PolicyArn", grant.ResourceExternalID)
	if _, err := c.callIAM(ctx, cfg, secrets, params); err != nil {
		if isAWSErrorCode(err, "EntityAlreadyExists") {
			return nil
		}
		return err
	}
	return nil
}

// RevokeAccess detaches the IAM managed policy via iam:DetachUserPolicy.
// NoSuchEntity (returned when the policy is not attached or the user does
// not exist) is treated as idempotent success.
func (c *AWSAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if err := validateGrantPair(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	params := url.Values{}
	params.Set("Action", "DetachUserPolicy")
	params.Set("UserName", grant.UserExternalID)
	params.Set("PolicyArn", grant.ResourceExternalID)
	if _, err := c.callIAM(ctx, cfg, secrets, params); err != nil {
		if isAWSErrorCode(err, "NoSuchEntity") {
			return nil
		}
		return err
	}
	return nil
}

// ListEntitlements pages through iam:ListAttachedUserPolicies and maps each
// attached managed policy to Entitlement{ResourceExternalID: PolicyArn,
// Role: PolicyName, Source: "direct"}.
func (c *AWSAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("aws: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	var out []access.Entitlement
	marker := ""
	for {
		params := url.Values{}
		params.Set("Action", "ListAttachedUserPolicies")
		params.Set("UserName", userExternalID)
		params.Set("MaxItems", "100")
		if marker != "" {
			params.Set("Marker", marker)
		}
		body, err := c.callIAM(ctx, cfg, secrets, params)
		if err != nil {
			return nil, err
		}
		var resp listAttachedUserPoliciesResponse
		if err := xml.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("aws: decode ListAttachedUserPolicies: %w", err)
		}
		for _, p := range resp.ListAttachedUserPoliciesResult.AttachedPolicies {
			out = append(out, access.Entitlement{
				ResourceExternalID: p.PolicyArn,
				Role:               p.PolicyName,
				Source:             "direct",
			})
		}
		if !resp.ListAttachedUserPoliciesResult.IsTruncated {
			return out, nil
		}
		marker = resp.ListAttachedUserPoliciesResult.Marker
		if marker == "" {
			return out, nil
		}
	}
}

func validateGrantPair(grant access.AccessGrant) error {
	if grant.UserExternalID == "" {
		return errors.New("aws: grant.UserExternalID is required")
	}
	if grant.ResourceExternalID == "" {
		return errors.New("aws: grant.ResourceExternalID is required")
	}
	return nil
}

// isAWSErrorCode returns true when the IAM error returned by callIAM
// matches the given AWS error <Code>. callIAM stringifies the body verbatim
// in the error so we can substring-match without re-parsing the XML.
func isAWSErrorCode(err error, code string) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "<Code>"+code+"</Code>")
}

type listAttachedUserPoliciesResponse struct {
	XMLName                        xml.Name `xml:"ListAttachedUserPoliciesResponse"`
	ListAttachedUserPoliciesResult struct {
		IsTruncated      bool   `xml:"IsTruncated"`
		Marker           string `xml:"Marker"`
		AttachedPolicies []struct {
			PolicyName string `xml:"PolicyName"`
			PolicyArn  string `xml:"PolicyArn"`
		} `xml:"AttachedPolicies>member"`
	} `xml:"ListAttachedUserPoliciesResult"`
}

// GetSSOMetadata returns SAML federation metadata for AWS IAM Identity
// Center when the operator has configured sso_saml_metadata_url. AWS
// IAM Identity Center publishes a per-instance SAML metadata document;
// the operator pastes its URL into the connector config and the
// access platform brokers federation through iam-core via
// SSOFederationService.ConfigureBroker.
//
// When sso_saml_metadata_url is empty the method returns (nil, nil) —
// the connector still works for identity sync / provisioning but
// SSO federation is opt-in.
func (c *AWSAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	md := strings.TrimSpace(cfg.SSOSAMLMetadataURL)
	if md == "" {
		return nil, nil
	}
	entity := strings.TrimSpace(cfg.SSOSAMLEntityID)
	if entity == "" {
		entity = md
	}
	return &access.SSOMetadata{
		Protocol:    "saml",
		MetadataURL: md,
		EntityID:    entity,
		SSOLoginURL: strings.TrimSpace(cfg.SSOLoginURL),
	}, nil
}

type listAccessKeysResponse struct {
	XMLName              xml.Name `xml:"ListAccessKeysResponse"`
	ListAccessKeysResult struct {
		IsTruncated       bool   `xml:"IsTruncated"`
		Marker            string `xml:"Marker"`
		AccessKeyMetadata []struct {
			AccessKeyID string `xml:"AccessKeyId"`
			Status      string `xml:"Status"`
			CreateDate  string `xml:"CreateDate"`
			UserName    string `xml:"UserName"`
		} `xml:"AccessKeyMetadata>member"`
	} `xml:"ListAccessKeysResult"`
}

// GetCredentialsMetadata returns the access-key age + status by calling
// iam:ListAccessKeys for the caller's identity. The connector never
// echoes the secret access key.
func (c *AWSAccessConnector) GetCredentialsMetadata(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"provider":      ProviderName,
		"region":        cfg.Region,
		"account_id":    cfg.AccountID,
		"access_key_id": secrets.AccessKeyID,
	}
	params := url.Values{}
	params.Set("Action", "ListAccessKeys")
	body, err := c.callIAM(ctx, cfg, secrets, params)
	if err != nil {
		return out, nil
	}
	var resp listAccessKeysResponse
	if err := xml.Unmarshal(body, &resp); err != nil {
		return out, nil
	}
	for _, k := range resp.ListAccessKeysResult.AccessKeyMetadata {
		if k.AccessKeyID == secrets.AccessKeyID {
			out["access_key_status"] = k.Status
			out["access_key_created_at"] = k.CreateDate
			out["iam_user_name"] = k.UserName
			break
		}
	}
	return out, nil
}

var _ access.AccessConnector = (*AWSAccessConnector)(nil)
