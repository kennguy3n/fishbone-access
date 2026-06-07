// Package monday implements the access.AccessConnector contract for the
// Monday.com GraphQL users API.
package monday

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/access/httputil"
)

// parseMondayID parses a Monday.com numeric ID (board_id, user_id) and
// returns its canonical decimal form. Monday IDs are 64-bit integers;
// rejecting non-numeric input prevents GraphQL injection when the value
// is interpolated into a mutation string (see ProvisionAccess /
// RevokeAccess below).
func parseMondayID(label, raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("monday: %s is required", label)
	}
	n, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil || n <= 0 {
		return "", fmt.Errorf("monday: %s must be a positive numeric id", label)
	}
	return strconv.FormatInt(n, 10), nil
}

const (
	ProviderName   = "monday"
	defaultBaseURL = "https://api.monday.com/v2"
	pageSize       = 200
)

var ErrNotImplemented = fmt.Errorf("monday: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	APIToken string `json:"api_token"`
}

type MondayAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *MondayAccessConnector { return &MondayAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(_ map[string]interface{}) (Config, error) { return Config{}, nil }

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("monday: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_token"].(string); ok {
		s.APIToken = v
	}
	return s, nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIToken) == "" {
		return errors.New("monday: api_token is required")
	}
	return nil
}

func (c *MondayAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
	if _, err := DecodeConfig(configRaw); err != nil {
		return err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return err
	}
	return s.validate()
}

func (c *MondayAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

// client returns the httpDoer used to talk to Monday's GraphQL
// endpoint. The test path goes through c.httpClient (an injected
// httptest.Server hook); the production path goes through the
// shared RetryClient so 429 (Monday GraphQL is rate-limited per
// account) and CDN 5xx hiccups are retried with Retry-After
// honoured.
func (c *MondayAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return retryDoerAdapter{r: sharedRetryClient}
}

// sharedRetryClient is a package-level singleton so the underlying
// *http.Client connection pool is reused across connector calls.
var sharedRetryClient = httputil.NewRetryClient(30 * time.Second)

// retryDoerAdapter bridges *httputil.RetryClient (which exposes
// Do(ctx, req)) to the httpDoer interface (which exposes
// Do(req)) so the existing call sites at line ~194 — and any
// future GraphQL helper — don't have to be rewritten. The
// context comes from the request itself, which is constructed
// via http.NewRequestWithContext upstream of this call.
type retryDoerAdapter struct{ r *httputil.RetryClient }

func (a retryDoerAdapter) Do(req *http.Request) (*http.Response, error) {
	return a.r.Do(req.Context(), req)
}

func (c *MondayAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
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

type graphQLRequest struct {
	Query string `json:"query"`
}

type graphQLError struct {
	Message string `json:"message"`
}

type graphQLResponse struct {
	Data struct {
		Users []mondayUser `json:"users"`
		Me    *mondayUser  `json:"me"`
	} `json:"data"`
	Errors []graphQLError `json:"errors,omitempty"`
}

type mondayBoard struct {
	ID          json.Number  `json:"id"`
	Name        string       `json:"name"`
	Subscribers []mondayUser `json:"subscribers"`
}

type graphQLBoardsResponse struct {
	Data struct {
		Boards []mondayBoard `json:"boards"`
	} `json:"data"`
	Errors []graphQLError `json:"errors,omitempty"`
}

type graphQLMutationResponse struct {
	Data   map[string]interface{} `json:"data"`
	Errors []graphQLError         `json:"errors,omitempty"`
}

type mondayUser struct {
	ID      json.Number `json:"id"`
	Name    string      `json:"name"`
	Email   string      `json:"email"`
	Enabled *bool       `json:"enabled,omitempty"`
}

func (c *MondayAccessConnector) post(ctx context.Context, secrets Secrets, query string) (*graphQLResponse, error) {
	body, err := c.postRaw(ctx, secrets, query)
	if err != nil {
		return nil, err
	}
	var g graphQLResponse
	if err := json.Unmarshal(body, &g); err != nil {
		return nil, fmt.Errorf("monday: decode graphql: %w", err)
	}
	if len(g.Errors) > 0 {
		return nil, fmt.Errorf("monday: graphql error: %s", g.Errors[0].Message)
	}
	return &g, nil
}

// postRaw issues a GraphQL request and returns the raw body. Unlike post,
// it does NOT inspect the `errors` array — callers must do so themselves.
// This is what the idempotent mutation paths use.
func (c *MondayAccessConnector) postRaw(ctx context.Context, secrets Secrets, query string) ([]byte, error) {
	payload, err := json.Marshal(graphQLRequest{Query: query})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", strings.TrimSpace(secrets.APIToken))
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("monday: graphql: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("monday: graphql: status %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// graphQLErrorIsIdempotent returns true if any of the supplied GraphQL
// errors look like a "already a subscriber" / "not a subscriber" /
// "not found" condition. Those are the natural idempotent cases for
// add_users_to_board / delete_subscribers_from_board.
func graphQLErrorIsIdempotent(errs []graphQLError, needles []string) bool {
	if len(errs) == 0 {
		return false
	}
	for _, e := range errs {
		lower := strings.ToLower(e.Message)
		for _, n := range needles {
			if strings.Contains(lower, n) {
				return true
			}
		}
	}
	return false
}

func (c *MondayAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if _, err := c.post(ctx, secrets, "query { me { id name email } }"); err != nil {
		return fmt.Errorf("monday: connect probe: %w", err)
	}
	return nil
}

func (c *MondayAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

func (c *MondayAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *MondayAccessConnector) SyncIdentities(
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
	for {
		query := fmt.Sprintf("query { users(limit: %d, page: %d) { id name email enabled } }", pageSize, page)
		resp, err := c.post(ctx, secrets, query)
		if err != nil {
			return err
		}
		identities := make([]*access.Identity, 0, len(resp.Data.Users))
		for _, u := range resp.Data.Users {
			status := "active"
			if u.Enabled != nil && !*u.Enabled {
				// Monday's `enabled: false` is a deactivated (but still present)
				// directory user — a deleted user is not returned by the users
				// query at all. Map it to "disabled" to match the taxonomy peers
				// use for accountEnabled=false (microsoft, mezmo); "deleted"
				// would mislead downstream reconciliation that distinguishes
				// removed vs deactivated accounts.
				status = "disabled"
			}
			display := u.Name
			if display == "" {
				display = u.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID.String(),
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      status,
			})
		}
		next := ""
		if len(resp.Data.Users) >= pageSize {
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

// ---------- advanced capabilities ----------

// ProvisionAccess subscribes a user to a Monday board via the
// add_users_to_board GraphQL mutation. ResourceExternalID is the
// board_id (numeric). "already subscribed" errors are mapped to
// idempotent success per docs/architecture.md §2.
func (c *MondayAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	userID, err := parseMondayID("grant.UserExternalID", grant.UserExternalID)
	if err != nil {
		return err
	}
	boardID, err := parseMondayID("grant.ResourceExternalID (board_id)", grant.ResourceExternalID)
	if err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	kind := "subscriber"
	if strings.EqualFold(grant.Role, "owner") {
		kind = "owner"
	}
	query := fmt.Sprintf("mutation { add_users_to_board(board_id: %s, user_ids: [%s], kind: %s) { id } }", boardID, userID, kind)
	body, err := c.postRaw(ctx, secrets, query)
	if err != nil {
		return err
	}
	var resp graphQLMutationResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("monday: decode mutation: %w", err)
	}
	if graphQLErrorIsIdempotent(resp.Errors, []string{"already subscribed", "already a subscriber", "already a member", "duplicate"}) {
		return nil
	}
	if len(resp.Errors) > 0 {
		return fmt.Errorf("monday: add_users_to_board: %s", resp.Errors[0].Message)
	}
	return nil
}

// RevokeAccess removes a user from a Monday board via the
// delete_subscribers_from_board GraphQL mutation. "not subscribed" /
// "not found" errors are mapped to idempotent success.
func (c *MondayAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	userID, err := parseMondayID("grant.UserExternalID", grant.UserExternalID)
	if err != nil {
		return err
	}
	boardID, err := parseMondayID("grant.ResourceExternalID (board_id)", grant.ResourceExternalID)
	if err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	query := fmt.Sprintf("mutation { delete_subscribers_from_board(board_id: %s, user_ids: [%s]) { id } }", boardID, userID)
	body, err := c.postRaw(ctx, secrets, query)
	if err != nil {
		return err
	}
	var resp graphQLMutationResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("monday: decode mutation: %w", err)
	}
	if graphQLErrorIsIdempotent(resp.Errors, []string{"not subscribed", "not a subscriber", "not found", "does not exist"}) {
		return nil
	}
	if len(resp.Errors) > 0 {
		return fmt.Errorf("monday: delete_subscribers_from_board: %s", resp.Errors[0].Message)
	}
	return nil
}

// maxBoardPages bounds the number of board pages ListEntitlements will
// scan. Monday.com has no per-user "my boards" query and the boards
// query is the only way to derive subscriptions for an arbitrary user,
// so the call is inherently O(boards / pageSize). On workspaces with
// hundreds of thousands of boards an unbounded scan would burn through
// the API complexity quota; capping at maxBoardPages keeps a single
// ListEntitlements call within a known request budget. Operators who
// need a complete view on very large workspaces should use the bulk
// SyncIdentities pipeline + a downstream join instead.
const maxBoardPages = 100

// ListEntitlements paginates boards via boards(limit:N,page:P) and emits
// one Entitlement per board the user is currently subscribed to. Monday
// does not expose a per-user "my boards" query for arbitrary users, so
// we walk the workspace boards and filter subscribers in-process. The
// scan honours ctx cancellation between pages and stops after
// maxBoardPages pages have been visited; see the maxBoardPages comment
// for the rationale.
func (c *MondayAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("monday: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	var out []access.Entitlement
	for page := 1; page <= maxBoardPages; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		query := fmt.Sprintf("query { boards(limit: %d, page: %d) { id name subscribers { id } } }", pageSize, page)
		body, err := c.postRaw(ctx, secrets, query)
		if err != nil {
			return nil, err
		}
		var resp graphQLBoardsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("monday: decode boards: %w", err)
		}
		if len(resp.Errors) > 0 {
			return nil, fmt.Errorf("monday: boards: %s", resp.Errors[0].Message)
		}
		for _, b := range resp.Data.Boards {
			for _, sub := range b.Subscribers {
				if sub.ID.String() == userExternalID {
					out = append(out, access.Entitlement{
						ResourceExternalID: b.ID.String(),
						Role:               "subscriber",
						Source:             "direct",
					})
					break
				}
			}
		}
		if len(resp.Data.Boards) < pageSize {
			return out, nil
		}
	}
	return out, nil
}
func (c *MondayAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *MondayAccessConnector) GetCredentialsMetadata(_ context.Context, _, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "api_token",
		"token_short": shortToken(s.APIToken),
	}, nil
}

// shortToken returns a redacted, human-identifiable hint for a credential
// without ever exposing the secret itself. GetCredentialsMetadata is documented
// as returning metadata without decrypting the secret, and its result is
// surfaced in admin UIs and logs, so the raw value must never appear. It only
// reveals a 4-char prefix and suffix when the token is long enough (>=12) to
// keep at least 4 characters hidden; shorter tokens are fully masked.
func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	if len(t) < 12 {
		return "***"
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*MondayAccessConnector)(nil)
