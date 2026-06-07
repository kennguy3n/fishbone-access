// Package aiclient is the Go control-plane client for the access-ai-agent A2A
// (agent-to-agent) skill server (cmd/access-ai-agent, Python/FastAPI).
//
// Transport is mutual TLS: the client presents a client certificate the agent
// verifies and pins the agent's server certificate to a configured CA (and,
// optionally, a SPIFFE URI-SAN allowlist). On top of mTLS it POSTs a JSON
// envelope to {baseURL}/a2a/invoke with an optional X-API-Key header for
// defence in depth. The agent routes by the request's skill_name field, so this
// client is skill-name-agnostic; callers target any skill the agent registers.
//
// Failure semantics: AI is decision-support, not the critical path. InvokeSkill
// never panics; transport / decode errors surface to the caller. The typed
// helpers in fallback.go wrap each skill with a fail-safe default (e.g.
// risk_score=medium) so a momentarily-unreachable agent never blocks a
// privileged decision — unless the caller opts into fail-closed.
package aiclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"
)

// defaultTimeout bounds a single skill invocation end-to-end. AI is
// decision-support, so a slow agent must not stall an access request: the
// control plane prefers its deterministic fallback to a long block.
const defaultTimeout = 5 * time.Second

// invokePath is the agent's single skill-dispatch endpoint.
const invokePath = "/a2a/invoke"

// ErrAIUnconfigured is returned by InvokeSkill when the client has no base URL.
// An unconfigured client is an explicit signal that AI is intentionally off;
// the fallback helpers treat it the same as an unreachable agent.
var ErrAIUnconfigured = errors.New("aiclient: agent base URL not configured")

// SkillResponse is the unified response envelope returned by the agent. Each
// skill populates a subset of the fields. Unknown JSON fields are intentionally
// ignored so server-side schema additions do not break existing callers.
type SkillResponse struct {
	RiskScore      string         `json:"risk_score,omitempty"`
	RiskFactors    []string       `json:"risk_factors,omitempty"`
	Decision       string         `json:"decision,omitempty"`
	Reason         string         `json:"reason,omitempty"`
	Explanation    string         `json:"explanation,omitempty"`
	Anomalies      []AnomalyEvent `json:"anomalies,omitempty"`
	Recommendation string         `json:"recommendation,omitempty"`
}

// AnomalyEvent is one entry in the access_anomaly_detection response. Severity
// uses the same low/medium/high vocabulary as risk score; Confidence is the
// agent's self-reported confidence in [0.0, 1.0] and is informative only.
type AnomalyEvent struct {
	Kind       string  `json:"kind"`
	Reason     string  `json:"reason,omitempty"`
	Severity   string  `json:"severity,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

// AIClient is the mTLS HTTP wrapper around the access-ai-agent service. The zero
// value is not usable; construct via NewAIClient or NewAIClientFromEnv. After
// construction it is safe for concurrent use.
type AIClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewAIClient builds a client that POSTs against baseURL (the agent root, e.g.
// "https://access-ai-agent.internal:8443"; the /a2a/invoke suffix is appended
// internally). tlsConfig carries the mTLS material from ClientTLSConfig.Build;
// when nil the client uses the default (system-trust) transport, which is only
// appropriate in tests against an httptest TLS server. apiKey is sent as
// X-API-Key when non-empty.
//
// An empty baseURL yields an intentionally-unconfigured client whose
// InvokeSkill returns ErrAIUnconfigured so the caller's fallback path runs.
func NewAIClient(baseURL string, tlsConfig *tls.Config, apiKey string) *AIClient {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig
		transport.ForceAttemptHTTP2 = true
	}
	return &AIClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		apiKey:  strings.TrimSpace(apiKey),
		httpClient: &http.Client{
			Timeout:   defaultTimeout,
			Transport: transport,
		},
	}
}

// NewAIClientFromEnv builds a client from the A2A environment contract. It
// returns an unconfigured client (no base URL → ErrAIUnconfigured) when neither
// the URL nor any mTLS variable is set, and a *MTLSConfigError when the mTLS
// material is partially configured or unreadable, so a misconfiguration fails
// the boot rather than silently degrading to an unauthenticated transport.
func NewAIClientFromEnv() (*AIClient, error) {
	baseURL := strings.TrimSpace(os.Getenv(EnvBaseURL))
	apiKey := strings.TrimSpace(os.Getenv(EnvAPIKey))
	tlsCfg, err := TLSConfigFromEnv()
	if err != nil {
		return nil, err
	}
	if tlsCfg == nil {
		// No mTLS configured. A base URL without mTLS is rejected: the A2A
		// contract is mTLS-only, so we never fall back to plaintext/TLS-without-
		// client-auth. With neither set, return an unconfigured client.
		if baseURL != "" {
			return nil, &MTLSConfigError{msg: fmt.Sprintf(
				"%s is set but mTLS is not configured: set %s, %s and %s",
				EnvBaseURL, EnvClientCertFile, EnvClientKeyFile, EnvServerCAFile,
			)}
		}
		return NewAIClient("", nil, ""), nil
	}
	// mTLS material is present. Requiring a base URL here keeps the contract
	// symmetric with the "URL without mTLS" rejection above: a half-configured
	// setup (certs provisioned but no agent URL) is an operator mistake that
	// fails the boot, rather than silently loading the certs into a client that
	// can never reach the agent and always returns ErrAIUnconfigured.
	if baseURL == "" {
		return nil, &MTLSConfigError{msg: fmt.Sprintf(
			"mTLS is configured but %s is not set: set the agent URL or unset the mTLS variables (%s, %s, %s)",
			EnvBaseURL, EnvClientCertFile, EnvClientKeyFile, EnvServerCAFile,
		)}
	}
	tc, err := tlsCfg.Build()
	if err != nil {
		return nil, err
	}
	return NewAIClient(baseURL, tc, apiKey), nil
}

// SetHTTPClient overrides the underlying *http.Client. Intended for tests that
// inject an httptest server's client; call once at construction before any
// goroutine invokes a skill.
func (c *AIClient) SetHTTPClient(h *http.Client) {
	if h != nil {
		c.httpClient = h
	}
}

// BaseURL returns the configured agent root URL ("" when unconfigured).
func (c *AIClient) BaseURL() string { return c.baseURL }

// Configured reports whether the client has a base URL to call.
func (c *AIClient) Configured() bool { return c != nil && c.baseURL != "" }

// invokeRequest is the JSON envelope POSTed to /a2a/invoke. The agent dispatches
// by SkillName; WorkspaceAITier (optional) routes the LLM model per workspace.
type invokeRequest struct {
	SkillName       string      `json:"skill_name"`
	Payload         interface{} `json:"payload,omitempty"`
	WorkspaceAITier string      `json:"workspace_ai_tier,omitempty"`
}

// InvokeSkill posts a skill invocation and decodes the unified envelope.
func (c *AIClient) InvokeSkill(ctx context.Context, skillName string, payload interface{}) (*SkillResponse, error) {
	return c.InvokeSkillForTier(ctx, skillName, "", payload)
}

// InvokeSkillForTier is the tier-aware sibling of InvokeSkill: it stamps the
// workspace's AI tier ("deterministic" / "local_4b" / "local_8b") into the
// envelope so the agent routes the LLM call accordingly. An empty tier is
// byte-identical to InvokeSkill.
func (c *AIClient) InvokeSkillForTier(ctx context.Context, skillName, workspaceAITier string, payload interface{}) (*SkillResponse, error) {
	var out SkillResponse
	if err := c.InvokeSkillInto(ctx, skillName, workspaceAITier, payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// InvokeSkillInto posts a skill invocation and decodes the response body into
// out (a non-nil pointer). It is the low-level primitive behind the typed skill
// helpers in fallback.go, which need to decode skill-specific response shapes
// rather than the unified envelope.
func (c *AIClient) InvokeSkillInto(ctx context.Context, skillName, workspaceAITier string, payload, out interface{}) error {
	if c == nil || c.baseURL == "" {
		return ErrAIUnconfigured
	}
	if err := requireNonNilPointer(out); err != nil {
		return err
	}
	body, err := json.Marshal(invokeRequest{
		SkillName:       skillName,
		Payload:         payload,
		WorkspaceAITier: workspaceAITier,
	})
	if err != nil {
		return fmt.Errorf("aiclient: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+invokePath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("aiclient: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("aiclient: invoke %q: %w", skillName, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Cap the response read so a misbehaving agent cannot exhaust memory.
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("aiclient: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("aiclient: skill %q returned HTTP %d: %s", skillName, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("aiclient: decode response: %w", err)
	}
	return nil
}

// requireNonNilPointer rejects a nil or non-pointer out so a decode never
// silently no-ops. It mirrors json.Unmarshal's own contract but with a clearer,
// package-scoped error.
func requireNonNilPointer(out interface{}) error {
	if out == nil {
		return errors.New("aiclient: out must be a non-nil pointer")
	}
	v := reflect.ValueOf(out)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return fmt.Errorf("aiclient: out must be a non-nil pointer, got %T", out)
	}
	return nil
}
