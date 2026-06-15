package handlers

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/kennguy3n/fishbone-access/internal/gateway"
	"github.com/kennguy3n/fishbone-access/internal/middleware"
	"github.com/kennguy3n/fishbone-access/internal/pkg/aiclient"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
	"github.com/kennguy3n/fishbone-access/internal/webaccess"
)

// bearerSubprotocolPrefix is how a browser smuggles the iam-core bearer token
// through the WebSocket handshake: the WebSocket API cannot set an Authorization
// header, but it can offer subprotocols, so the client offers
// "shieldnet.bearer.<jwt>" (a JWT is a valid RFC6455 subprotocol token —
// base64url + '.') alongside the negotiated protocol below. The server reads
// the token from there and never echoes it back.
const bearerSubprotocolPrefix = "shieldnet.bearer."

// negotiatedSubprotocol is the non-secret subprotocol the server selects in the
// upgrade response (browsers require the server to echo one of the offered
// protocols when any are offered).
const negotiatedSubprotocol = "shieldnet.access.v1"

// webAccessHandlers serves the clientless browser-access WebSocket endpoints
// (web SSH terminal + web database console). It authenticates each handshake
// itself — the iam-core bearer (Authorization header or bearer subprotocol) and
// the tenant→workspace resolution — because a browser WebSocket cannot carry
// the headers the normal /api/v1 middleware chain requires.
type webAccessHandlers struct {
	bridge    *webaccess.Bridge
	validator middleware.TokenValidator
	resolver  middleware.WorkspaceResolver
	upgrader  websocket.Upgrader
}

// newWebAccessHandlers wires the bridge to a PAM service bundle built the same
// way the native gateway and the PAM REST surface build theirs, so a browser
// session redeems tokens, validates leases, gates commands, records, audits, and
// honours admin takeover identically. It starts a SessionReconciler so
// pause/terminate issued through the PAM REST API (a different service bundle,
// writing only durable intent) is applied to the in-process browser sessions;
// the reconciler is hub-gated (it queries only for sessions currently bridged),
// so it is idle and free when no browser session is live.
func newWebAccessHandlers(deps Deps, resolver middleware.WorkspaceResolver) *webAccessHandlers {
	db := deps.DB

	enc := deps.ConnectorEncryptor
	if enc == nil {
		keyVersion := 1
		if v := os.Getenv("ACCESS_KMS_KEY_VERSION"); v != "" {
			// Match the config and crypto layers, which both require a key
			// version >= 1 (a 0 is rejected by NewDerivedDEKKeyManager); accept
			// only a valid version so this fallback never feeds the crypto layer
			// a value it will reject.
			if n, perr := strconv.Atoi(v); perr == nil && n >= 1 {
				keyVersion = n
			}
		}
		built, err := access.CredentialEncryptorFromConfig(
			os.Getenv("ACCESS_KMS_MASTER_KEY"), keyVersion, os.Getenv("ACCESS_CREDENTIAL_DEK"),
		)
		if err != nil {
			logger.Errorf(context.Background(), "webaccess: credential encryptor init: %v (vault operations will fail closed)", err)
			built = access.NewDisabledEncryptor()
		}
		enc = built
	}

	var stepUp *pam.StepUpGate
	if deps.Validator != nil {
		stepUp = pam.NewStepUpGate(deps.Validator, 5*time.Minute)
	}

	vault := pam.NewVault(db, enc, stepUp)
	broker := pam.NewBroker(db, vault, stepUp)
	evaluator := pam.NewCommandPolicyEvaluator(db, 5*time.Second)
	// The hub is wired as the session manager's live controller so an in-process
	// browser session reacts immediately to a control decision that lands on
	// this same bundle; the reconciler below is the cross-bundle catch-up.
	hub := gateway.NewSessionHub()
	sessions := pam.NewSessionManager(db, evaluator, hub)

	ai := deps.AI
	if ai == nil {
		built, aiErr := aiclient.NewAIClientFromEnv()
		if aiErr != nil {
			built = aiclient.NewAIClient("", nil, "")
		}
		ai = built
	}
	leases := pam.NewPAMLeaseService(db, ai)
	leases.SetSessionTerminator(sessions)
	broker.SetLeaseValidator(leases)

	store := buildReplayStore()

	bridge, err := webaccess.NewBridge(webaccess.BridgeConfig{
		Broker:        broker,
		Sessions:      sessions,
		Hub:           hub,
		Store:         store,
		CA:            buildWebAccessSSHCA(),
		RecMaxBytes:   deps.WebAccess.RecMaxBytes,
		DialTimeout:   deps.WebAccess.DialTimeout,
		IdleTimeout:   deps.WebAccess.IdleTimeout,
		MaxResultRows: deps.WebAccess.MaxResultRows,
	})
	if err != nil {
		// NewBridge only errors on a missing broker/sessions, which are always
		// constructed above; treat it as a fatal wiring bug rather than booting
		// a half-wired feature.
		logger.Errorf(context.Background(), "webaccess: bridge init: %v (web access disabled)", err)
		return nil
	}

	// Bridge REST-issued session control onto in-process browser sessions. Bound
	// to the process-lifetime context (signal-cancelled in main) so the loop is
	// cancelled on shutdown like every other background loop rather than leaked.
	// It is also hub-gated, so it does no work (and no DB query) while no browser
	// session is live. nil falls back to context.Background() for bare-Deps
	// test routers, preserving prior behaviour.
	reconcileCtx := deps.WebAccessContext
	if reconcileCtx == nil {
		reconcileCtx = context.Background()
	}
	reconciler := gateway.NewSessionReconciler(hub, sessions, 0)
	go reconciler.Run(reconcileCtx)

	return &webAccessHandlers{
		bridge:    bridge,
		validator: deps.Validator,
		resolver:  resolver,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			Subprotocols:    []string{negotiatedSubprotocol},
			// Authentication is the iam-core bearer token, not an ambient
			// cookie, so there is no cross-site request-forgery authority for an
			// Origin check to protect: a page on another origin cannot obtain a
			// valid bearer token. Accept any origin and rely on the token.
			CheckOrigin: func(*http.Request) bool { return true },
		},
	}
}

// buildReplayStore selects the session-replay WRITE backend from the
// environment, matching the gateway's buildReplayStore so browser sessions are
// recorded to the same location the native gateway writes to (and the PAM
// replay reader reads from). Returns nil when no backend initialises, in which
// case recording is captured in-memory but not persisted (the session still
// runs and is fully audited).
func buildReplayStore() gateway.ReplayStore {
	if bucket := os.Getenv("PAM_REPLAY_S3_BUCKET"); bucket != "" {
		region := os.Getenv("PAM_REPLAY_S3_REGION")
		var opts []gateway.S3Option
		if ep := os.Getenv("PAM_REPLAY_S3_ENDPOINT"); ep != "" {
			opts = append(opts, gateway.WithEndpointURL(ep), gateway.WithForcePathStyle(true))
		}
		store, err := gateway.NewS3ReplayStore(context.Background(), bucket, region, opts...)
		if err != nil {
			logger.Errorf(context.Background(), "webaccess: S3 replay store init: %v (recordings not persisted)", err)
			return nil
		}
		return store
	}
	dir := os.Getenv("PAM_REPLAY_DIR")
	if dir == "" {
		dir = "./pam-replays"
	}
	store, err := gateway.NewFilesystemReplayStore(dir)
	if err != nil {
		logger.Warnf(context.Background(), "webaccess: filesystem replay store init: %v (recordings not persisted)", err)
		return nil
	}
	return store
}

// buildWebAccessSSHCA loads the optional SSH certificate authority used to mint
// short-lived upstream certificates, matching the gateway's CA wiring (same
// PAM_SSH_CA_KEY). Returns nil (credential-injection-only) when no CA key is
// configured or it fails to load.
func buildWebAccessSSHCA() *gateway.SSHCertificateAuthority {
	key := os.Getenv("PAM_SSH_CA_KEY")
	if key == "" {
		return nil
	}
	ca, err := gateway.LoadSSHCAFromValue(key, 0)
	if err != nil {
		logger.Warnf(context.Background(), "webaccess: ssh CA init: %v (falling back to credential injection)", err)
		return nil
	}
	return ca
}

// register mounts the WebSocket endpoints on the ROOT engine (not the
// tenant-scoped group): the handshake cannot pass the Auth + RequireTenant
// middleware because a browser WebSocket carries no Authorization or
// X-Tenant-ID header, so each handler authenticates the handshake itself.
func (h *webAccessHandlers) register(r *gin.Engine) {
	if h == nil {
		return
	}
	r.GET("/api/v1/webaccess/ssh", h.serveSSH)
	r.GET("/api/v1/webaccess/db", h.serveDB)
}

func (h *webAccessHandlers) serveSSH(c *gin.Context) {
	h.serve(c, kindWebSSH)
}

func (h *webAccessHandlers) serveDB(c *gin.Context) {
	h.serve(c, kindWebDB)
}

// webKind selects which bridge entry-point a route drives.
type webKind int

const (
	kindWebSSH webKind = iota
	kindWebDB
)

// serve authenticates the handshake, resolves the caller's workspace, upgrades
// the connection, and hands it to the bridge. Pre-upgrade failures answer with
// an HTTP status (the handshake never completes); the bridge owns all
// post-upgrade messaging.
func (h *webAccessHandlers) serve(c *gin.Context, k webKind) {
	if h.validator == nil || h.resolver == nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "web access unavailable"})
		return
	}

	token := h.bearerFromRequest(c)
	if token == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
		return
	}
	claims, err := h.validator.Validate(token)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}
	if claims.TenantID == "" {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "token is not scoped to a tenant"})
		return
	}
	workspaceID, err := h.resolver.WorkspaceIDByTenant(c.Request.Context(), claims.TenantID)
	if err != nil || workspaceID == uuid.Nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "no workspace for tenant"})
		return
	}

	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		// Upgrade already wrote the error response; nothing more to do.
		logger.Warnf(c.Request.Context(), "webaccess: upgrade failed: %v", err)
		return
	}

	params := webaccess.ServeParams{
		WorkspaceID: workspaceID,
		RemoteAddr:  c.ClientIP(),
	}
	// Detach from the Gin request context (which is cancelled the instant this
	// handler returns) so the long-lived session runs for its full duration; the
	// bridge owns teardown and the idle/lease/terminate controls bound it.
	ctx := context.WithoutCancel(c.Request.Context())
	switch k {
	case kindWebSSH:
		h.bridge.ServeSSH(ctx, conn, params)
	case kindWebDB:
		h.bridge.ServeDB(ctx, conn, params)
	}
}

// bearerFromRequest extracts the iam-core bearer token from either the
// Authorization header (non-browser clients, tests) or the bearer subprotocol
// (browsers, which cannot set the header).
func (h *webAccessHandlers) bearerFromRequest(c *gin.Context) string {
	if raw := bearerHeaderToken(c.GetHeader("Authorization")); raw != "" {
		return raw
	}
	for _, proto := range websocket.Subprotocols(c.Request) {
		if strings.HasPrefix(proto, bearerSubprotocolPrefix) {
			return strings.TrimPrefix(proto, bearerSubprotocolPrefix)
		}
	}
	return ""
}

// bearerHeaderToken extracts the raw token from an "Authorization: Bearer …"
// header value, or "" when the header is absent or malformed.
func bearerHeaderToken(header string) string {
	const prefix = "Bearer "
	if len(header) > len(prefix) && strings.EqualFold(header[:len(prefix)], prefix) {
		return strings.TrimSpace(header[len(prefix):])
	}
	return ""
}
