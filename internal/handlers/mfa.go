package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/mfa"
)

// mfaHandlers serves the self-service step-up MFA enrolment and management
// surface: a user registers and manages the factors (TOTP and/or WebAuthn) that
// the high-risk step-up gates (e.g. policy promotion) later require via the
// X-MFA-Assertion header. Every operation is scoped to the verified tenant
// (RequireTenant) and the validated token subject — a user can only manage
// their OWN credentials — so no permission gate is needed and one tenant member
// cannot touch another's enrolled authenticators.
//
// The actual step-up verification is NOT performed here: the begin endpoints
// issue a challenge, the user agent produces an assertion, and that assertion
// is submitted on the next high-risk request through middleware.RequireStepUpMFA
// → the composite verifier. These routes only manage the credentials and issue
// the ceremony options.
type mfaHandlers struct {
	totp     *mfa.TOTPMFAVerifier
	webauthn *mfa.WebAuthnMFAVerifier
}

// newMFAHandlers builds the handler set from the concrete verifiers wired on
// Deps. Either may be nil (the corresponding factor's routes then return 503),
// so the surface degrades cleanly when only one factor — or neither — is
// configured.
func newMFAHandlers(deps Deps) *mfaHandlers {
	return &mfaHandlers{totp: deps.TOTP, webauthn: deps.WebAuthn}
}

// register mounts the MFA self-service routes on the tenant-scoped group (which
// already carries Auth + ResolveTenant + RequireTenant). The routes are
// self-service (keyed by the authenticated subject), so they are deliberately
// not behind a RequirePermission gate — every user manages their own factors.
func (h *mfaHandlers) register(g *gin.RouterGroup) {
	grp := g.Group("/mfa")

	// Aggregate enrolment status across factors, for the account security page.
	grp.GET("/methods", h.methods)

	// TOTP (authenticator-app) enrolment.
	grp.POST("/totp/enroll/begin", h.totpEnrollBegin)
	grp.POST("/totp/enroll/finish", h.totpEnrollFinish)
	grp.POST("/totp/disable", h.totpDisable)

	// WebAuthn / FIDO2 enrolment + management.
	grp.POST("/webauthn/register/begin", h.webauthnRegisterBegin)
	grp.POST("/webauthn/register/finish", h.webauthnRegisterFinish)
	grp.POST("/webauthn/stepup/begin", h.webauthnStepUpBegin)
	grp.GET("/webauthn/credentials", h.webauthnListCredentials)
	grp.DELETE("/webauthn/credentials/:id", h.webauthnDeleteCredential)
}

// --- aggregate status ---

// webAuthnCredentialDTO is the sanitized public view of an enrolled WebAuthn
// credential. It deliberately omits the sealed envelope, the raw credential id,
// and the AAGUID/public key: the client only needs to identify and manage the
// credential, never any material that could aid impersonation.
type webAuthnCredentialDTO struct {
	ID           uuid.UUID  `json:"id"`
	FriendlyName string     `json:"friendly_name"`
	SignCount    uint32     `json:"sign_count"`
	CloneWarning bool       `json:"clone_warning"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

func toWebAuthnCredentialDTO(rows []models.WebAuthnCredential) []webAuthnCredentialDTO {
	out := make([]webAuthnCredentialDTO, 0, len(rows))
	for i := range rows {
		out = append(out, webAuthnCredentialDTO{
			ID:           rows[i].ID,
			FriendlyName: rows[i].FriendlyName,
			SignCount:    rows[i].SignCount,
			CloneWarning: rows[i].CloneWarning,
			LastUsedAt:   rows[i].LastUsedAt,
			CreatedAt:    rows[i].CreatedAt,
		})
	}
	return out
}

// methods reports the caller's enrolment state across every factor, so the
// account security page can render "TOTP: enrolled / WebAuthn: 2 keys" and the
// step-up prompt can offer only the factors the user actually has. Each factor
// block is present only when its verifier is wired.
func (h *mfaHandlers) methods(c *gin.Context) {
	ws, ok := workspace(c)
	if !ok {
		return
	}
	user := actor(c)

	resp := gin.H{}

	if h.totp != nil {
		status, err := h.totp.Status(c.Request.Context(), ws, user)
		if err != nil {
			h.fail(c, err)
			return
		}
		resp["totp"] = gin.H{
			"configured": true,
			"verified":   status.Verified,
			"pending":    status.Pending,
		}
	} else {
		resp["totp"] = gin.H{"configured": false}
	}

	if h.webauthn != nil {
		rows, err := h.webauthn.ListCredentials(c.Request.Context(), ws, user)
		if err != nil {
			h.fail(c, err)
			return
		}
		resp["webauthn"] = gin.H{
			"configured":  true,
			"credentials": toWebAuthnCredentialDTO(rows),
		}
	} else {
		resp["webauthn"] = gin.H{"configured": false}
	}

	c.JSON(http.StatusOK, resp)
}

// --- TOTP ---

func (h *mfaHandlers) totpEnrollBegin(c *gin.Context) {
	if h.totp == nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "TOTP is not configured"})
		return
	}
	ws, ok := workspace(c)
	if !ok {
		return
	}
	enrollment, err := h.totp.BeginEnrollment(c.Request.Context(), ws, actor(c), "", "")
	if err != nil {
		h.fail(c, err)
		return
	}
	// The secret/otpauth URL are shown exactly once for QR/manual entry; the
	// secret is already sealed server-side. Not logged.
	c.JSON(http.StatusOK, gin.H{
		"secret":      enrollment.Secret,
		"otpauth_url": enrollment.OtpauthURL,
	})
}

type totpFinishBody struct {
	Code string `json:"code" binding:"required"`
}

func (h *mfaHandlers) totpEnrollFinish(c *gin.Context) {
	if h.totp == nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "TOTP is not configured"})
		return
	}
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var body totpFinishBody
	if !bind(c, &body) {
		return
	}
	if err := h.totp.FinishEnrollment(c.Request.Context(), ws, actor(c), body.Code); err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"verified": true})
}

func (h *mfaHandlers) totpDisable(c *gin.Context) {
	if h.totp == nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "TOTP is not configured"})
		return
	}
	ws, ok := workspace(c)
	if !ok {
		return
	}
	if err := h.totp.DisableTOTP(c.Request.Context(), ws, actor(c)); err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"disabled": true})
}

// --- WebAuthn ---

func (h *mfaHandlers) webauthnRegisterBegin(c *gin.Context) {
	if h.webauthn == nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "WebAuthn is not configured"})
		return
	}
	ws, ok := workspace(c)
	if !ok {
		return
	}
	creation, err := h.webauthn.BeginRegistration(c.Request.Context(), ws, actor(c), "")
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, creation)
}

// webauthnRegisterFinishBody carries the attestation response from
// navigator.credentials.create(). credential is the raw PublicKeyCredential JSON
// the browser produced; it is forwarded verbatim to the verifier, which parses
// and cryptographically validates it against the outstanding challenge.
type webauthnRegisterFinishBody struct {
	FriendlyName string          `json:"friendly_name"`
	Credential   json.RawMessage `json:"credential" binding:"required"`
}

func (h *mfaHandlers) webauthnRegisterFinish(c *gin.Context) {
	if h.webauthn == nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "WebAuthn is not configured"})
		return
	}
	ws, ok := workspace(c)
	if !ok {
		return
	}
	var body webauthnRegisterFinishBody
	if !bind(c, &body) {
		return
	}
	cred, err := h.webauthn.FinishRegistration(c.Request.Context(), ws, actor(c), body.FriendlyName, body.Credential)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"id":            cred.ID,
		"friendly_name": cred.FriendlyName,
		"created_at":    cred.CreatedAt,
	})
}

func (h *mfaHandlers) webauthnStepUpBegin(c *gin.Context) {
	if h.webauthn == nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "WebAuthn is not configured"})
		return
	}
	ws, ok := workspace(c)
	if !ok {
		return
	}
	assertion, err := h.webauthn.BeginStepUp(c.Request.Context(), ws, actor(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, assertion)
}

func (h *mfaHandlers) webauthnListCredentials(c *gin.Context) {
	if h.webauthn == nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "WebAuthn is not configured"})
		return
	}
	ws, ok := workspace(c)
	if !ok {
		return
	}
	rows, err := h.webauthn.ListCredentials(c.Request.Context(), ws, actor(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"credentials": toWebAuthnCredentialDTO(rows)})
}

func (h *mfaHandlers) webauthnDeleteCredential(c *gin.Context) {
	if h.webauthn == nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "WebAuthn is not configured"})
		return
	}
	ws, ok := workspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c, "id")
	if !ok {
		return
	}
	if err := h.webauthn.DeleteCredential(c.Request.Context(), ws, actor(c), id); err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// fail maps MFA service errors to HTTP status codes. A verification/enrolment
// rejection (ErrMFAFailed) is a 400 in this self-service context — the client
// submitted a bad code or a non-verifying attestation, which it can correct and
// retry. A missing credential is 404. A sealing-key outage (no DEK configured)
// is 503: the operation is temporarily impossible, not the client's fault.
// Anything else is a 500 and is logged, never echoed.
func (h *mfaHandlers) fail(c *gin.Context, err error) {
	switch {
	case errors.Is(err, mfa.ErrMFAFailed):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "verification failed"})
	case errors.Is(err, gorm.ErrRecordNotFound):
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "credential not found"})
	case errors.Is(err, crypto.ErrSecretsDisabled):
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "MFA secret storage is not configured"})
	default:
		logger.Errorf(c.Request.Context(), "mfa: unhandled error: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}
