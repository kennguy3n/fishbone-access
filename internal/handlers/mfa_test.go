package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	vwa "github.com/descope/virtualwebauthn"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/mfa"
)

// mfaTestDEK is a fixed base64 32-byte DEK exercising the real AES-GCM seal path
// in handler tests (a test key, not a credential).
const mfaTestDEK = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

const (
	mfaRPID    = "example.com"
	mfaRPName  = "ShieldNet Access"
	mfaOrigin  = "https://example.com"
	mfaSubject = "user-a"
)

// mfaTestDeps builds a router-ready Deps with both step-up factors wired against
// a real (non-passthrough) encryptor, plus the resolved workspace UUID for
// tenant-a so a test can drive a virtual-authenticator ceremony.
func mfaTestDeps(t *testing.T) (Deps, *gorm.DB, uuid.UUID) {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ws := models.Workspace{Name: "tenant-a", IAMCoreTenantID: "tenant-a"}
	if err := db.Create(&ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}

	enc, err := crypto.NewAESGCMEncryptor(mfaTestDEK)
	if err != nil {
		t.Fatalf("new encryptor: %v", err)
	}
	totpV, err := mfa.NewTOTPMFAVerifier(db, enc)
	if err != nil {
		t.Fatalf("new totp verifier: %v", err)
	}
	webauthnV, err := mfa.NewWebAuthnMFAVerifier(db, enc, mfa.WebAuthnSettings{
		RPID:          mfaRPID,
		RPDisplayName: mfaRPName,
		RPOrigins:     []string{mfaOrigin},
	})
	if err != nil {
		t.Fatalf("new webauthn verifier: %v", err)
	}

	ready := &atomic.Bool{}
	ready.Store(true)
	deps := Deps{
		Validator: mapValidator{byToken: map[string]*iamcore.Claims{
			"tok-a": {Subject: mfaSubject, TenantID: "tenant-a"},
		}},
		DB:        db,
		Encryptor: enc,
		TOTP:      totpV,
		WebAuthn:  webauthnV,
		StepUpMFA: mfa.NewCompositeMFAVerifier(webauthnV, totpV),
		Ready:     ready,
	}
	return deps, db, ws.ID
}

func TestMFAMethodsReportsBothFactors(t *testing.T) {
	deps, _, _ := mfaTestDeps(t)
	r := NewRouter(deps)

	w := do(t, r, http.MethodGet, "/api/v1/mfa/methods", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("methods status = %d, body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		TOTP struct {
			Configured bool `json:"configured"`
			Verified   bool `json:"verified"`
			Pending    bool `json:"pending"`
		} `json:"totp"`
		WebAuthn struct {
			Configured  bool              `json:"configured"`
			Credentials []json.RawMessage `json:"credentials"`
		} `json:"webauthn"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.TOTP.Configured || resp.TOTP.Verified || resp.TOTP.Pending {
		t.Fatalf("totp block = %+v, want configured-only", resp.TOTP)
	}
	if !resp.WebAuthn.Configured || len(resp.WebAuthn.Credentials) != 0 {
		t.Fatalf("webauthn block = %+v, want configured with no credentials", resp.WebAuthn)
	}
}

func TestTOTPEnrollViaHTTP(t *testing.T) {
	deps, _, _ := mfaTestDeps(t)
	r := NewRouter(deps)

	// Begin: returns a fresh secret + provisioning URI.
	w := do(t, r, http.MethodPost, "/api/v1/mfa/totp/enroll/begin", "tok-a", map[string]any{})
	if w.Code != http.StatusOK {
		t.Fatalf("begin status = %d, body=%s", w.Code, w.Body.String())
	}
	var begin struct {
		Secret     string `json:"secret"`
		OtpauthURL string `json:"otpauth_url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &begin); err != nil {
		t.Fatalf("decode begin: %v", err)
	}
	if begin.Secret == "" || !strings.HasPrefix(begin.OtpauthURL, "otpauth://totp/") {
		t.Fatalf("bad begin payload: %+v", begin)
	}

	// Finish with a valid code derived from the returned secret.
	code, err := totp.GenerateCode(begin.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	w = do(t, r, http.MethodPost, "/api/v1/mfa/totp/enroll/finish", "tok-a", map[string]any{"code": code})
	if w.Code != http.StatusOK {
		t.Fatalf("finish status = %d, body=%s", w.Code, w.Body.String())
	}

	// methods now reports TOTP verified.
	w = do(t, r, http.MethodGet, "/api/v1/mfa/methods", "tok-a", nil)
	if !strings.Contains(w.Body.String(), `"verified":true`) {
		t.Fatalf("methods after finish did not show verified: %s", w.Body.String())
	}

	// Disable removes the factor.
	w = do(t, r, http.MethodPost, "/api/v1/mfa/totp/disable", "tok-a", map[string]any{})
	if w.Code != http.StatusOK {
		t.Fatalf("disable status = %d, body=%s", w.Code, w.Body.String())
	}
}

func TestTOTPFinishBadCodeViaHTTP(t *testing.T) {
	deps, _, _ := mfaTestDeps(t)
	r := NewRouter(deps)

	if w := do(t, r, http.MethodPost, "/api/v1/mfa/totp/enroll/begin", "tok-a", map[string]any{}); w.Code != http.StatusOK {
		t.Fatalf("begin status = %d", w.Code)
	}
	// A wrong code is a client-correctable 400, not a 500.
	w := do(t, r, http.MethodPost, "/api/v1/mfa/totp/enroll/finish", "tok-a", map[string]any{"code": "000000"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("finish bad code status = %d, want 400, body=%s", w.Code, w.Body.String())
	}
}

func TestWebAuthnRegisterAndManageViaHTTP(t *testing.T) {
	deps, _, _ := mfaTestDeps(t)
	r := NewRouter(deps)

	// Begin registration → credential-creation options.
	w := do(t, r, http.MethodPost, "/api/v1/mfa/webauthn/register/begin", "tok-a", map[string]any{})
	if w.Code != http.StatusOK {
		t.Fatalf("register begin status = %d, body=%s", w.Code, w.Body.String())
	}
	attOpts, err := vwa.ParseAttestationOptions(w.Body.String())
	if err != nil {
		t.Fatalf("parse attestation options: %v", err)
	}

	// A virtual authenticator answers the ceremony.
	rp := vwa.RelyingParty{Name: mfaRPName, ID: mfaRPID, Origin: mfaOrigin}
	authr := vwa.NewAuthenticator()
	cred := vwa.NewCredential(vwa.KeyTypeEC2)
	attResp := vwa.CreateAttestationResponse(rp, authr, cred, *attOpts)

	// Finish registration with the attestation + a friendly name.
	w = do(t, r, http.MethodPost, "/api/v1/mfa/webauthn/register/finish", "tok-a", map[string]any{
		"friendly_name": "My YubiKey",
		"credential":    json.RawMessage(attResp),
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("register finish status = %d, body=%s", w.Code, w.Body.String())
	}

	// List returns a SANITIZED credential — never the sealed envelope, raw
	// credential id, AAGUID, or any key material.
	w = do(t, r, http.MethodGet, "/api/v1/mfa/webauthn/credentials", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d, body=%s", w.Code, w.Body.String())
	}
	body := strings.ToLower(w.Body.String())
	for _, leaked := range []string{"sealed", "credential_id", "credentialid", "aaguid", "public_key", "publickey"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("credential list leaked sensitive field %q: %s", leaked, w.Body.String())
		}
	}
	var list struct {
		Credentials []struct {
			ID           string `json:"id"`
			FriendlyName string `json:"friendly_name"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Credentials) != 1 || list.Credentials[0].FriendlyName != "My YubiKey" {
		t.Fatalf("unexpected list: %+v", list.Credentials)
	}

	// stepup/begin issues assertion options scoped to the registered credential.
	w = do(t, r, http.MethodPost, "/api/v1/mfa/webauthn/stepup/begin", "tok-a", map[string]any{})
	if w.Code != http.StatusOK {
		t.Fatalf("stepup begin status = %d, body=%s", w.Code, w.Body.String())
	}
	if _, err := vwa.ParseAssertionOptions(w.Body.String()); err != nil {
		t.Fatalf("parse assertion options: %v", err)
	}

	// Delete the credential, then a second delete is 404.
	id := list.Credentials[0].ID
	if w := do(t, r, http.MethodDelete, "/api/v1/mfa/webauthn/credentials/"+id, "tok-a", nil); w.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body=%s", w.Code, w.Body.String())
	}
	if w := do(t, r, http.MethodDelete, "/api/v1/mfa/webauthn/credentials/"+id, "tok-a", nil); w.Code != http.StatusNotFound {
		t.Fatalf("re-delete status = %d, want 404", w.Code)
	}
}

// TestMFARoutesDegradeWhenFactorUnconfigured proves the routes return 503 (not
// 500/panic) when a factor's verifier is nil.
func TestMFARoutesDegradeWhenFactorUnconfigured(t *testing.T) {
	deps, _, _ := mfaTestDeps(t)
	deps.TOTP = nil
	deps.WebAuthn = nil
	r := NewRouter(deps)

	for _, path := range []string{
		"/api/v1/mfa/totp/enroll/begin",
		"/api/v1/mfa/webauthn/register/begin",
		"/api/v1/mfa/webauthn/stepup/begin",
	} {
		if w := do(t, r, http.MethodPost, path, "tok-a", map[string]any{}); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s status = %d, want 503", path, w.Code)
		}
	}
	// methods still works, reporting both factors unconfigured.
	w := do(t, r, http.MethodGet, "/api/v1/mfa/methods", "tok-a", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"configured":false`) {
		t.Fatalf("methods with no factors = %d body=%s", w.Code, w.Body.String())
	}
}
