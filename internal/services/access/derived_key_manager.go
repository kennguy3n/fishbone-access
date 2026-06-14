package access

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DerivedDEKKeyManager is the per-workspace KeyManager for deployments that
// want true tenant key separation without operating an external KMS yet — the
// local/dev posture. It holds one high-entropy master key (the KEK) and
// DERIVES a distinct 32-byte AES-256 DEK for each workspace with HKDF-SHA256,
// using the workspace id and key version as the derivation info. No per-tenant
// key material is stored: every DEK is recomputed on demand and is
// cryptographically independent of every other workspace's DEK (HKDF is a
// one-way KDF, so compromising one workspace's derived DEK reveals neither the
// master key nor any other workspace's DEK).
//
// It satisfies the same KeyManager seam as StaticDEKKeyManager, so a future AWS
// KMS / Vault / GCP / Azure manager — which would generate-and-wrap per-tenant
// DEKs under a managed KEK — drops in at the same interface with no service-
// layer change. The EnvelopeEncryptor persists the keyVersion alongside each
// ciphertext, so this manager supports key rotation: bump currentVersion and
// new writes seal under the new version while old rows still open under the
// version recorded with them.
//
// Boundary (documented honestly): all per-workspace DEKs derive from one master
// key, so a compromise of the master key compromises every workspace — exactly
// as a compromise of a single KMS CMK would. That is the inherent property of
// any single-root key hierarchy; per-tenant isolation here protects against
// leak/misuse of an individual workspace's DEK, not against root compromise.
type DerivedDEKKeyManager struct {
	master         []byte
	currentVersion int
}

// hkdfSalt is a fixed, application-specific salt for the HKDF extract step. A
// salt need not be secret; binding it to this application domain keeps DEKs
// derived here from colliding with keys any other system might derive from the
// same master bytes. It must never change or previously sealed data won't open.
var hkdfSalt = []byte("shieldnet-access/kms/v1")

// NewDerivedDEKKeyManager builds a DerivedDEKKeyManager from a base64-encoded
// 32-byte master key (ACCESS_KMS_MASTER_KEY) and the current key version (the
// version new writes seal under; must be >= 1). An empty or malformed key is a
// hard error so a misconfigured deployment fails closed at boot rather than
// silently downgrading.
func NewDerivedDEKKeyManager(base64Master string, currentVersion int) (*DerivedDEKKeyManager, error) {
	if base64Master == "" {
		return nil, fmt.Errorf("access: DerivedDEKKeyManager: master key is required")
	}
	master, err := base64.StdEncoding.DecodeString(base64Master)
	if err != nil {
		return nil, fmt.Errorf("access: DerivedDEKKeyManager: decode master key: %w", err)
	}
	if len(master) != 32 {
		return nil, fmt.Errorf("access: DerivedDEKKeyManager: master key must be 32 bytes (got %d)", len(master))
	}
	if currentVersion < 1 {
		return nil, fmt.Errorf("access: DerivedDEKKeyManager: currentVersion must be >= 1 (got %d)", currentVersion)
	}
	return &DerivedDEKKeyManager{master: master, currentVersion: currentVersion}, nil
}

// GetLatestOrgDEK derives and returns the DEK for workspaceID at the manager's
// current key version. The version is returned so the caller persists it
// alongside the ciphertext for later decryption.
func (m *DerivedDEKKeyManager) GetLatestOrgDEK(_ context.Context, workspaceID string) ([]byte, int, error) {
	if workspaceID == "" {
		return nil, 0, fmt.Errorf("access: DerivedDEKKeyManager: workspaceID required")
	}
	dek, err := m.derive(workspaceID, m.currentVersion)
	if err != nil {
		return nil, 0, err
	}
	return dek, m.currentVersion, nil
}

// GetOrgDEK derives the DEK for a specific (workspaceID, keyVersion), so a row
// sealed under an older version still opens after the workspace's current
// version advances. A version outside [1, currentVersion] is rejected: a higher
// version cannot have sealed any existing row under this manager, and signals
// either corruption or data sealed by a differently-configured manager.
func (m *DerivedDEKKeyManager) GetOrgDEK(_ context.Context, workspaceID string, keyVersion int) ([]byte, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("access: DerivedDEKKeyManager: workspaceID required")
	}
	if keyVersion < 1 || keyVersion > m.currentVersion {
		return nil, fmt.Errorf("access: DerivedDEKKeyManager: key version %d out of range [1,%d]", keyVersion, m.currentVersion)
	}
	return m.derive(workspaceID, keyVersion)
}

// derive computes the per-(workspace,version) DEK via HKDF-SHA256. The version
// and workspace id are bound into the info parameter so each (workspace,
// version) pair yields an independent 32-byte key; changing either changes the
// key, which is exactly what gives per-tenant separation and clean rotation.
func (m *DerivedDEKKeyManager) derive(workspaceID string, version int) ([]byte, error) {
	info := []byte(fmt.Sprintf("dek/v%d/ws/%s", version, workspaceID))
	r := hkdf.New(sha256.New, m.master, hkdfSalt, info)
	dek := make([]byte, 32)
	if _, err := io.ReadFull(r, dek); err != nil {
		return nil, fmt.Errorf("access: DerivedDEKKeyManager: derive DEK (workspace=%s, version=%d): %w", workspaceID, version, err)
	}
	return dek, nil
}

// NewDerivedEnvelopeEncryptor is the convenience constructor for the
// per-workspace deployment: a DerivedDEKKeyManager wrapped in an
// EnvelopeEncryptor. base64Master is ACCESS_KMS_MASTER_KEY; currentVersion is
// ACCESS_KMS_KEY_VERSION.
func NewDerivedEnvelopeEncryptor(base64Master string, currentVersion int) (CredentialEncryptor, error) {
	km, err := NewDerivedDEKKeyManager(base64Master, currentVersion)
	if err != nil {
		return nil, err
	}
	return NewEnvelopeEncryptor(km)
}

// CredentialEncryptorFromConfig builds the production CredentialEncryptor from
// configuration, choosing the strongest configured key strategy:
//
//   - masterKey set  -> per-workspace DerivedDEKKeyManager (preferred).
//   - else staticDEK set -> single-key StaticDEKKeyManager (back-compat).
//   - else neither   -> fail-closed DisabledEncryptor (refuses to persist
//     plaintext rather than silently downgrading).
//
// A non-empty but malformed key (either kind) is a hard error so the caller
// aborts boot. This is the single helper binaries should call; it supersedes
// CredentialEncryptorFromKey, which remains for callers that only ever used the
// static DEK.
func CredentialEncryptorFromConfig(masterKey string, keyVersion int, staticDEK string) (CredentialEncryptor, error) {
	if masterKey != "" {
		return NewDerivedEnvelopeEncryptor(masterKey, keyVersion)
	}
	if staticDEK != "" {
		return NewStaticEnvelopeEncryptor(staticDEK)
	}
	return NewDisabledEncryptor(), nil
}
