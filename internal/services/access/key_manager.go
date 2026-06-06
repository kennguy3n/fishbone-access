package access

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
)

// KeyManager resolves per-workspace data-encryption keys (DEKs) for envelope
// encryption. It is the single pluggable seam between ShieldNet Access and a
// key-management backend: the StaticDEKKeyManager below serves one process-wide
// DEK from configuration, and a future AWS KMS / Vault implementation can
// satisfy the same interface to deliver true per-workspace keys with rotation —
// without the service layer changing.
//
// DEKs returned here are raw 32-byte AES-256 keys. Callers MUST treat them as
// secret: never log, persist, or return them to clients, and zero them after
// use (the EnvelopeEncryptor does).
type KeyManager interface {
	// GetLatestOrgDEK returns the current DEK for workspaceID along with its
	// version. Encrypt uses this; the version is persisted alongside the
	// ciphertext so Decrypt can resolve the same key after a rotation.
	GetLatestOrgDEK(ctx context.Context, workspaceID string) (dek []byte, keyVersion int, err error)
	// GetOrgDEK returns the DEK for a specific (workspaceID, keyVersion),
	// used by Decrypt to open a row sealed under an older key.
	GetOrgDEK(ctx context.Context, workspaceID string, keyVersion int) (dek []byte, err error)
}

// StaticDEKKeyManager serves a single process-wide DEK (version 1) for every
// workspace, sourced from a base64-encoded 32-byte key (ACCESS_CREDENTIAL_DEK).
// It is the default KeyManager for single-key deployments; it provides no true
// per-workspace isolation or rotation, but it satisfies the KeyManager seam so
// a KMS-backed manager can be dropped in later with no service-layer changes.
type StaticDEKKeyManager struct {
	dek []byte
}

const staticDEKVersion = 1

// NewStaticDEKKeyManager builds a StaticDEKKeyManager from a base64-encoded
// 32-byte key. An empty key is an error: callers that want fail-closed
// behaviour wire NewDisabledEncryptor instead of constructing this with no key.
func NewStaticDEKKeyManager(base64Key string) (*StaticDEKKeyManager, error) {
	if base64Key == "" {
		return nil, fmt.Errorf("access: StaticDEKKeyManager: DEK is required")
	}
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("access: StaticDEKKeyManager: decode DEK: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("access: StaticDEKKeyManager: DEK must be 32 bytes (got %d)", len(key))
	}
	return &StaticDEKKeyManager{dek: key}, nil
}

// GetLatestOrgDEK returns a copy of the static DEK at version 1.
func (m *StaticDEKKeyManager) GetLatestOrgDEK(_ context.Context, workspaceID string) ([]byte, int, error) {
	if workspaceID == "" {
		return nil, 0, fmt.Errorf("access: StaticDEKKeyManager: workspaceID required")
	}
	return m.copyDEK(), staticDEKVersion, nil
}

// GetOrgDEK returns a copy of the static DEK for keyVersion 1. Any other
// version is rejected — the static manager has only ever sealed under v1, so a
// request for another version signals data sealed by a different KeyManager.
func (m *StaticDEKKeyManager) GetOrgDEK(_ context.Context, workspaceID string, keyVersion int) ([]byte, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("access: StaticDEKKeyManager: workspaceID required")
	}
	if keyVersion != staticDEKVersion {
		return nil, fmt.Errorf("access: StaticDEKKeyManager: unknown key version %d (only %d available)", keyVersion, staticDEKVersion)
	}
	return m.copyDEK(), nil
}

// copyDEK returns a fresh copy so a caller zeroing the returned slice (the
// EnvelopeEncryptor does) cannot wipe the manager's retained key.
func (m *StaticDEKKeyManager) copyDEK() []byte {
	out := make([]byte, len(m.dek))
	copy(out, m.dek)
	return out
}

// EnvelopeEncryptor is the production CredentialEncryptor. It implements
// per-workspace envelope encryption by routing every Encrypt/Decrypt through a
// KeyManager (which resolves the right per-workspace DEK on demand) and
// delegating the actual AES-256-GCM seal/open to the audited
// internal/pkg/crypto primitive. The plaintext DEK lives in memory only for the
// duration of a single cipher call and is zeroed immediately after.
type EnvelopeEncryptor struct {
	km KeyManager
}

// NewEnvelopeEncryptor wires an EnvelopeEncryptor to a KeyManager. The
// KeyManager is the only configuration point; the cipher primitives come from
// internal/pkg/crypto.
func NewEnvelopeEncryptor(km KeyManager) (*EnvelopeEncryptor, error) {
	if km == nil {
		return nil, fmt.Errorf("access: EnvelopeEncryptor: KeyManager is required")
	}
	return &EnvelopeEncryptor{km: km}, nil
}

// Encrypt resolves the latest DEK for workspaceID, seals plaintext under
// AES-256-GCM with aad bound as Additional Authenticated Data, and returns the
// ciphertext envelope plus the key version the caller must persist.
func (e *EnvelopeEncryptor) Encrypt(ctx context.Context, workspaceID string, plaintext []byte, aad []byte) ([]byte, int, error) {
	if e == nil || e.km == nil {
		return nil, 0, fmt.Errorf("access: EnvelopeEncryptor not initialised")
	}
	if workspaceID == "" {
		return nil, 0, fmt.Errorf("access: EnvelopeEncryptor: workspaceID required")
	}
	if len(aad) == 0 {
		return nil, 0, fmt.Errorf("access: EnvelopeEncryptor: aad required")
	}
	dek, keyVersion, err := e.km.GetLatestOrgDEK(ctx, workspaceID)
	if err != nil {
		return nil, 0, fmt.Errorf("access: EnvelopeEncryptor: resolve latest DEK (workspace=%s): %w", workspaceID, err)
	}
	defer zeroBytes(dek)
	enc, err := crypto.NewAESGCMEncryptor(base64.StdEncoding.EncodeToString(dek))
	if err != nil {
		return nil, 0, fmt.Errorf("access: EnvelopeEncryptor: build cipher (workspace=%s): %w", workspaceID, err)
	}
	sealed, err := enc.Seal(plaintext, aad)
	if err != nil {
		return nil, 0, fmt.Errorf("access: EnvelopeEncryptor: seal (workspace=%s): %w", workspaceID, err)
	}
	return []byte(sealed), keyVersion, nil
}

// Decrypt resolves the DEK for (workspaceID, keyVersion) and opens ciphertext
// under AES-256-GCM with aad as AAD. Routing through the persisted keyVersion
// (rather than always the latest DEK) is what makes the encryptor robust to DEK
// rotations: a row sealed under v1 still opens after the workspace rotates to
// v2.
func (e *EnvelopeEncryptor) Decrypt(ctx context.Context, workspaceID string, ciphertext []byte, aad []byte, keyVersion int) ([]byte, error) {
	if e == nil || e.km == nil {
		return nil, fmt.Errorf("access: EnvelopeEncryptor not initialised")
	}
	if workspaceID == "" {
		return nil, fmt.Errorf("access: EnvelopeEncryptor: workspaceID required")
	}
	if len(aad) == 0 {
		return nil, fmt.Errorf("access: EnvelopeEncryptor: aad required")
	}
	if keyVersion <= 0 {
		return nil, fmt.Errorf("access: EnvelopeEncryptor: keyVersion must be > 0 (got %d)", keyVersion)
	}
	dek, err := e.km.GetOrgDEK(ctx, workspaceID, keyVersion)
	if err != nil {
		return nil, fmt.Errorf("access: EnvelopeEncryptor: resolve DEK (workspace=%s, version=%d): %w", workspaceID, keyVersion, err)
	}
	defer zeroBytes(dek)
	enc, err := crypto.NewAESGCMEncryptor(base64.StdEncoding.EncodeToString(dek))
	if err != nil {
		return nil, fmt.Errorf("access: EnvelopeEncryptor: build cipher (workspace=%s): %w", workspaceID, err)
	}
	plaintext, err := enc.Open(string(ciphertext), aad)
	if err != nil {
		return nil, fmt.Errorf("access: EnvelopeEncryptor: open (workspace=%s, version=%d): %w", workspaceID, keyVersion, err)
	}
	return plaintext, nil
}

// NewStaticEnvelopeEncryptor is the convenience constructor for the default
// single-DEK deployment: a StaticDEKKeyManager wrapped in an EnvelopeEncryptor.
// base64Key is ACCESS_CREDENTIAL_DEK. When it is empty the caller should wire
// NewDisabledEncryptor (fail-closed) instead; this constructor errors rather
// than silently downgrading.
func NewStaticEnvelopeEncryptor(base64Key string) (CredentialEncryptor, error) {
	km, err := NewStaticDEKKeyManager(base64Key)
	if err != nil {
		return nil, err
	}
	return NewEnvelopeEncryptor(km)
}

// CredentialEncryptorFromKey is the boot helper binaries use to build the
// production CredentialEncryptor from configuration. An empty base64Key wires
// the fail-closed NewDisabledEncryptor (so a misconfigured deployment refuses to
// persist plaintext rather than silently downgrading); a non-empty key builds
// the static-DEK EnvelopeEncryptor. A malformed non-empty key is a hard error,
// so the caller aborts boot.
func CredentialEncryptorFromKey(base64Key string) (CredentialEncryptor, error) {
	if base64Key == "" {
		return NewDisabledEncryptor(), nil
	}
	return NewStaticEnvelopeEncryptor(base64Key)
}

// zeroBytes overwrites b with zeros. Used to wipe a plaintext DEK from memory as
// soon as the cipher call that needed it returns. The subtle import keeps this
// from being optimised away by future inlining (and documents intent).
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	// Touch via constant-time compare so the compiler cannot prove the writes
	// above are dead and elide them.
	_ = subtle.ConstantTimeCompare(b, b)
}
