// Package crypto provides authenticated encryption for connector secrets at
// rest. ShieldNet Access seals every connector credential blob with AES-256-GCM
// before it touches the database, binding each ciphertext to its owning row via
// Additional Authenticated Data (AAD) so a ciphertext copied to a different row
// fails to open.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Encryptor seals and opens connector secret blobs.
type Encryptor interface {
	// Seal encrypts plaintext, binding it to aad. The returned value is a
	// base64-encoded (nonce || ciphertext || tag) envelope.
	Seal(plaintext, aad []byte) (string, error)
	// Open reverses Seal. It fails if aad does not match the value passed to
	// Seal, or if the ciphertext was tampered with.
	Open(envelope string, aad []byte) ([]byte, error)
}

// ErrSecretsDisabled is returned by the passthrough encryptor's Seal/Open to
// make a missing ACCESS_CREDENTIAL_DEK a loud, fail-closed error rather than a
// silent plaintext write.
var ErrSecretsDisabled = errors.New("crypto: credential encryption disabled (ACCESS_CREDENTIAL_DEK unset)")

// AESGCMEncryptor is the production AES-256-GCM Encryptor.
type AESGCMEncryptor struct {
	aead cipher.AEAD
}

// NewAESGCMEncryptor builds an encryptor from a base64-encoded 32-byte key.
func NewAESGCMEncryptor(base64Key string) (*AESGCMEncryptor, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("crypto: decode DEK: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: DEK must be 32 bytes (got %d)", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new GCM: %w", err)
	}
	return &AESGCMEncryptor{aead: aead}, nil
}

// Seal implements Encryptor.
func (e *AESGCMEncryptor) Seal(plaintext, aad []byte) (string, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("crypto: read nonce: %w", err)
	}
	sealed := e.aead.Seal(nonce, nonce, plaintext, aad)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open implements Encryptor.
func (e *AESGCMEncryptor) Open(envelope string, aad []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(envelope)
	if err != nil {
		return nil, fmt.Errorf("crypto: decode envelope: %w", err)
	}
	ns := e.aead.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("crypto: envelope shorter than nonce")
	}
	nonce, ct := raw[:ns], raw[ns:]
	plaintext, err := e.aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: open: %w", err)
	}
	return plaintext, nil
}

// PassthroughEncryptor is wired when no DEK is configured. It refuses to seal
// or open so the platform fails closed instead of persisting plaintext secrets.
type PassthroughEncryptor struct{}

// Seal always errors.
func (PassthroughEncryptor) Seal([]byte, []byte) (string, error) {
	return "", ErrSecretsDisabled
}

// Open always errors.
func (PassthroughEncryptor) Open(string, []byte) ([]byte, error) {
	return nil, ErrSecretsDisabled
}

// FromKey returns the production encryptor when base64Key is non-empty, or the
// fail-closed passthrough when it is empty. A non-empty but malformed key is a
// hard error (the caller should abort boot rather than silently downgrade).
func FromKey(base64Key string) (Encryptor, error) {
	if base64Key == "" {
		return PassthroughEncryptor{}, nil
	}
	return NewAESGCMEncryptor(base64Key)
}

// IsPassthrough reports whether enc is the fail-closed PassthroughEncryptor.
// Boot helpers for binaries that MUST be able to open connector secrets (the
// connector worker, the workflow engine) use this to refuse to start under the
// no-op encryptor. It matches both the value and pointer forms so the gate is
// robust to how the type is constructed.
func IsPassthrough(enc Encryptor) bool {
	switch enc.(type) {
	case PassthroughEncryptor, *PassthroughEncryptor:
		return true
	default:
		return false
	}
}
