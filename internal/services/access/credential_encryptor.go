package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// CredentialEncryptor is the narrow contract the connector-management and
// worker layers use to seal connector secrets before they touch
// access_connectors.secret_envelope, and to open them again just before a
// provider API call. The service layer depends only on this interface so it
// never imports crypto primitives directly: cmd/ztna-api and
// cmd/access-connector-worker wire the production encryptor in at boot.
//
// (ctx, workspaceID) carry the per-request tenant identity through to the
// underlying KeyManager so envelope encryption can resolve the right
// per-workspace DEK. Implementations backed by a single static key ignore both
// arguments.
//
// aad is the access_connectors.ID (bound as AES-GCM Additional Authenticated
// Data) so a ciphertext copied to a different row fails to open. keyVersion is
// returned by Encrypt so the caller can persist it alongside the ciphertext and
// resolve the same DEK on Decrypt across key rotations.
type CredentialEncryptor interface {
	Encrypt(ctx context.Context, workspaceID string, plaintext []byte, aad []byte) (ciphertext []byte, keyVersion int, err error)
	Decrypt(ctx context.Context, workspaceID string, ciphertext []byte, aad []byte, keyVersion int) (plaintext []byte, err error)
}

// ErrSecretsDisabled is returned by the fail-closed encryptor wired when no DEK
// is configured, so a missing key is a loud error rather than a silent
// plaintext write.
var ErrSecretsDisabled = errors.New("access: credential encryption disabled (no DEK configured)")

// disabledEncryptor is wired in production when ACCESS_CREDENTIAL_DEK is unset.
// It refuses to seal or open so the platform fails closed instead of persisting
// plaintext connector secrets.
type disabledEncryptor struct{}

func (disabledEncryptor) Encrypt(context.Context, string, []byte, []byte) ([]byte, int, error) {
	return nil, 0, ErrSecretsDisabled
}

func (disabledEncryptor) Decrypt(context.Context, string, []byte, []byte, int) ([]byte, error) {
	return nil, ErrSecretsDisabled
}

// NewDisabledEncryptor returns the fail-closed CredentialEncryptor used when no
// DEK is configured. Exported so binaries can wire it explicitly.
func NewDisabledEncryptor() CredentialEncryptor { return disabledEncryptor{} }

// PassthroughEncryptor is the test-only CredentialEncryptor that returns
// plaintext verbatim. It is NOT a mock: it implements the real interface
// contract end-to-end (its semantics are simply the identity function) so tests
// exercise the same encrypt/decrypt call sites production uses without needing
// a real DEK. Production must never wire it — IsPassthroughEncryptor gates the
// paths that would otherwise persist plaintext.
type PassthroughEncryptor struct{}

// Encrypt returns a defensive copy of plaintext and keyVersion=1.
func (PassthroughEncryptor) Encrypt(_ context.Context, _ string, plaintext []byte, aad []byte) ([]byte, int, error) {
	if len(aad) == 0 {
		return nil, 0, fmt.Errorf("access: credential encryptor: aad is required")
	}
	out := make([]byte, len(plaintext))
	copy(out, plaintext)
	return out, 1, nil
}

// Decrypt returns a defensive copy of ciphertext. keyVersion is ignored.
func (PassthroughEncryptor) Decrypt(_ context.Context, _ string, ciphertext []byte, aad []byte, _ int) ([]byte, error) {
	if len(aad) == 0 {
		return nil, fmt.Errorf("access: credential encryptor: aad is required")
	}
	out := make([]byte, len(ciphertext))
	copy(out, ciphertext)
	return out, nil
}

// IsPassthroughEncryptor reports whether enc is the test-only
// PassthroughEncryptor. Production boot helpers use this to refuse to start
// features that MUST NOT run under the no-op encryptor. It matches both the
// value and pointer forms so the gate is robust to how the type is constructed.
func IsPassthroughEncryptor(enc CredentialEncryptor) bool {
	switch enc.(type) {
	case PassthroughEncryptor, *PassthroughEncryptor:
		return true
	default:
		return false
	}
}

// encryptSecretsMap marshals secrets to JSON and seals them via enc, returning
// the (ciphertext, keyVersion) pair to persist on the access_connectors row.
// workspaceID is forwarded so envelope encryption resolves the per-workspace
// DEK; aad is the connector UUID, bound as AES-GCM AAD.
func encryptSecretsMap(ctx context.Context, enc CredentialEncryptor, workspaceID string, secrets map[string]interface{}, aad string) (string, int, error) {
	if enc == nil {
		return "", 0, fmt.Errorf("access: credential encryptor is required")
	}
	if aad == "" {
		return "", 0, fmt.Errorf("access: credential encryptor: aad is required")
	}
	plaintext, err := json.Marshal(secrets)
	if err != nil {
		return "", 0, fmt.Errorf("access: marshal secrets: %w", err)
	}
	ciphertext, kv, err := enc.Encrypt(ctx, workspaceID, plaintext, []byte(aad))
	if err != nil {
		return "", 0, fmt.Errorf("access: encrypt secrets: %w", err)
	}
	return string(ciphertext), kv, nil
}

// decryptSecretsMap opens a sealed envelope and unmarshals it back into a
// secrets map. It is the inverse of encryptSecretsMap and is the only path the
// service/worker layers use to recover plaintext secrets just before a provider
// call. A nil/empty envelope yields an empty map (a connector configured with
// no secrets), never an error.
func decryptSecretsMap(ctx context.Context, enc CredentialEncryptor, workspaceID, envelope, aad string, keyVersion int) (map[string]interface{}, error) {
	if enc == nil {
		return nil, fmt.Errorf("access: credential encryptor is required")
	}
	if envelope == "" {
		return map[string]interface{}{}, nil
	}
	if aad == "" {
		return nil, fmt.Errorf("access: credential encryptor: aad is required")
	}
	plaintext, err := enc.Decrypt(ctx, workspaceID, []byte(envelope), []byte(aad), keyVersion)
	if err != nil {
		return nil, fmt.Errorf("access: decrypt secrets: %w", err)
	}
	var secrets map[string]interface{}
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return nil, fmt.Errorf("access: unmarshal secrets: %w", err)
	}
	if secrets == nil {
		secrets = map[string]interface{}{}
	}
	return secrets, nil
}
