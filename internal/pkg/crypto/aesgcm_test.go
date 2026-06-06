package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func newTestEncryptor(t *testing.T) *AESGCMEncryptor {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	enc, err := NewAESGCMEncryptor(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	return enc
}

func TestSealOpenRoundTrip(t *testing.T) {
	enc := newTestEncryptor(t)
	plain := []byte(`{"api_token":"super-secret"}`)
	aad := []byte("access_connectors:42")

	env, err := enc.Seal(plain, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := enc.Open(env, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch: %q != %q", got, plain)
	}
}

func TestOpenWithWrongAADFails(t *testing.T) {
	enc := newTestEncryptor(t)
	env, err := enc.Seal([]byte("secret"), []byte("row:1"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := enc.Open(env, []byte("row:2")); err == nil {
		t.Fatal("Open with mismatched AAD succeeded, want auth failure")
	}
}

func TestBadKeyLength(t *testing.T) {
	if _, err := NewAESGCMEncryptor(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("expected error for non-32-byte key")
	}
}

func TestPassthroughFailsClosed(t *testing.T) {
	enc, err := FromKey("")
	if err != nil {
		t.Fatalf("FromKey(\"\"): %v", err)
	}
	if _, err := enc.Seal([]byte("x"), nil); !errors.Is(err, ErrSecretsDisabled) {
		t.Fatalf("Seal err = %v, want ErrSecretsDisabled", err)
	}
	if _, err := enc.Open("x", nil); !errors.Is(err, ErrSecretsDisabled) {
		t.Fatalf("Open err = %v, want ErrSecretsDisabled", err)
	}
}

func TestFromKeyMalformedIsHardError(t *testing.T) {
	if _, err := FromKey("not-base64!!!"); err == nil {
		t.Fatal("FromKey with malformed key should error, not downgrade")
	}
}
