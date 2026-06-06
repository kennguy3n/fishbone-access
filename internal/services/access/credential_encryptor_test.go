package access

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func testDEK(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func TestPassthroughEncryptorRoundTrip(t *testing.T) {
	enc := PassthroughEncryptor{}
	ctx := context.Background()
	plaintext := []byte(`{"token":"abc"}`)

	ct, kv, err := enc.Encrypt(ctx, "ws-1", plaintext, []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if kv != 1 {
		t.Errorf("keyVersion = %d, want 1", kv)
	}
	// Mutating the returned ciphertext must not affect the source plaintext.
	ct[0] = 'X'
	if plaintext[0] == 'X' {
		t.Error("Encrypt returned a buffer aliased to the input plaintext")
	}

	out, err := enc.Decrypt(ctx, "ws-1", []byte(plaintext), []byte("aad"), 1)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Errorf("Decrypt = %q, want %q", out, plaintext)
	}
}

func TestPassthroughEncryptorRequiresAAD(t *testing.T) {
	enc := PassthroughEncryptor{}
	if _, _, err := enc.Encrypt(context.Background(), "ws", []byte("x"), nil); err == nil {
		t.Error("Encrypt with empty aad should error")
	}
	if _, err := enc.Decrypt(context.Background(), "ws", []byte("x"), nil, 1); err == nil {
		t.Error("Decrypt with empty aad should error")
	}
}

func TestIsPassthroughEncryptor(t *testing.T) {
	if !IsPassthroughEncryptor(PassthroughEncryptor{}) {
		t.Error("value form not detected")
	}
	if !IsPassthroughEncryptor(&PassthroughEncryptor{}) {
		t.Error("pointer form not detected")
	}
	env, err := NewStaticEnvelopeEncryptor(testDEK(t))
	if err != nil {
		t.Fatalf("NewStaticEnvelopeEncryptor: %v", err)
	}
	if IsPassthroughEncryptor(env) {
		t.Error("EnvelopeEncryptor wrongly detected as passthrough")
	}
	if IsPassthroughEncryptor(NewDisabledEncryptor()) {
		t.Error("disabledEncryptor wrongly detected as passthrough")
	}
}

func TestDisabledEncryptorFailsClosed(t *testing.T) {
	enc := NewDisabledEncryptor()
	if _, _, err := enc.Encrypt(context.Background(), "ws", []byte("x"), []byte("aad")); !errors.Is(err, ErrSecretsDisabled) {
		t.Errorf("Encrypt err = %v, want ErrSecretsDisabled", err)
	}
	if _, err := enc.Decrypt(context.Background(), "ws", []byte("x"), []byte("aad"), 1); !errors.Is(err, ErrSecretsDisabled) {
		t.Errorf("Decrypt err = %v, want ErrSecretsDisabled", err)
	}
}

func TestStaticDEKKeyManagerValidation(t *testing.T) {
	if _, err := NewStaticDEKKeyManager(""); err == nil {
		t.Error("empty key should error")
	}
	if _, err := NewStaticDEKKeyManager("not-base64!!"); err == nil {
		t.Error("bad base64 should error")
	}
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	if _, err := NewStaticDEKKeyManager(short); err == nil {
		t.Error("16-byte key should error (need 32)")
	}
}

func TestStaticDEKKeyManagerVersions(t *testing.T) {
	km, err := NewStaticDEKKeyManager(testDEK(t))
	if err != nil {
		t.Fatalf("NewStaticDEKKeyManager: %v", err)
	}
	ctx := context.Background()

	dek, kv, err := km.GetLatestOrgDEK(ctx, "ws-1")
	if err != nil {
		t.Fatalf("GetLatestOrgDEK: %v", err)
	}
	if kv != 1 || len(dek) != 32 {
		t.Fatalf("kv=%d len=%d, want kv=1 len=32", kv, len(dek))
	}
	// Zeroing the returned DEK must not corrupt the manager's retained copy.
	zeroBytes(dek)
	dek2, _, err := km.GetLatestOrgDEK(ctx, "ws-1")
	if err != nil {
		t.Fatalf("GetLatestOrgDEK 2: %v", err)
	}
	if bytes.Equal(dek2, make([]byte, 32)) {
		t.Error("manager DEK was zeroed by caller mutation")
	}

	if _, err := km.GetOrgDEK(ctx, "ws-1", 2); err == nil {
		t.Error("GetOrgDEK with unknown version should error")
	}
	if _, _, err := km.GetLatestOrgDEK(ctx, ""); err == nil {
		t.Error("empty workspace should error")
	}
}

func TestEnvelopeEncryptorRoundTrip(t *testing.T) {
	enc, err := NewStaticEnvelopeEncryptor(testDEK(t))
	if err != nil {
		t.Fatalf("NewStaticEnvelopeEncryptor: %v", err)
	}
	ctx := context.Background()
	plaintext := []byte(`{"client_secret":"s3cr3t"}`)
	aad := []byte("connector-uuid-1")

	ct, kv, err := enc.Encrypt(ctx, "ws-1", plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if kv != 1 {
		t.Errorf("keyVersion = %d, want 1", kv)
	}
	if bytes.Contains(ct, []byte("s3cr3t")) {
		t.Error("ciphertext contains plaintext secret")
	}

	out, err := enc.Decrypt(ctx, "ws-1", ct, aad, kv)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Errorf("Decrypt = %q, want %q", out, plaintext)
	}
}

func TestEnvelopeEncryptorAADBinding(t *testing.T) {
	enc, err := NewStaticEnvelopeEncryptor(testDEK(t))
	if err != nil {
		t.Fatalf("NewStaticEnvelopeEncryptor: %v", err)
	}
	ctx := context.Background()
	ct, kv, err := enc.Encrypt(ctx, "ws-1", []byte("secret"), []byte("connector-A"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// A ciphertext sealed for connector-A must not open under connector-B's
	// AAD, so a row copied to another connector fails closed.
	if _, err := enc.Decrypt(ctx, "ws-1", ct, []byte("connector-B"), kv); err == nil {
		t.Error("Decrypt under mismatched aad should fail")
	}
	if _, err := enc.Decrypt(ctx, "ws-1", ct, []byte("connector-A"), 2); err == nil {
		t.Error("Decrypt under unknown key version should fail")
	}
}

func TestEnvelopeEncryptorRejectsMissingArgs(t *testing.T) {
	enc, err := NewStaticEnvelopeEncryptor(testDEK(t))
	if err != nil {
		t.Fatalf("NewStaticEnvelopeEncryptor: %v", err)
	}
	ctx := context.Background()
	if _, _, err := enc.Encrypt(ctx, "", []byte("x"), []byte("aad")); err == nil {
		t.Error("Encrypt with empty workspace should error")
	}
	if _, _, err := enc.Encrypt(ctx, "ws", []byte("x"), nil); err == nil {
		t.Error("Encrypt with empty aad should error")
	}
	if _, err := enc.Decrypt(ctx, "ws", []byte("x"), []byte("aad"), 0); err == nil {
		t.Error("Decrypt with non-positive key version should error")
	}
}

func TestEncryptDecryptSecretsMap(t *testing.T) {
	enc, err := NewStaticEnvelopeEncryptor(testDEK(t))
	if err != nil {
		t.Fatalf("NewStaticEnvelopeEncryptor: %v", err)
	}
	ctx := context.Background()
	secrets := map[string]interface{}{"client_id": "id", "client_secret": "shh"}

	envelope, kv, err := encryptSecretsMap(ctx, enc, "ws-1", secrets, "connector-1")
	if err != nil {
		t.Fatalf("encryptSecretsMap: %v", err)
	}

	got, err := decryptSecretsMap(ctx, enc, "ws-1", envelope, "connector-1", kv)
	if err != nil {
		t.Fatalf("decryptSecretsMap: %v", err)
	}
	if got["client_id"] != "id" || got["client_secret"] != "shh" {
		t.Errorf("round-trip secrets = %v", got)
	}
}

func TestDecryptSecretsMapEmptyEnvelope(t *testing.T) {
	enc := PassthroughEncryptor{}
	got, err := decryptSecretsMap(context.Background(), enc, "ws", "", "connector-1", 1)
	if err != nil {
		t.Fatalf("decryptSecretsMap empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty envelope should yield empty map, got %v", got)
	}
}
