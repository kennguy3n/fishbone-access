package access

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	pkgcrypto "github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
)

// testMasterKey returns a fresh base64-encoded 32-byte master key.
func testMasterKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func TestNewDerivedDEKKeyManagerValidation(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		version int
		wantErr bool
	}{
		{"empty key", "", 1, true},
		{"not base64", "!!!not-base64!!!", 1, true},
		{"too short", base64.StdEncoding.EncodeToString(make([]byte, 16)), 1, true},
		{"too long", base64.StdEncoding.EncodeToString(make([]byte, 64)), 1, true},
		{"version zero", base64.StdEncoding.EncodeToString(make([]byte, 32)), 0, true},
		{"version negative", base64.StdEncoding.EncodeToString(make([]byte, 32)), -3, true},
		{"valid", base64.StdEncoding.EncodeToString(make([]byte, 32)), 1, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewDerivedDEKKeyManager(tc.key, tc.version)
			if tc.wantErr != (err != nil) {
				t.Fatalf("NewDerivedDEKKeyManager(%q,%d) err=%v, wantErr=%v", tc.key, tc.version, err, tc.wantErr)
			}
		})
	}
}

// TestDerivedDEKPerWorkspaceIsolation is the core P0-2 property: every
// workspace gets a distinct DEK, while the same (workspace, version) is
// deterministic so a row sealed earlier still opens.
func TestDerivedDEKPerWorkspaceIsolation(t *testing.T) {
	km, err := NewDerivedDEKKeyManager(testMasterKey(t), 1)
	if err != nil {
		t.Fatalf("NewDerivedDEKKeyManager: %v", err)
	}
	ctx := context.Background()

	dekA, vA, err := km.GetLatestOrgDEK(ctx, "workspace-a")
	if err != nil {
		t.Fatalf("GetLatestOrgDEK(a): %v", err)
	}
	dekB, _, err := km.GetLatestOrgDEK(ctx, "workspace-b")
	if err != nil {
		t.Fatalf("GetLatestOrgDEK(b): %v", err)
	}
	if vA != 1 {
		t.Errorf("latest version = %d, want 1", vA)
	}
	if len(dekA) != 32 {
		t.Errorf("DEK length = %d, want 32", len(dekA))
	}
	if bytes.Equal(dekA, dekB) {
		t.Fatal("two workspaces derived the SAME DEK; per-workspace isolation broken")
	}

	// Determinism: re-deriving the same workspace's DEK yields identical bytes.
	dekA2, err := km.GetOrgDEK(ctx, "workspace-a", 1)
	if err != nil {
		t.Fatalf("GetOrgDEK(a,1): %v", err)
	}
	if !bytes.Equal(dekA, dekA2) {
		t.Fatal("same (workspace,version) derived different DEKs; not deterministic")
	}
}

// TestDerivedDEKMasterKeyChangesAllDEKs proves DEKs are bound to the master key:
// a different master yields a different DEK for the same workspace.
func TestDerivedDEKMasterKeyChangesAllDEKs(t *testing.T) {
	ctx := context.Background()
	km1, err := NewDerivedDEKKeyManager(testMasterKey(t), 1)
	if err != nil {
		t.Fatalf("km1: %v", err)
	}
	km2, err := NewDerivedDEKKeyManager(testMasterKey(t), 1)
	if err != nil {
		t.Fatalf("km2: %v", err)
	}
	d1, _, err := km1.GetLatestOrgDEK(ctx, "ws")
	if err != nil {
		t.Fatalf("km1 dek: %v", err)
	}
	d2, _, err := km2.GetLatestOrgDEK(ctx, "ws")
	if err != nil {
		t.Fatalf("km2 dek: %v", err)
	}
	if bytes.Equal(d1, d2) {
		t.Fatal("different master keys produced the same DEK")
	}
}

// TestDerivedDEKVersionRotation proves the version dimension: a higher current
// version derives a different DEK than v1 for the same workspace, older
// versions remain derivable, and out-of-range versions are rejected.
func TestDerivedDEKVersionRotation(t *testing.T) {
	master := testMasterKey(t)
	ctx := context.Background()

	v1mgr, err := NewDerivedDEKKeyManager(master, 1)
	if err != nil {
		t.Fatalf("v1mgr: %v", err)
	}
	v2mgr, err := NewDerivedDEKKeyManager(master, 2)
	if err != nil {
		t.Fatalf("v2mgr: %v", err)
	}

	dekV1, _, err := v1mgr.GetLatestOrgDEK(ctx, "ws")
	if err != nil {
		t.Fatalf("v1 latest: %v", err)
	}
	dekV2, ver, err := v2mgr.GetLatestOrgDEK(ctx, "ws")
	if err != nil {
		t.Fatalf("v2 latest: %v", err)
	}
	if ver != 2 {
		t.Errorf("v2 manager latest version = %d, want 2", ver)
	}
	if bytes.Equal(dekV1, dekV2) {
		t.Fatal("v1 and v2 DEKs are identical; rotation derives no new key")
	}

	// The v2 manager can still derive the v1 DEK for old rows, identically to v1mgr.
	oldFromV2, err := v2mgr.GetOrgDEK(ctx, "ws", 1)
	if err != nil {
		t.Fatalf("v2mgr GetOrgDEK(ws,1): %v", err)
	}
	if !bytes.Equal(oldFromV2, dekV1) {
		t.Fatal("v2 manager derived a different v1 DEK than v1 manager; old rows would not open")
	}

	// Out-of-range versions are rejected.
	if _, err := v2mgr.GetOrgDEK(ctx, "ws", 3); err == nil {
		t.Error("GetOrgDEK with version above current should error")
	}
	if _, err := v2mgr.GetOrgDEK(ctx, "ws", 0); err == nil {
		t.Error("GetOrgDEK with version 0 should error")
	}
	if _, _, err := v1mgr.GetLatestOrgDEK(ctx, ""); err == nil {
		t.Error("GetLatestOrgDEK with empty workspace should error")
	}
}

// TestDerivedEnvelopeRoundTrip proves an end-to-end seal/open through the
// EnvelopeEncryptor on top of the derived manager.
func TestDerivedEnvelopeRoundTrip(t *testing.T) {
	enc, err := NewDerivedEnvelopeEncryptor(testMasterKey(t), 1)
	if err != nil {
		t.Fatalf("NewDerivedEnvelopeEncryptor: %v", err)
	}
	ctx := context.Background()
	plaintext := []byte(`{"client_secret":"s3cr3t"}`)
	aad := []byte("connector:okta:42")

	ct, kv, err := enc.Encrypt(ctx, "ws-1", plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if kv != 1 {
		t.Errorf("keyVersion = %d, want 1", kv)
	}
	if bytes.Contains(ct, plaintext) {
		t.Fatal("ciphertext contains plaintext; not encrypted")
	}
	out, err := enc.Decrypt(ctx, "ws-1", ct, aad, kv)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Errorf("Decrypt = %q, want %q", out, plaintext)
	}
}

// TestDerivedEnvelopeCrossWorkspaceCannotOpen is the security guarantee that
// motivates P0-2: a secret sealed for workspace A cannot be opened under
// workspace B — even with identical AAD and key version — because each
// workspace's DEK is independently derived. With the old StaticDEKKeyManager
// (one DEK for all tenants) this open would SUCCEED.
func TestDerivedEnvelopeCrossWorkspaceCannotOpen(t *testing.T) {
	enc, err := NewDerivedEnvelopeEncryptor(testMasterKey(t), 1)
	if err != nil {
		t.Fatalf("NewDerivedEnvelopeEncryptor: %v", err)
	}
	ctx := context.Background()
	plaintext := []byte("tenant-a-only")
	aad := []byte("connector:github:1")

	ct, kv, err := enc.Encrypt(ctx, "workspace-a", plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt(a): %v", err)
	}
	if _, err := enc.Decrypt(ctx, "workspace-b", ct, aad, kv); err == nil {
		t.Fatal("workspace B opened workspace A's ciphertext; per-tenant key isolation is broken")
	}
	// Sanity: the owning workspace still opens it.
	if _, err := enc.Decrypt(ctx, "workspace-a", ct, aad, kv); err != nil {
		t.Fatalf("owning workspace failed to open its own ciphertext: %v", err)
	}
}

// TestDerivedEnvelopeOpensRowSealedUnderOldVersion proves rotation robustness
// at the envelope layer: a row sealed by a v1-current manager still opens via a
// v2-current manager when the persisted key version (1) is supplied.
func TestDerivedEnvelopeOpensRowSealedUnderOldVersion(t *testing.T) {
	master := testMasterKey(t)
	ctx := context.Background()
	aad := []byte("connector:aws:7")
	plaintext := []byte("rotate-me")

	v1enc, err := NewDerivedEnvelopeEncryptor(master, 1)
	if err != nil {
		t.Fatalf("v1enc: %v", err)
	}
	ct, kv, err := v1enc.Encrypt(ctx, "ws", plaintext, aad)
	if err != nil {
		t.Fatalf("v1 Encrypt: %v", err)
	}
	if kv != 1 {
		t.Fatalf("sealed version = %d, want 1", kv)
	}

	// Operator rotates: current version is now 2. New writes seal under v2, but
	// the old row (persisted kv=1) must still open.
	v2enc, err := NewDerivedEnvelopeEncryptor(master, 2)
	if err != nil {
		t.Fatalf("v2enc: %v", err)
	}
	out, err := v2enc.Decrypt(ctx, "ws", ct, aad, kv)
	if err != nil {
		t.Fatalf("v2 manager failed to open v1 row: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Errorf("Decrypt = %q, want %q", out, plaintext)
	}

	// A fresh seal under v2 records version 2.
	_, kv2, err := v2enc.Encrypt(ctx, "ws", plaintext, aad)
	if err != nil {
		t.Fatalf("v2 Encrypt: %v", err)
	}
	if kv2 != 2 {
		t.Errorf("new seal version = %d, want 2", kv2)
	}
}

// TestCredentialEncryptorFromConfigPrecedence locks the boot precedence:
// master key -> per-workspace derived; else static DEK -> single key; else
// fail-closed disabled encryptor.
func TestCredentialEncryptorFromConfigPrecedence(t *testing.T) {
	ctx := context.Background()
	aad := []byte("aad")

	t.Run("master key yields per-workspace isolation", func(t *testing.T) {
		enc, err := CredentialEncryptorFromConfig(testMasterKey(t), 1, "")
		if err != nil {
			t.Fatalf("FromConfig(master): %v", err)
		}
		ct, kv, err := enc.Encrypt(ctx, "ws-a", []byte("x"), aad)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		// Derived manager => other workspace cannot open it.
		if _, err := enc.Decrypt(ctx, "ws-b", ct, aad, kv); err == nil {
			t.Fatal("master-key encryptor is not per-workspace (ws-b opened ws-a's row)")
		}
	})

	t.Run("master key preferred over static DEK", func(t *testing.T) {
		master := testMasterKey(t)
		enc, err := CredentialEncryptorFromConfig(master, 1, testDEK(t))
		if err != nil {
			t.Fatalf("FromConfig(master+dek): %v", err)
		}
		ct, kv, err := enc.Encrypt(ctx, "ws-a", []byte("x"), aad)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		// If the static DEK had won, ws-b would open this (one key for all).
		if _, err := enc.Decrypt(ctx, "ws-b", ct, aad, kv); err == nil {
			t.Fatal("static DEK took precedence over master key")
		}
	})

	t.Run("static DEK only", func(t *testing.T) {
		enc, err := CredentialEncryptorFromConfig("", 1, testDEK(t))
		if err != nil {
			t.Fatalf("FromConfig(dek): %v", err)
		}
		if IsPassthroughEncryptor(enc) {
			t.Fatal("static DEK config wrongly produced a passthrough encryptor")
		}
		ct, kv, err := enc.Encrypt(ctx, "ws-a", []byte("x"), aad)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		// Static manager => one DEK for all workspaces, so ws-b opens it.
		if _, err := enc.Decrypt(ctx, "ws-b", ct, aad, kv); err != nil {
			t.Fatalf("static DEK should share one key across workspaces: %v", err)
		}
	})

	t.Run("neither yields fail-closed", func(t *testing.T) {
		enc, err := CredentialEncryptorFromConfig("", 1, "")
		if err != nil {
			t.Fatalf("FromConfig(none): %v", err)
		}
		if _, _, err := enc.Encrypt(ctx, "ws", []byte("x"), aad); !errors.Is(err, ErrSecretsDisabled) {
			t.Fatalf("Encrypt err = %v, want ErrSecretsDisabled", err)
		}
	})

	t.Run("malformed master key is a hard error", func(t *testing.T) {
		if _, err := CredentialEncryptorFromConfig("!!notb64!!", 1, ""); err == nil {
			t.Fatal("malformed master key should error, not silently downgrade")
		}
	})
}

// TestCryptoEncryptorFromConfig covers the process-wide (non-per-workspace)
// crypto.Encryptor used for TOTP step-up MFA. It must mirror the connector
// path's precedence so one master key roots all at-rest encryption, fixing the
// review finding where a KMS-only deployment silently lost MFA.
func TestCryptoEncryptorFromConfig(t *testing.T) {
	master := testMasterKey(t)
	aad := []byte("totp:user-1")
	pt := []byte("totp-shared-secret")

	t.Run("master key only seals and opens (MFA works under KMS-only)", func(t *testing.T) {
		enc, err := CryptoEncryptorFromConfig(master, "")
		if err != nil {
			t.Fatalf("CryptoEncryptorFromConfig(master): %v", err)
		}
		env, err := enc.Seal(pt, aad)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		got, err := enc.Open(env, aad)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("Open = %q, want %q", got, pt)
		}
	})

	t.Run("derived TOTP key differs from any per-workspace DEK", func(t *testing.T) {
		// The service key is derived under a distinct "svc/" info domain, so it
		// must never equal a per-workspace DEK derived from the same master.
		svcKey, err := deriveServiceKey(master, "totp-mfa")
		if err != nil {
			t.Fatalf("deriveServiceKey: %v", err)
		}
		km, err := NewDerivedDEKKeyManager(master, 1)
		if err != nil {
			t.Fatalf("NewDerivedDEKKeyManager: %v", err)
		}
		dek, _, err := km.GetLatestOrgDEK(context.Background(), "totp-mfa")
		if err != nil {
			t.Fatalf("GetLatestOrgDEK: %v", err)
		}
		if bytes.Equal(svcKey, dek) {
			t.Fatal("service key collided with a per-workspace DEK; HKDF info domains overlap")
		}
	})

	t.Run("master key takes precedence over static DEK", func(t *testing.T) {
		// Seal under master-only, then confirm a DEK-only encryptor (the static
		// fallback) cannot open it — proving the master path is actually used
		// when both are present.
		masterEnc, err := CryptoEncryptorFromConfig(master, "")
		if err != nil {
			t.Fatalf("FromConfig(master): %v", err)
		}
		env, err := masterEnc.Seal(pt, aad)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		dekEnc, err := CryptoEncryptorFromConfig("", testDEK(t))
		if err != nil {
			t.Fatalf("FromConfig(dek): %v", err)
		}
		if _, err := dekEnc.Open(env, aad); err == nil {
			t.Fatal("static DEK opened a master-sealed envelope; precedence is wrong")
		}
	})

	t.Run("static DEK only seals and opens (back-compat)", func(t *testing.T) {
		enc, err := CryptoEncryptorFromConfig("", testDEK(t))
		if err != nil {
			t.Fatalf("FromConfig(dek): %v", err)
		}
		env, err := enc.Seal(pt, aad)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if _, err := enc.Open(env, aad); err != nil {
			t.Fatalf("Open: %v", err)
		}
	})

	t.Run("neither set fails closed", func(t *testing.T) {
		enc, err := CryptoEncryptorFromConfig("", "")
		if err != nil {
			t.Fatalf("FromConfig(none): %v", err)
		}
		// The crypto-path passthrough returns crypto.ErrSecretsDisabled (distinct
		// from the access package's own ErrSecretsDisabled used by the
		// KeyManager/EnvelopeEncryptor path).
		if _, err := enc.Seal(pt, aad); !errors.Is(err, pkgcrypto.ErrSecretsDisabled) {
			t.Fatalf("Seal err = %v, want crypto.ErrSecretsDisabled", err)
		}
	})

	t.Run("malformed master key is a hard error", func(t *testing.T) {
		if _, err := CryptoEncryptorFromConfig("!!notb64!!", ""); err == nil {
			t.Fatal("malformed master key should error, not silently downgrade")
		}
	})
}
