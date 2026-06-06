package iamcore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"

	"github.com/kennguy3n/fishbone-access/internal/config"
)

const testKID = "test-key-1"

// jwksServer builds an httptest server that serves a JWKS containing the public
// half of key, then returns a Validator wired to it. This exercises the real
// JWKS-fetch path (keyfunc.NewDefaultCtx) rather than a mock keyfunc.
func jwksServer(t *testing.T, key *rsa.PrivateKey, issuer, audience string) *Validator {
	t.Helper()
	jwks := map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"kid": testKID,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(bigEndianExponent(key.E)),
		}},
	}
	body, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	kf, err := keyfunc.NewDefaultCtx(context.Background(), []string{srv.URL})
	if err != nil {
		t.Fatalf("NewDefaultCtx: %v", err)
	}
	return newValidator(kf, issuer, audience)
}

func bigEndianExponent(e int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(e))
	// strip leading zero bytes
	i := 0
	for i < len(b)-1 && b[i] == 0 {
		i++
	}
	return b[i:]
}

func signToken(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = testKID
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func TestValidateHappyPath(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	v := jwksServer(t, key, "https://iam.example.com", "shieldnet-access")

	tokenStr := signToken(t, key, jwt.MapClaims{
		"iss":       "https://iam.example.com",
		"aud":       "shieldnet-access",
		"sub":       "user-123",
		"tenant_id": "tenant-abc",
		"roles":     []any{"admin", "auditor"},
		"scope":     "access:read access:write",
		"amr":       []any{"pwd", "otp"},
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
	})

	claims, err := v.Validate(tokenStr)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Errorf("Subject = %q", claims.Subject)
	}
	if claims.TenantID != "tenant-abc" {
		t.Errorf("TenantID = %q", claims.TenantID)
	}
	if len(claims.Roles) != 2 || claims.Roles[0] != "admin" {
		t.Errorf("Roles = %v", claims.Roles)
	}
	if len(claims.Scopes) != 2 || claims.Scopes[1] != "access:write" {
		t.Errorf("Scopes = %v", claims.Scopes)
	}
	if !claims.MFASatisfied {
		t.Error("MFASatisfied = false, want true (amr contains otp)")
	}
}

func TestValidateRejectsWrongAudience(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := jwksServer(t, key, "https://iam.example.com", "shieldnet-access")
	tokenStr := signToken(t, key, jwt.MapClaims{
		"iss": "https://iam.example.com",
		"aud": "some-other-app",
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := v.Validate(tokenStr); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken for wrong aud", err)
	}
}

func TestValidateRejectsExpired(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := jwksServer(t, key, "https://iam.example.com", "")
	tokenStr := signToken(t, key, jwt.MapClaims{
		"iss": "https://iam.example.com",
		"sub": "user-1",
		"exp": time.Now().Add(-time.Minute).Unix(),
	})
	if _, err := v.Validate(tokenStr); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken for expired token", err)
	}
}

func TestValidateRejectsBadSignature(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := jwksServer(t, key, "https://iam.example.com", "")

	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokenStr := signToken(t, otherKey, jwt.MapClaims{
		"iss": "https://iam.example.com",
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := v.Validate(tokenStr); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken for bad signature", err)
	}
}

func TestValidateRejectsMissingSub(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := jwksServer(t, key, "https://iam.example.com", "")
	tokenStr := signToken(t, key, jwt.MapClaims{
		"iss": "https://iam.example.com",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := v.Validate(tokenStr); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken for missing sub", err)
	}
}

func TestNewValidatorUnconfigured(t *testing.T) {
	if _, err := NewValidator(context.Background(), config.IAMCoreConfig{}); err == nil {
		t.Fatal("NewValidator with empty config should error")
	}
}
