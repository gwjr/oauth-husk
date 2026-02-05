package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestTokenService_RoundTrip(t *testing.T) {
	ts, err := NewTokenService(testKey(t))
	if err != nil {
		t.Fatal(err)
	}

	token, claims, err := ts.GenerateAccessToken("test-client", "mcp:tools", 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if token == "" {
		t.Error("expected non-empty token")
	}
	if claims.Sub != "test-client" {
		t.Errorf("expected sub=test-client, got %s", claims.Sub)
	}
	if claims.Scope != "mcp:tools" {
		t.Errorf("expected scope=mcp:tools, got %s", claims.Scope)
	}

	validated, err := ts.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("validation error: %v", err)
	}
	if validated.JTI != claims.JTI {
		t.Errorf("jti mismatch: %s vs %s", validated.JTI, claims.JTI)
	}
	if validated.Sub != claims.Sub {
		t.Errorf("sub mismatch: %s vs %s", validated.Sub, claims.Sub)
	}
}

func TestTokenService_TamperedPayload(t *testing.T) {
	ts, err := NewTokenService(testKey(t))
	if err != nil {
		t.Fatal(err)
	}

	token, _, err := ts.GenerateAccessToken("test-client", "mcp:tools", 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the payload
	parts := strings.SplitN(token, ".", 2)
	tampered := base64.RawURLEncoding.EncodeToString([]byte(`{"jti":"fake","sub":"evil","iat":0,"exp":9999999999}`)) + "." + parts[1]

	if _, err := ts.ValidateAccessToken(tampered); err == nil {
		t.Error("expected validation to fail for tampered payload")
	}
}

func TestTokenService_TamperedSignature(t *testing.T) {
	ts, err := NewTokenService(testKey(t))
	if err != nil {
		t.Fatal(err)
	}

	token, _, err := ts.GenerateAccessToken("test-client", "mcp:tools", 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the signature
	parts := strings.SplitN(token, ".", 2)
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte("wrong-signature-data-here-padded"))

	if _, err := ts.ValidateAccessToken(tampered); err == nil {
		t.Error("expected validation to fail for tampered signature")
	}
}

func TestTokenService_Expired(t *testing.T) {
	ts, err := NewTokenService(testKey(t))
	if err != nil {
		t.Fatal(err)
	}

	// Use negative TTL to create an already-expired token
	token, _, err := ts.GenerateAccessToken("test-client", "mcp:tools", -1*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ts.ValidateAccessToken(token); err == nil {
		t.Error("expected validation to fail for expired token")
	}
}

func TestTokenService_ShortKey(t *testing.T) {
	shortKey := make([]byte, 16)
	if _, err := NewTokenService(shortKey); err == nil {
		t.Error("expected error for key shorter than 32 bytes")
	}
}

func TestTokenService_InvalidFormat(t *testing.T) {
	ts, err := NewTokenService(testKey(t))
	if err != nil {
		t.Fatal(err)
	}

	tests := []string{
		"",
		"no-dot-here",
		"too.many.dots",
		"valid-base64.!!!invalid!!!",
	}

	for _, tt := range tests {
		if _, err := ts.ValidateAccessToken(tt); err == nil {
			t.Errorf("expected validation to fail for %q", tt)
		}
	}
}

func TestGenerateRefreshToken(t *testing.T) {
	tok, err := GenerateRefreshToken()
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("not valid base64url: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(decoded))
	}
}
