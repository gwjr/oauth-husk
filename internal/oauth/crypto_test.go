package oauth

import (
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestGenerateSecret(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		t.Fatalf("secret not base64url: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(raw))
	}
}

func TestHashSecret(t *testing.T) {
	hash, err := HashSecret("s3cr3t")
	if err != nil {
		t.Fatalf("HashSecret: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("s3cr3t")); err != nil {
		t.Fatal("expected hash to verify")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrong")); err == nil {
		t.Fatal("expected hash not to verify with wrong secret")
	}
}
