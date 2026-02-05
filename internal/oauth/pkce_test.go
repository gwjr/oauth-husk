package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestValidatePKCE_KnownPair(t *testing.T) {
	// RFC 7636 Appendix B example verifier
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	if !ValidatePKCE(verifier, challenge) {
		t.Errorf("expected PKCE to validate for known verifier/challenge pair")
	}
}

func TestValidatePKCE_WrongVerifier(t *testing.T) {
	verifier := "correct-verifier-value"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	if ValidatePKCE("wrong-verifier-value", challenge) {
		t.Errorf("expected PKCE to fail for wrong verifier")
	}
}

func TestValidatePKCE_NoPadding(t *testing.T) {
	// Ensure base64url encoding without padding works
	verifier := "test-verifier-that-produces-padding"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Challenge should not contain padding characters
	for _, c := range challenge {
		if c == '=' {
			t.Errorf("challenge contains padding character '='")
		}
	}

	if !ValidatePKCE(verifier, challenge) {
		t.Errorf("expected PKCE to validate")
	}
}

func TestGenerateAuthCode(t *testing.T) {
	code, err := GenerateAuthCode()
	if err != nil {
		t.Fatalf("GenerateAuthCode error: %v", err)
	}
	if code == "" {
		t.Error("expected non-empty auth code")
	}

	// Should be base64url-encoded 32 bytes = 43 chars (no padding)
	decoded, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil {
		t.Fatalf("auth code is not valid base64url: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(decoded))
	}

	// Two codes should be different
	code2, _ := GenerateAuthCode()
	if code == code2 {
		t.Error("two generated codes should not be identical")
	}
}
