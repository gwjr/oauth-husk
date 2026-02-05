package oauth

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"
)

// GenerateSecret generates a 32-byte cryptographically random secret, base64url-encoded.
func GenerateSecret() (string, error) {
	return randomBase64(32)
}

// HashSecret hashes a client secret with bcrypt.
func HashSecret(secret string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// GenerateAuthCode generates a 32-byte cryptographically random code, base64url-encoded.
func GenerateAuthCode() (string, error) {
	return randomBase64(32)
}

// GenerateRefreshToken creates an opaque 32-byte random token, base64url-encoded.
func GenerateRefreshToken() (string, error) {
	return randomBase64(32)
}

func randomBase64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
