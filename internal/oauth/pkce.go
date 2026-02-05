package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// ValidatePKCE verifies that base64url(sha256(verifier)) == challenge.
func ValidatePKCE(verifier, challenge string) bool {
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}
