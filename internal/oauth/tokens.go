package oauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	AccessTokenTTL  = 24 * time.Hour
	RefreshTokenTTL = 30 * 24 * time.Hour
)

type TokenClaims struct {
	JTI   string `json:"jti"`
	Sub   string `json:"sub"`
	IAT   int64  `json:"iat"`
	EXP   int64  `json:"exp"`
	Scope string `json:"scope,omitempty"`
}

type TokenService struct {
	signingKey []byte
}

func NewTokenService(signingKey []byte) (*TokenService, error) {
	if len(signingKey) < 32 {
		return nil, fmt.Errorf("signing key must be at least 32 bytes (got %d)", len(signingKey))
	}
	return &TokenService{signingKey: signingKey}, nil
}

// GenerateAccessToken creates a signed access token: base64url(json).base64url(hmac).
func (ts *TokenService) GenerateAccessToken(clientID, scope string, ttl time.Duration) (string, *TokenClaims, error) {
	jti, err := randomBase64(16)
	if err != nil {
		return "", nil, fmt.Errorf("generating jti: %w", err)
	}

	now := time.Now()
	claims := &TokenClaims{
		JTI:   jti,
		Sub:   clientID,
		IAT:   now.Unix(),
		EXP:   now.Add(ttl).Unix(),
		Scope: scope,
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", nil, fmt.Errorf("marshaling claims: %w", err)
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sig := ts.sign([]byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	token := payloadB64 + "." + sigB64
	return token, claims, nil
}

// ValidateAccessToken verifies the token signature and checks expiry.
func (ts *TokenService) ValidateAccessToken(token string) (*TokenClaims, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	payloadB64 := parts[0]
	sigB64 := parts[1]

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding")
	}

	expected := ts.sign([]byte(payloadB64))
	if !hmac.Equal(sig, expected) {
		return nil, fmt.Errorf("invalid signature")
	}

	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding")
	}

	var claims TokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("invalid payload: %w", err)
	}

	if time.Now().Unix() > claims.EXP {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}

// GenerateRefreshToken creates an opaque 32-byte random token, base64url-encoded.
func GenerateRefreshToken() (string, error) {
	return randomBase64(32)
}

func (ts *TokenService) sign(data []byte) []byte {
	mac := hmac.New(sha256.New, ts.signingKey)
	mac.Write(data)
	return mac.Sum(nil)
}

func randomBase64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
