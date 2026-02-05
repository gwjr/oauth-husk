package oauth

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gwjr/oauth-husk/internal/database"
	"golang.org/x/crypto/bcrypt"
)

const (
	authCodeTTL = 120 * time.Second
	bcryptCost  = 12
)

// dummyBcryptHash is a valid bcrypt hash used for timing-safe comparison
// when the client_id is not found. Must use the same cost as real hashes
// to prevent timing-based client enumeration.
var dummyBcryptHash = func() []byte {
	hash, _ := bcrypt.GenerateFromPassword([]byte("oauth-husk-dummy-secret"), bcryptCost)
	return hash
}()

// Handlers holds dependencies for all OAuth HTTP handlers.
type Handlers struct {
	DB     *database.DB
	Tokens *TokenService
	Logger *slog.Logger
}

type authorizeRequest struct {
	clientID            string
	redirectURI         string
	responseType        string
	state               string
	codeChallenge       string
	codeChallengeMethod string
	scope               string
}

type tokenRequest struct {
	clientID     string
	clientSecret string
	code         string
	redirectURI  string
	codeVerifier string
}

func parseAuthorizeRequest(r *http.Request) authorizeRequest {
	q := r.URL.Query()
	return authorizeRequest{
		clientID:            q.Get("client_id"),
		redirectURI:         q.Get("redirect_uri"),
		responseType:        q.Get("response_type"),
		state:               q.Get("state"),
		codeChallenge:       q.Get("code_challenge"),
		codeChallengeMethod: q.Get("code_challenge_method"),
		scope:               q.Get("scope"),
	}
}

func parseTokenRequest(r *http.Request) tokenRequest {
	return tokenRequest{
		clientID:     r.FormValue("client_id"),
		clientSecret: r.FormValue("client_secret"),
		code:         r.FormValue("code"),
		redirectURI:  r.FormValue("redirect_uri"),
		codeVerifier: r.FormValue("code_verifier"),
	}
}

func validateRedirectURI(raw string) (string, error) {
	parsedRedirect, err := url.Parse(raw)
	if err != nil || parsedRedirect.Scheme != "https" || parsedRedirect.Host == "" {
		return "", fmt.Errorf("Invalid redirect URI: must use https")
	}
	if parsedRedirect.Fragment != "" {
		return "", fmt.Errorf("Invalid redirect URI: fragment not allowed")
	}
	return parsedRedirect.String(), nil
}

// baseURL derives the external base URL from the request headers.
// Caddy sets X-Forwarded-Host and X-Forwarded-Proto.
func baseURL(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "https"
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host
}

// ProtectedResourceMetadata handles GET /.well-known/oauth-protected-resource
func (h *Handlers) ProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	h.Logger.Info("discovery: protected resource metadata", "remote", r.RemoteAddr)
	base := baseURL(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":              base,
		"authorization_servers": []string{base},
	})
}

// AuthorizationServerMetadata handles GET /.well-known/oauth-authorization-server
func (h *Handlers) AuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	h.Logger.Info("discovery: authorization server metadata", "remote", r.RemoteAddr)
	base := baseURL(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/token",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
	})
}

// Authorize handles GET /authorize
func (h *Handlers) Authorize(w http.ResponseWriter, r *http.Request) {
	req := parseAuthorizeRequest(r)

	// Validate client_id
	client, err := h.DB.GetClient(req.clientID)
	if err != nil {
		h.Logger.Error("authorize: db error", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if client == nil {
		h.Logger.Warn("authorize: unknown client_id", "client_id", req.clientID)
		http.Error(w, "Unknown client", http.StatusUnauthorized)
		return
	}

	redirectFull, err := validateRedirectURI(req.redirectURI)
	if err != nil {
		h.Logger.Warn("authorize: invalid redirect_uri", "client_id", req.clientID, "redirect_uri", req.redirectURI)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate redirect_uri: exact match if locked; accept any valid HTTPS URI if unlocked.
	// Deliberate design choice: redirect_uri is locked on first successful token exchange
	// (not here), so that only a caller who presents the correct client_secret can lock it.
	// See tokenAuthorizationCode for the lock-on-first-use logic.
	if client.RedirectURI != "" && redirectFull != client.RedirectURI {
		h.Logger.Warn("authorize: redirect_uri mismatch", "client_id", req.clientID, "got", redirectFull, "want", client.RedirectURI)
		http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
		return
	}

	// From here on, errors redirect back to redirect_uri with error params
	redirectError := func(errCode, desc string) {
		u, _ := url.Parse(req.redirectURI)
		params := u.Query()
		params.Set("error", errCode)
		params.Set("error_description", desc)
		if req.state != "" {
			params.Set("state", req.state)
		}
		u.RawQuery = params.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	}

	if req.responseType != "code" {
		redirectError("unsupported_response_type", "Only 'code' response type is supported")
		return
	}
	if req.codeChallengeMethod != "S256" {
		redirectError("invalid_request", "Only S256 code_challenge_method is supported")
		return
	}
	if req.codeChallenge == "" {
		redirectError("invalid_request", "code_challenge is required")
		return
	}

	// Generate auth code
	code, err := GenerateAuthCode()
	if err != nil {
		h.Logger.Error("authorize: generating code", "error", err)
		redirectError("server_error", "Failed to generate authorization code")
		return
	}

	if err := h.DB.StoreAuthCode(code, req.clientID, req.redirectURI, req.codeChallenge, req.scope, authCodeTTL); err != nil {
		h.Logger.Error("authorize: storing code", "error", err)
		redirectError("server_error", "Failed to store authorization code")
		return
	}

	h.Logger.Info("authorize: code issued", "client_id", req.clientID, "scope", req.scope)

	// Redirect with code and state
	u, _ := url.Parse(req.redirectURI)
	params := u.Query()
	params.Set("code", code)
	if req.state != "" {
		params.Set("state", req.state)
	}
	u.RawQuery = params.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// Token handles POST /token
func (h *Handlers) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "Failed to parse form")
		return
	}

	grantType := r.FormValue("grant_type")
	switch grantType {
	case "authorization_code":
		h.tokenAuthorizationCode(w, r)
	case "refresh_token":
		h.tokenRefreshToken(w, r)
	default:
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "Unsupported grant type")
	}
}

func (h *Handlers) tokenAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	req := parseTokenRequest(r)

	// Validate client credentials
	client, err := h.DB.GetClient(req.clientID)
	if err != nil {
		h.Logger.Error("token: db error", "error", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "Internal error")
		return
	}
	if client == nil {
		bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(req.clientSecret))
		h.Logger.Warn("token: unknown client_id", "client_id", req.clientID)
		tokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(req.clientSecret)); err != nil {
		h.Logger.Warn("token: invalid client_secret", "client_id", req.clientID)
		tokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}

	// Look up auth code
	ac, err := h.DB.GetAuthCode(req.code)
	if err != nil {
		h.Logger.Error("token: db error looking up code", "error", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "Internal error")
		return
	}
	if ac == nil {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid authorization code")
		return
	}
	if ac.UsedAt != nil {
		// RFC 6749 §10.5: if a code is used more than once, revoke all tokens issued from it
		h.Logger.Warn("token: auth code replay detected — revoking all tokens from this code", "client_id", req.clientID)
		if n, err := h.DB.RevokeTokensByAuthCode(req.code); err != nil {
			h.Logger.Error("token: failed to revoke tokens on code replay", "error", err)
		} else if n > 0 {
			h.Logger.Warn("token: revoked tokens due to code replay", "client_id", req.clientID, "count", n)
		}
		tokenError(w, http.StatusBadRequest, "invalid_grant", "Authorization code already used")
		return
	}
	if time.Now().After(ac.ExpiresAt) {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "Authorization code expired")
		return
	}
	if ac.ClientID != req.clientID {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "Client ID mismatch")
		return
	}
	if ac.RedirectURI != req.redirectURI {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "Redirect URI mismatch")
		return
	}

	// Verify PKCE
	if !ValidatePKCE(req.codeVerifier, ac.CodeChallenge) {
		h.Logger.Warn("token: PKCE verification failed", "client_id", req.clientID)
		tokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	// Lock redirect URI on first successful token exchange (deliberate design choice:
	// we defer locking to this point so that only callers with the valid client_secret
	// can lock the URI, preventing unauthenticated redirect URI hijacking at /authorize).
	if client.RedirectURI == "" {
		locked, err := h.DB.LockRedirectURI(req.clientID, req.redirectURI)
		if err != nil {
			h.Logger.Error("token: locking redirect_uri", "error", err)
			tokenError(w, http.StatusInternalServerError, "server_error", "Internal error")
			return
		}
		if locked {
			h.Logger.Info("token: locked redirect_uri on first exchange", "client_id", req.clientID, "redirect_uri", req.redirectURI)
		} else {
			// Race: another request locked it first — re-fetch and validate
			client, _ = h.DB.GetClient(req.clientID)
			if client == nil || req.redirectURI != client.RedirectURI {
				tokenError(w, http.StatusBadRequest, "invalid_grant", "Redirect URI mismatch")
				return
			}
		}
	}

	// Mark code as used
	if err := h.DB.MarkCodeUsed(req.code); err != nil {
		h.Logger.Error("token: marking code used", "error", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "Internal error")
		return
	}

	// Issue tokens
	h.issueTokens(w, req.clientID, ac.Scope, req.code)
}

func (h *Handlers) tokenRefreshToken(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	refreshTokenStr := r.FormValue("refresh_token")

	// Validate client credentials
	client, err := h.DB.GetClient(clientID)
	if err != nil {
		h.Logger.Error("token: db error", "error", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "Internal error")
		return
	}
	if client == nil {
		bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(clientSecret))
		tokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(clientSecret)); err != nil {
		tokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}

	// Look up refresh token
	rt, err := h.DB.GetRefreshToken(refreshTokenStr)
	if err != nil {
		h.Logger.Error("token: db error looking up refresh token", "error", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "Internal error")
		return
	}
	if rt == nil {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid refresh token")
		return
	}
	if time.Now().After(rt.ExpiresAt) {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "Refresh token expired")
		return
	}
	if rt.ClientID != clientID {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "Client ID mismatch")
		return
	}

	// Delete old refresh token (revoke = delete)
	if err := h.DB.RevokeRefreshToken(refreshTokenStr); err != nil {
		h.Logger.Error("token: revoking old refresh token", "error", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "Failed to revoke old token")
		return
	}
	// Delete old access token if present
	if rt.AccessTokenID != "" {
		if err := h.DB.RevokeAccessToken(rt.AccessTokenID); err != nil {
			h.Logger.Error("token: revoking old access token", "error", err)
		}
	}

	// Issue new tokens (no auth code linkage for refresh-based issuance)
	h.issueTokens(w, clientID, rt.Scope, "")
}

func (h *Handlers) issueTokens(w http.ResponseWriter, clientID, scope, authCode string) {
	accessToken, claims, err := h.Tokens.GenerateAccessToken(clientID, scope, AccessTokenTTL)
	if err != nil {
		h.Logger.Error("token: generating access token", "error", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate token")
		return
	}

	refreshToken, err := GenerateRefreshToken()
	if err != nil {
		h.Logger.Error("token: generating refresh token", "error", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate token")
		return
	}

	// Store tokens — fail if storage fails (tokens must be in DB for revocation)
	expiresAt := time.Unix(claims.EXP, 0)
	if err := h.DB.StoreAccessToken(claims.JTI, clientID, scope, authCode, expiresAt); err != nil {
		h.Logger.Error("token: storing access token", "error", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "Failed to store token")
		return
	}
	rfExpiry := time.Now().Add(RefreshTokenTTL)
	if err := h.DB.StoreRefreshToken(refreshToken, clientID, claims.JTI, scope, authCode, rfExpiry); err != nil {
		h.Logger.Error("token: storing refresh token", "error", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "Failed to store token")
		return
	}

	h.Logger.Info("token: issued", "client_id", clientID, "token_id", claims.JTI, "scope", scope)

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(AccessTokenTTL.Seconds()),
		"refresh_token": refreshToken,
	})
}

// VerifyToken handles GET /auth/verify for Caddy forward_auth.
func (h *Handlers) VerifyToken(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		h.writeUnauthorized(w, r)
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		h.writeUnauthorized(w, r)
		return
	}
	token := parts[1]

	claims, err := h.Tokens.ValidateAccessToken(token)
	if err != nil {
		h.Logger.Debug("verify: token validation failed", "error", err)
		h.writeUnauthorized(w, r)
		return
	}

	// Token must exist in DB (revoke = delete, so missing = revoked)
	exists, err := h.DB.AccessTokenExists(claims.JTI)
	if err != nil {
		h.Logger.Error("verify: db error", "error", err)
		h.writeUnauthorized(w, r)
		return
	}
	if !exists {
		h.Logger.Info("verify: token not in database (revoked or never stored)", "token_id", claims.JTI)
		h.writeUnauthorized(w, r)
		return
	}

	h.Logger.Debug("verify: token valid", "token_id", claims.JTI, "client_id", claims.Sub)
	w.Header().Set("X-Auth-Client", claims.Sub)
	w.Header().Set("X-Auth-Scope", claims.Scope)
	w.WriteHeader(http.StatusOK)
}

func (h *Handlers) writeUnauthorized(w http.ResponseWriter, r *http.Request) {
	base := baseURL(r)
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, base))
	w.WriteHeader(http.StatusUnauthorized)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func tokenError(w http.ResponseWriter, status int, errCode, description string) {
	writeJSON(w, status, map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
