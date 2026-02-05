package oauth_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gwjr/oauth-husk/internal/database"
	"github.com/gwjr/oauth-husk/internal/oauth"
	"golang.org/x/crypto/bcrypt"
)

type testEnv struct {
	DB       *database.DB
	Handlers *oauth.Handlers
	Mux      *http.ServeMux
	Server   *httptest.Server
}

func setup(t *testing.T) *testEnv {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	key := make([]byte, 32)
	rand.Read(key)

	tokenSvc, err := oauth.NewTokenService(key)
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	h := &oauth.Handlers{
		DB:     db,
		Tokens: tokenSvc,
		Logger: logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", h.ProtectedResourceMetadata)
	mux.HandleFunc("HEAD /.well-known/oauth-protected-resource", h.ProtectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.AuthorizationServerMetadata)
	mux.HandleFunc("HEAD /.well-known/oauth-authorization-server", h.AuthorizationServerMetadata)
	mux.HandleFunc("GET /authorize", h.Authorize)
	mux.HandleFunc("POST /token", h.Token)
	mux.HandleFunc("GET /auth/verify", h.VerifyToken)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &testEnv{DB: db, Handlers: h, Mux: mux, Server: srv}
}

func seedClient(t *testing.T, env *testEnv, clientID, secret, redirectURI string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.DB.CreateClient(clientID, string(hash), redirectURI, "test"); err != nil {
		t.Fatal(err)
	}
}

func TestProtectedResourceMetadata(t *testing.T) {
	env := setup(t)
	// baseURL(r) derives from Host header; httptest sets Host to server's addr.
	// The default scheme is "https" when no X-Forwarded-Proto is set.
	expectedBase := "https://" + strings.TrimPrefix(env.Server.URL, "http://")

	// GET
	resp, err := http.Get(env.Server.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %s", ct)
	}

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if body["resource"] != expectedBase {
		t.Errorf("expected resource=%s, got %v", expectedBase, body["resource"])
	}

	// HEAD
	resp2, err := http.Head(env.Server.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Errorf("HEAD expected 200, got %d", resp2.StatusCode)
	}
}

func TestAuthorizationServerMetadata(t *testing.T) {
	env := setup(t)
	expectedBase := "https://" + strings.TrimPrefix(env.Server.URL, "http://")

	resp, err := http.Get(env.Server.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if body["issuer"] != expectedBase {
		t.Errorf("expected issuer=%s, got %v", expectedBase, body["issuer"])
	}
	if body["authorization_endpoint"] != expectedBase+"/authorize" {
		t.Errorf("wrong authorization_endpoint: %v", body["authorization_endpoint"])
	}
}

func TestAuthorize_HappyPath(t *testing.T) {
	env := setup(t)
	seedClient(t, env, "client1", "secret1", "https://callback.example.com/cb")

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	u := fmt.Sprintf("%s/authorize?response_type=code&client_id=client1&redirect_uri=%s&state=xyz&code_challenge=%s&code_challenge_method=S256&scope=mcp:tools",
		env.Server.URL,
		url.QueryEscape("https://callback.example.com/cb"),
		challenge,
	)

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != 302 {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}

	loc, _ := resp.Location()
	if loc.Host != "callback.example.com" {
		t.Errorf("expected redirect to callback.example.com, got %s", loc.Host)
	}
	if loc.Query().Get("code") == "" {
		t.Error("expected code in redirect")
	}
	if loc.Query().Get("state") != "xyz" {
		t.Errorf("expected state=xyz, got %s", loc.Query().Get("state"))
	}
}

func TestAuthorize_UnknownClient(t *testing.T) {
	env := setup(t)

	u := fmt.Sprintf("%s/authorize?response_type=code&client_id=unknown&redirect_uri=https://evil.com/cb&code_challenge=x&code_challenge_method=S256",
		env.Server.URL,
	)

	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Errorf("expected 401 for unknown client, got %d", resp.StatusCode)
	}
}

func TestAuthorize_BadRedirectURI(t *testing.T) {
	env := setup(t)
	seedClient(t, env, "client1", "secret1", "https://good.example.com/cb")

	u := fmt.Sprintf("%s/authorize?response_type=code&client_id=client1&redirect_uri=%s&code_challenge=x&code_challenge_method=S256",
		env.Server.URL,
		url.QueryEscape("https://evil.example.com/cb"),
	)

	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Errorf("expected 400 for bad redirect_uri, got %d", resp.StatusCode)
	}
}

func TestAuthorize_BadChallengeMethod(t *testing.T) {
	env := setup(t)
	seedClient(t, env, "client1", "secret1", "https://callback.example.com/cb")

	u := fmt.Sprintf("%s/authorize?response_type=code&client_id=client1&redirect_uri=%s&code_challenge=x&code_challenge_method=plain&state=s1",
		env.Server.URL,
		url.QueryEscape("https://callback.example.com/cb"),
	)

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != 302 {
		t.Fatalf("expected redirect with error, got %d", resp.StatusCode)
	}
	loc, _ := resp.Location()
	if loc.Query().Get("error") != "invalid_request" {
		t.Errorf("expected error=invalid_request, got %s", loc.Query().Get("error"))
	}
}

func TestFullTokenExchange(t *testing.T) {
	env := setup(t)
	seedClient(t, env, "client1", "secret1", "https://callback.example.com/cb")

	// Step 1: Authorize
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=client1&redirect_uri=%s&state=xyz&code_challenge=%s&code_challenge_method=S256&scope=mcp:tools",
		env.Server.URL,
		url.QueryEscape("https://callback.example.com/cb"),
		challenge,
	)

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	loc, _ := resp.Location()
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("no code in redirect")
	}

	// Step 2: Token exchange
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://callback.example.com/cb"},
		"client_id":     {"client1"},
		"client_secret": {"secret1"},
		"code_verifier": {verifier},
	}

	resp2, err := http.PostForm(env.Server.URL+"/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 200 {
		var errBody map[string]string
		json.NewDecoder(resp2.Body).Decode(&errBody)
		t.Fatalf("expected 200, got %d: %v", resp2.StatusCode, errBody)
	}

	var tokenResp map[string]any
	json.NewDecoder(resp2.Body).Decode(&tokenResp)

	if tokenResp["access_token"] == nil {
		t.Error("expected access_token")
	}
	if tokenResp["refresh_token"] == nil {
		t.Error("expected refresh_token")
	}
	if tokenResp["token_type"] != "Bearer" {
		t.Errorf("expected Bearer, got %v", tokenResp["token_type"])
	}

	// Step 3: Verify token
	accessToken := tokenResp["access_token"].(string)
	req, _ := http.NewRequest("GET", env.Server.URL+"/auth/verify", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp3, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != 200 {
		t.Errorf("verify expected 200, got %d", resp3.StatusCode)
	}
}

func TestToken_DoubleUseCode(t *testing.T) {
	env := setup(t)
	seedClient(t, env, "client1", "secret1", "https://callback.example.com/cb")

	verifier := "test-verifier-for-double-use"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Authorize
	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=client1&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256",
		env.Server.URL,
		url.QueryEscape("https://callback.example.com/cb"),
		challenge,
	)
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, _ := client.Get(authURL)
	resp.Body.Close()
	loc, _ := resp.Location()
	code := loc.Query().Get("code")

	// First exchange — should succeed
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://callback.example.com/cb"},
		"client_id":     {"client1"},
		"client_secret": {"secret1"},
		"code_verifier": {verifier},
	}
	resp2, _ := http.PostForm(env.Server.URL+"/token", form)
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("first exchange expected 200, got %d", resp2.StatusCode)
	}

	// Second exchange — should fail
	resp3, _ := http.PostForm(env.Server.URL+"/token", form)
	resp3.Body.Close()
	if resp3.StatusCode == 200 {
		t.Error("second exchange should fail")
	}
}

func TestToken_WrongPKCE(t *testing.T) {
	env := setup(t)
	seedClient(t, env, "client1", "secret1", "https://callback.example.com/cb")

	verifier := "correct-verifier"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Authorize
	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=client1&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256",
		env.Server.URL,
		url.QueryEscape("https://callback.example.com/cb"),
		challenge,
	)
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, _ := client.Get(authURL)
	resp.Body.Close()
	loc, _ := resp.Location()
	code := loc.Query().Get("code")

	// Exchange with wrong verifier
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://callback.example.com/cb"},
		"client_id":     {"client1"},
		"client_secret": {"secret1"},
		"code_verifier": {"wrong-verifier"},
	}
	resp2, _ := http.PostForm(env.Server.URL+"/token", form)
	defer resp2.Body.Close()

	if resp2.StatusCode == 200 {
		t.Error("expected failure for wrong PKCE verifier")
	}

	var errResp map[string]string
	json.NewDecoder(resp2.Body).Decode(&errResp)
	if errResp["error"] != "invalid_grant" {
		t.Errorf("expected invalid_grant, got %s", errResp["error"])
	}
}

func TestRefreshTokenFlow(t *testing.T) {
	env := setup(t)
	seedClient(t, env, "client1", "secret1", "https://callback.example.com/cb")

	// Get initial tokens via auth code flow
	verifier := "refresh-test-verifier"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=client1&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&scope=mcp:tools",
		env.Server.URL,
		url.QueryEscape("https://callback.example.com/cb"),
		challenge,
	)
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, _ := client.Get(authURL)
	resp.Body.Close()
	loc, _ := resp.Location()
	code := loc.Query().Get("code")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://callback.example.com/cb"},
		"client_id":     {"client1"},
		"client_secret": {"secret1"},
		"code_verifier": {verifier},
	}
	resp2, _ := http.PostForm(env.Server.URL+"/token", form)
	var tokenResp map[string]any
	json.NewDecoder(resp2.Body).Decode(&tokenResp)
	resp2.Body.Close()

	refreshToken := tokenResp["refresh_token"].(string)

	// Use refresh token
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"client1"},
		"client_secret": {"secret1"},
	}
	resp3, err := http.PostForm(env.Server.URL+"/token", refreshForm)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()

	if resp3.StatusCode != 200 {
		var errBody map[string]string
		json.NewDecoder(resp3.Body).Decode(&errBody)
		t.Fatalf("refresh expected 200, got %d: %v", resp3.StatusCode, errBody)
	}

	var newTokens map[string]any
	json.NewDecoder(resp3.Body).Decode(&newTokens)
	if newTokens["access_token"] == nil {
		t.Error("expected new access_token")
	}
	if newTokens["refresh_token"] == nil {
		t.Error("expected new refresh_token")
	}

	// Old refresh token should be revoked (reuse should fail)
	resp4, _ := http.PostForm(env.Server.URL+"/token", refreshForm)
	resp4.Body.Close()
	if resp4.StatusCode == 200 {
		t.Error("expected old refresh token to be revoked")
	}
}

func TestVerifyToken_Missing(t *testing.T) {
	env := setup(t)

	req, _ := http.NewRequest("GET", env.Server.URL+"/auth/verify", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, "resource_metadata") {
		t.Errorf("expected WWW-Authenticate with resource_metadata, got %s", wwwAuth)
	}
}

func TestVerifyToken_Invalid(t *testing.T) {
	env := setup(t)

	req, _ := http.NewRequest("GET", env.Server.URL+"/auth/verify", nil)
	req.Header.Set("Authorization", "Bearer invalid-token-data")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAuthorize_RedirectURI_LockOnFirstUse(t *testing.T) {
	env := setup(t)
	// Create client with no redirect_uri — will lock on first auth
	seedClient(t, env, "client1", "secret1", "")

	verifier := "lock-test-verifier"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	noRedirectClient := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// First auth — should lock the redirect URI
	u := fmt.Sprintf("%s/authorize?response_type=code&client_id=client1&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256",
		env.Server.URL,
		url.QueryEscape("https://callback.example.com/cb"),
		challenge,
	)
	resp, err := noRedirectClient.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}

	// Second auth with same URI — should succeed
	verifier2 := "lock-test-verifier-2"
	h2 := sha256.Sum256([]byte(verifier2))
	challenge2 := base64.RawURLEncoding.EncodeToString(h2[:])

	u2 := fmt.Sprintf("%s/authorize?response_type=code&client_id=client1&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256",
		env.Server.URL,
		url.QueryEscape("https://callback.example.com/cb"),
		challenge2,
	)
	resp2, err := noRedirectClient.Get(u2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 302 {
		t.Errorf("expected 302 for same URI, got %d", resp2.StatusCode)
	}

	// Third auth with different URI — should be rejected
	u3 := fmt.Sprintf("%s/authorize?response_type=code&client_id=client1&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256",
		env.Server.URL,
		url.QueryEscape("https://evil.example.com/cb"),
		challenge2,
	)
	resp3, err := noRedirectClient.Get(u3)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != 400 {
		t.Errorf("expected 400 for different URI after lock, got %d", resp3.StatusCode)
	}
}

func TestToken_WrongClientSecret(t *testing.T) {
	env := setup(t)
	seedClient(t, env, "client1", "correct-secret", "https://callback.example.com/cb")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"doesnt-matter"},
		"redirect_uri":  {"https://callback.example.com/cb"},
		"client_id":     {"client1"},
		"client_secret": {"wrong-secret"},
		"code_verifier": {"x"},
	}
	resp, _ := http.PostForm(env.Server.URL+"/token", form)
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Errorf("expected 401 for wrong secret, got %d", resp.StatusCode)
	}
}
