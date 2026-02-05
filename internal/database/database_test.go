package database

import (
	"path/filepath"
	"testing"
	"time"
)

func testDB(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestClientCRUD(t *testing.T) {
	db := testDB(t)

	// Create
	if err := db.CreateClient("test-id", "$2a$12$hash", "https://example.com/cb", "test"); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	// Get
	c, err := db.GetClient("test-id")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if c == nil {
		t.Fatal("expected client, got nil")
	}
	if c.ClientID != "test-id" {
		t.Errorf("expected client_id=test-id, got %s", c.ClientID)
	}
	if c.RedirectURI != "https://example.com/cb" {
		t.Errorf("expected redirect_uri, got %s", c.RedirectURI)
	}

	// Get nonexistent
	c, err = db.GetClient("nonexistent")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if c != nil {
		t.Error("expected nil for nonexistent client")
	}

	// List
	clients, err := db.ListClients()
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(clients) != 1 {
		t.Errorf("expected 1 client, got %d", len(clients))
	}

	// Delete
	if err := db.DeleteClient("test-id"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	clients, _ = db.ListClients()
	if len(clients) != 0 {
		t.Errorf("expected 0 clients after delete, got %d", len(clients))
	}
}

func TestUpsertClient(t *testing.T) {
	db := testDB(t)

	// Insert
	if err := db.UpsertClient("test-id", "hash1", "https://a.com/cb", "first"); err != nil {
		t.Fatal(err)
	}
	c, _ := db.GetClient("test-id")
	if c.ClientSecretHash != "hash1" {
		t.Errorf("expected hash1, got %s", c.ClientSecretHash)
	}

	// Update
	if err := db.UpsertClient("test-id", "hash2", "https://b.com/cb", "second"); err != nil {
		t.Fatal(err)
	}
	c, _ = db.GetClient("test-id")
	if c.ClientSecretHash != "hash2" {
		t.Errorf("expected hash2, got %s", c.ClientSecretHash)
	}
	if c.RedirectURI != "https://b.com/cb" {
		t.Errorf("expected updated redirect_uri, got %s", c.RedirectURI)
	}
}

func TestAuthCodeFlow(t *testing.T) {
	db := testDB(t)
	db.CreateClient("client1", "hash", "https://example.com/cb", "")

	// Store code
	err := db.StoreAuthCode("code123", "client1", "https://example.com/cb", "challenge", "mcp:tools", "", 120*time.Second)
	if err != nil {
		t.Fatalf("StoreAuthCode: %v", err)
	}

	// Get code
	ac, err := db.GetAuthCode("code123")
	if err != nil {
		t.Fatalf("GetAuthCode: %v", err)
	}
	if ac == nil {
		t.Fatal("expected auth code, got nil")
	}
	if ac.ClientID != "client1" {
		t.Errorf("expected client_id=client1, got %s", ac.ClientID)
	}
	if ac.UsedAt != nil {
		t.Error("expected unused code")
	}

	// Mark used
	if err := db.MarkCodeUsed("code123"); err != nil {
		t.Fatalf("MarkCodeUsed: %v", err)
	}

	// Verify marked
	ac, _ = db.GetAuthCode("code123")
	if ac.UsedAt == nil {
		t.Error("expected code to be marked used")
	}

	// Double use should fail
	if err := db.MarkCodeUsed("code123"); err == nil {
		t.Error("expected error on double use")
	}
}

func TestTokenRevocation(t *testing.T) {
	db := testDB(t)
	db.CreateClient("client1", "hash", "https://example.com/cb", "")

	// Store access token
	expires := time.Now().Add(24 * time.Hour)
	if err := db.StoreAccessToken("token1", "client1", "mcp:tools", expires); err != nil {
		t.Fatalf("StoreAccessToken: %v", err)
	}

	// Token exists
	exists, err := db.AccessTokenExists("token1")
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("expected token to exist")
	}

	// Revoke (delete)
	if err := db.RevokeAccessToken("token1"); err != nil {
		t.Fatal(err)
	}

	// Token no longer exists
	exists, _ = db.AccessTokenExists("token1")
	if exists {
		t.Error("expected token to be gone after revocation")
	}
}

func TestRefreshTokenCRUD(t *testing.T) {
	db := testDB(t)
	db.CreateClient("client1", "hash", "https://example.com/cb", "")

	expires := time.Now().Add(30 * 24 * time.Hour)
	if err := db.StoreRefreshToken("raw-refresh-token", "client1", "at1", "mcp:tools", expires); err != nil {
		t.Fatalf("StoreRefreshToken: %v", err)
	}

	// Look up by raw token (hashed internally)
	rt, err := db.GetRefreshToken("raw-refresh-token")
	if err != nil {
		t.Fatal(err)
	}
	if rt == nil {
		t.Fatal("expected refresh token")
	}
	if rt.ClientID != "client1" {
		t.Errorf("expected client1, got %s", rt.ClientID)
	}
	if rt.AccessTokenID != "at1" {
		t.Errorf("expected at1, got %s", rt.AccessTokenID)
	}

	// Verify it's stored as a hash, not the raw token
	if rt.TokenHash == "raw-refresh-token" {
		t.Error("expected token to be stored as hash, not raw value")
	}
	expectedHash := HashRefreshToken("raw-refresh-token")
	if rt.TokenHash != expectedHash {
		t.Errorf("expected hash %s, got %s", expectedHash, rt.TokenHash)
	}

	// Revoke (delete)
	if err := db.RevokeRefreshToken("raw-refresh-token"); err != nil {
		t.Fatal(err)
	}
	rt, _ = db.GetRefreshToken("raw-refresh-token")
	if rt != nil {
		t.Error("expected refresh token to be gone after revocation")
	}
}

func TestRevokeClientTokens(t *testing.T) {
	db := testDB(t)
	db.CreateClient("client1", "hash", "https://example.com/cb", "")

	expires := time.Now().Add(24 * time.Hour)
	db.StoreAccessToken("at1", "client1", "", expires)
	db.StoreAccessToken("at2", "client1", "", expires)
	db.StoreRefreshToken("rt1", "client1", "at1", "", expires)

	n, err := db.RevokeClientTokens("client1")
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("expected 3 revoked, got %d", n)
	}

	exists, _ := db.AccessTokenExists("at1")
	if exists {
		t.Error("at1 should be deleted")
	}
}

func TestCleanupExpired(t *testing.T) {
	db := testDB(t)
	db.CreateClient("client1", "hash", "https://example.com/cb", "")

	// Store expired code
	db.StoreAuthCode("expired-code", "client1", "https://example.com/cb", "ch", "", "", -1*time.Second)

	// Store expired token
	db.StoreAccessToken("expired-at", "client1", "", time.Now().Add(-1*time.Hour))

	if err := db.CleanupExpired(); err != nil {
		t.Fatal(err)
	}

	ac, _ := db.GetAuthCode("expired-code")
	if ac != nil {
		t.Error("expected expired code to be cleaned up")
	}

	exists, _ := db.AccessTokenExists("expired-at")
	if exists {
		t.Error("expected expired token to be cleaned up")
	}
}
