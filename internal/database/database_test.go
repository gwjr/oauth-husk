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
}

func TestLockRedirectURI(t *testing.T) {
	db := testDB(t)

	if err := db.CreateClient("client1", "hash", "", ""); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	locked, err := db.LockRedirectURI("client1", "https://example.com/cb")
	if err != nil {
		t.Fatalf("LockRedirectURI: %v", err)
	}
	if !locked {
		t.Fatal("expected redirect URI to be locked on first call")
	}

	c, err := db.GetClient("client1")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if c.RedirectURI != "https://example.com/cb" {
		t.Fatalf("expected redirect_uri to be set, got %s", c.RedirectURI)
	}

	locked, err = db.LockRedirectURI("client1", "https://evil.example.com/cb")
	if err != nil {
		t.Fatalf("LockRedirectURI (second): %v", err)
	}
	if locked {
		t.Fatal("expected redirect URI not to change after lock")
	}
}

func TestAuthCodeFlow(t *testing.T) {
	db := testDB(t)
	db.CreateClient("client1", "hash", "https://example.com/cb", "")

	// Store code
	err := db.StoreAuthCode("code123", "client1", "https://example.com/cb", "challenge", "mcp:tools", 120*time.Second)
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
	// Delete (single-use)
	if err := db.DeleteAuthCode("code123"); err != nil {
		t.Fatalf("DeleteAuthCode: %v", err)
	}

	// Second lookup should find nothing
	ac, _ = db.GetAuthCode("code123")
	if ac != nil {
		t.Error("expected auth code to be gone after delete")
	}
}

func TestRefreshTokenCRUD(t *testing.T) {
	db := testDB(t)
	db.CreateClient("client1", "hash", "https://example.com/cb", "")

	expires := time.Now().Add(30 * 24 * time.Hour)
	if err := db.StoreRefreshToken("raw-refresh-token", "client1", "mcp:tools", expires); err != nil {
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
	// Verify it's stored as a hash, not the raw token
	if rt.TokenHash == "raw-refresh-token" {
		t.Error("expected token to be stored as hash, not raw value")
	}
	expectedHash := HashToken("raw-refresh-token")
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
	db.StoreRefreshToken("rt1", "client1", "", expires)
	db.StoreRefreshToken("rt2", "client1", "", expires)

	n, err := db.RevokeClientTokens("client1")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("expected 2 revoked, got %d", n)
	}
}

func TestCleanupExpired(t *testing.T) {
	db := testDB(t)
	db.CreateClient("client1", "hash", "https://example.com/cb", "")

	// Store expired code
	db.StoreAuthCode("expired-code", "client1", "https://example.com/cb", "ch", "", -1*time.Second)

	// Store expired refresh token
	db.StoreRefreshToken("expired-rt", "client1", "", time.Now().Add(-1*time.Hour))

	if err := db.CleanupExpired(); err != nil {
		t.Fatal(err)
	}

	ac, _ := db.GetAuthCode("expired-code")
	if ac != nil {
		t.Error("expected expired code to be cleaned up")
	}

	rt, _ := db.GetRefreshToken("expired-rt")
	if rt != nil {
		t.Error("expected expired refresh token to be cleaned up")
	}
}

func TestSigningKey(t *testing.T) {
	db := testDB(t)

	key1, err := db.SigningKey()
	if err != nil {
		t.Fatalf("SigningKey (first): %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("expected 32-byte signing key, got %d", len(key1))
	}

	key2, err := db.SigningKey()
	if err != nil {
		t.Fatalf("SigningKey (second): %v", err)
	}
	if string(key1) != string(key2) {
		t.Fatal("expected signing key to be stable across calls")
	}
}
