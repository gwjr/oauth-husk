package database

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	db *sql.DB
}

func Open(path string) (*DB, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating database directory: %w", err)
	}

	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	if err := os.Chmod(path, 0600); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting database permissions: %w", err)
	}

	d := &DB{db: db}
	if err := d.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return d, nil
}

func (d *DB) Close() error {
	return d.db.Close()
}

func (d *DB) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS clients (
			client_id TEXT PRIMARY KEY,
			client_secret_hash TEXT NOT NULL,
			redirect_uri TEXT,
			created_at INTEGER NOT NULL,
			description TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS auth_codes (
			code TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			code_challenge TEXT NOT NULL,
			code_challenge_method TEXT NOT NULL DEFAULT 'S256',
			scope TEXT,
			resource TEXT,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			used_at INTEGER,
			FOREIGN KEY (client_id) REFERENCES clients(client_id)
		)`,
		`CREATE TABLE IF NOT EXISTS access_tokens (
			token_id TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			scope TEXT,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			FOREIGN KEY (client_id) REFERENCES clients(client_id)
		)`,
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			token_hash TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			access_token_id TEXT,
			scope TEXT,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			FOREIGN KEY (client_id) REFERENCES clients(client_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON auth_codes(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_expires ON access_tokens(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_client ON access_tokens(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client ON refresh_tokens(client_id)`,
	}

	for _, m := range migrations {
		if _, err := d.db.Exec(m); err != nil {
			return fmt.Errorf("executing migration: %w\nSQL: %s", err, m)
		}
	}
	return nil
}

// SigningKey returns the token signing key, generating and storing one if it doesn't exist.
func (d *DB) SigningKey() ([]byte, error) {
	var value string
	err := d.db.QueryRow("SELECT value FROM settings WHERE key = 'signing_key'").Scan(&value)
	if err == nil {
		return base64.RawURLEncoding.DecodeString(value)
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("querying signing key: %w", err)
	}

	// Generate a new 32-byte key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating signing key: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(key)

	if _, err := d.db.Exec("INSERT INTO settings (key, value) VALUES ('signing_key', ?)", encoded); err != nil {
		return nil, fmt.Errorf("storing signing key: %w", err)
	}

	return key, nil
}

func (d *DB) CleanupExpired() error {
	now := time.Now().Unix()

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete expired and used auth codes
	if _, err := tx.Exec("DELETE FROM auth_codes WHERE expires_at < ? OR used_at IS NOT NULL", now); err != nil {
		return err
	}
	// Delete expired access tokens
	if _, err := tx.Exec("DELETE FROM access_tokens WHERE expires_at < ?", now); err != nil {
		return err
	}
	// Delete expired refresh tokens
	if _, err := tx.Exec("DELETE FROM refresh_tokens WHERE expires_at < ?", now); err != nil {
		return err
	}

	return tx.Commit()
}
