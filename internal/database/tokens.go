package database

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

type AccessToken struct {
	TokenID   string
	ClientID  string
	Scope     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type RefreshToken struct {
	TokenHash     string
	ClientID      string
	AccessTokenID string
	Scope         string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// HashRefreshToken returns the SHA-256 hex digest of a raw refresh token.
func HashRefreshToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func (d *DB) StoreAccessToken(tokenID, clientID, scope string, expiresAt time.Time) error {
	_, err := d.db.Exec(
		"INSERT INTO access_tokens (token_id, client_id, scope, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
		tokenID, clientID, scope, time.Now().Unix(), expiresAt.Unix(),
	)
	return err
}

// AccessTokenExists returns true if the token exists in the database (not deleted/revoked).
func (d *DB) AccessTokenExists(tokenID string) (bool, error) {
	var id string
	err := d.db.QueryRow(
		"SELECT token_id FROM access_tokens WHERE token_id = ?", tokenID,
	).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// RevokeAccessToken deletes the access token record.
func (d *DB) RevokeAccessToken(tokenID string) error {
	_, err := d.db.Exec("DELETE FROM access_tokens WHERE token_id = ?", tokenID)
	return err
}

// StoreRefreshToken stores a refresh token by its SHA-256 hash.
func (d *DB) StoreRefreshToken(rawToken, clientID, accessTokenID, scope string, expiresAt time.Time) error {
	_, err := d.db.Exec(
		"INSERT INTO refresh_tokens (token_hash, client_id, access_token_id, scope, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
		HashRefreshToken(rawToken), clientID, accessTokenID, scope, time.Now().Unix(), expiresAt.Unix(),
	)
	return err
}

// GetRefreshToken looks up a refresh token by hashing the raw value.
func (d *DB) GetRefreshToken(rawToken string) (*RefreshToken, error) {
	row := d.db.QueryRow(
		"SELECT token_hash, client_id, access_token_id, scope, created_at, expires_at FROM refresh_tokens WHERE token_hash = ?",
		HashRefreshToken(rawToken),
	)

	var t RefreshToken
	var createdAt, expiresAt int64
	var accessTokenID, scope sql.NullString
	if err := row.Scan(&t.TokenHash, &t.ClientID, &accessTokenID, &scope, &createdAt, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	t.AccessTokenID = accessTokenID.String
	t.Scope = scope.String
	t.CreatedAt = time.Unix(createdAt, 0)
	t.ExpiresAt = time.Unix(expiresAt, 0)
	return &t, nil
}

// RevokeRefreshToken deletes the refresh token record.
func (d *DB) RevokeRefreshToken(rawToken string) error {
	_, err := d.db.Exec("DELETE FROM refresh_tokens WHERE token_hash = ?", HashRefreshToken(rawToken))
	return err
}

func (d *DB) DeleteExpiredTokens() (int64, error) {
	now := time.Now().Unix()
	res1, err := d.db.Exec("DELETE FROM access_tokens WHERE expires_at < ?", now)
	if err != nil {
		return 0, err
	}
	res2, err := d.db.Exec("DELETE FROM refresh_tokens WHERE expires_at < ?", now)
	if err != nil {
		return 0, err
	}
	n1, _ := res1.RowsAffected()
	n2, _ := res2.RowsAffected()
	return n1 + n2, nil
}
