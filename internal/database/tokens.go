package database

import (
	"database/sql"
	"errors"
	"time"
)

type RefreshToken struct {
	TokenHash string
	ClientID  string
	Scope     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// StoreRefreshToken stores a refresh token by its SHA-256 hash.
func (d *DB) StoreRefreshToken(rawToken, clientID, scope string, expiresAt time.Time) error {
	_, err := d.db.Exec(
		"INSERT INTO refresh_tokens (token_hash, client_id, scope, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
		HashToken(rawToken), clientID, scope, time.Now().Unix(), expiresAt.Unix(),
	)
	return err
}

// GetRefreshToken looks up a refresh token by hashing the raw value.
func (d *DB) GetRefreshToken(rawToken string) (*RefreshToken, error) {
	row := d.db.QueryRow(
		"SELECT token_hash, client_id, scope, created_at, expires_at FROM refresh_tokens WHERE token_hash = ?",
		HashToken(rawToken),
	)

	var t RefreshToken
	var createdAt, expiresAt int64
	var scope sql.NullString
	if err := row.Scan(&t.TokenHash, &t.ClientID, &scope, &createdAt, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	t.Scope = scope.String
	t.CreatedAt = time.Unix(createdAt, 0)
	t.ExpiresAt = time.Unix(expiresAt, 0)
	return &t, nil
}

// RevokeRefreshToken deletes the refresh token record.
func (d *DB) RevokeRefreshToken(rawToken string) error {
	_, err := d.db.Exec("DELETE FROM refresh_tokens WHERE token_hash = ?", HashToken(rawToken))
	return err
}
