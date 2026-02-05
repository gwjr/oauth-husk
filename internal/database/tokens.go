package database

import (
	"database/sql"
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

func (d *DB) StoreAccessToken(tokenID, clientID, scope, authCode string, expiresAt time.Time) error {
	codeHash := HashToken(authCode) // empty string hashes to a fixed value; harmless
	_, err := d.db.Exec(
		"INSERT INTO access_tokens (token_id, client_id, scope, auth_code, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
		tokenID, clientID, scope, codeHash, time.Now().Unix(), expiresAt.Unix(),
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
func (d *DB) StoreRefreshToken(rawToken, clientID, accessTokenID, scope, authCode string, expiresAt time.Time) error {
	codeHash := HashToken(authCode)
	_, err := d.db.Exec(
		"INSERT INTO refresh_tokens (token_hash, client_id, access_token_id, scope, auth_code, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		HashToken(rawToken), clientID, accessTokenID, scope, codeHash, time.Now().Unix(), expiresAt.Unix(),
	)
	return err
}

// GetRefreshToken looks up a refresh token by hashing the raw value.
func (d *DB) GetRefreshToken(rawToken string) (*RefreshToken, error) {
	row := d.db.QueryRow(
		"SELECT token_hash, client_id, access_token_id, scope, created_at, expires_at FROM refresh_tokens WHERE token_hash = ?",
		HashToken(rawToken),
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
	_, err := d.db.Exec("DELETE FROM refresh_tokens WHERE token_hash = ?", HashToken(rawToken))
	return err
}

// RevokeTokensByAuthCode deletes all access and refresh tokens issued from a given auth code.
func (d *DB) RevokeTokensByAuthCode(authCode string) (int64, error) {
	if authCode == "" {
		return 0, nil
	}
	codeHash := HashToken(authCode)
	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	res1, err := tx.Exec("DELETE FROM access_tokens WHERE auth_code = ?", codeHash)
	if err != nil {
		return 0, err
	}
	res2, err := tx.Exec("DELETE FROM refresh_tokens WHERE auth_code = ?", codeHash)
	if err != nil {
		return 0, err
	}

	n1, _ := res1.RowsAffected()
	n2, _ := res2.RowsAffected()
	return n1 + n2, tx.Commit()
}
