package database

import (
	"database/sql"
	"errors"
	"time"
)

type AuthCode struct {
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Scope         string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

func (d *DB) StoreAuthCode(code, clientID, redirectURI, codeChallenge, scope string, ttl time.Duration) error {
	now := time.Now()
	_, err := d.db.Exec(
		`INSERT INTO auth_codes (code, client_id, redirect_uri, code_challenge, scope, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		HashToken(code), clientID, redirectURI, codeChallenge, scope, now.Unix(), now.Add(ttl).Unix(),
	)
	return err
}

func (d *DB) GetAuthCode(code string) (*AuthCode, error) {
	row := d.db.QueryRow(
		`SELECT client_id, redirect_uri, code_challenge, scope, created_at, expires_at
		 FROM auth_codes WHERE code = ?`,
		HashToken(code),
	)

	var ac AuthCode
	var createdAt, expiresAt int64
	var scope sql.NullString
	if err := row.Scan(&ac.ClientID, &ac.RedirectURI, &ac.CodeChallenge,
		&scope, &createdAt, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	ac.Scope = scope.String
	ac.CreatedAt = time.Unix(createdAt, 0)
	ac.ExpiresAt = time.Unix(expiresAt, 0)
	return &ac, nil
}

// DeleteAuthCode removes the auth code row. Used after successful exchange
// to enforce single-use — a second attempt simply finds no row.
func (d *DB) DeleteAuthCode(code string) error {
	_, err := d.db.Exec("DELETE FROM auth_codes WHERE code = ?", HashToken(code))
	return err
}
