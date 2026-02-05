package database

import (
	"database/sql"
	"errors"
	"time"
)

type AuthCode struct {
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	UsedAt              *time.Time
}

func (d *DB) StoreAuthCode(code, clientID, redirectURI, codeChallenge, scope string, ttl time.Duration) error {
	now := time.Now()
	_, err := d.db.Exec(
		`INSERT INTO auth_codes (code, client_id, redirect_uri, code_challenge, code_challenge_method, scope, created_at, expires_at)
		 VALUES (?, ?, ?, ?, 'S256', ?, ?, ?)`,
		HashToken(code), clientID, redirectURI, codeChallenge, scope, now.Unix(), now.Add(ttl).Unix(),
	)
	return err
}

func (d *DB) GetAuthCode(code string) (*AuthCode, error) {
	row := d.db.QueryRow(
		`SELECT client_id, redirect_uri, code_challenge, code_challenge_method, scope, created_at, expires_at, used_at
		 FROM auth_codes WHERE code = ?`,
		HashToken(code),
	)

	var ac AuthCode
	var createdAt, expiresAt int64
	var usedAt sql.NullInt64
	var scope sql.NullString
	if err := row.Scan(&ac.ClientID, &ac.RedirectURI, &ac.CodeChallenge, &ac.CodeChallengeMethod,
		&scope, &createdAt, &expiresAt, &usedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	ac.Scope = scope.String
	ac.CreatedAt = time.Unix(createdAt, 0)
	ac.ExpiresAt = time.Unix(expiresAt, 0)
	if usedAt.Valid {
		t := time.Unix(usedAt.Int64, 0)
		ac.UsedAt = &t
	}
	return &ac, nil
}

func (d *DB) MarkCodeUsed(code string) error {
	res, err := d.db.Exec(
		"UPDATE auth_codes SET used_at = ? WHERE code = ? AND used_at IS NULL",
		time.Now().Unix(), HashToken(code),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("auth code already used or not found")
	}
	return nil
}
