package database

import (
	"database/sql"
	"errors"
	"time"
)

type Client struct {
	ClientID         string
	ClientSecretHash string
	RedirectURI      string
	CreatedAt        time.Time
	Description      string
}

func (d *DB) CreateClient(clientID, secretHash, redirectURI, description string) error {
	var uri any
	if redirectURI != "" {
		uri = redirectURI
	}
	_, err := d.db.Exec(
		"INSERT INTO clients (client_id, client_secret_hash, redirect_uri, created_at, description) VALUES (?, ?, ?, ?, ?)",
		clientID, secretHash, uri, time.Now().Unix(), description,
	)
	return err
}

func (d *DB) GetClient(clientID string) (*Client, error) {
	row := d.db.QueryRow(
		"SELECT client_id, client_secret_hash, redirect_uri, created_at, description FROM clients WHERE client_id = ?",
		clientID,
	)

	var c Client
	var createdAt int64
	var desc, redirectURI sql.NullString
	if err := row.Scan(&c.ClientID, &c.ClientSecretHash, &redirectURI, &createdAt, &desc); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	c.RedirectURI = redirectURI.String
	c.CreatedAt = time.Unix(createdAt, 0)
	c.Description = desc.String
	return &c, nil
}

func (d *DB) ListClients() ([]Client, error) {
	rows, err := d.db.Query("SELECT client_id, redirect_uri, created_at, description FROM clients ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []Client
	for rows.Next() {
		var c Client
		var createdAt int64
		var desc sql.NullString
		if err := rows.Scan(&c.ClientID, &c.RedirectURI, &createdAt, &desc); err != nil {
			return nil, err
		}
		c.CreatedAt = time.Unix(createdAt, 0)
		c.Description = desc.String
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

func (d *DB) DeleteClient(clientID string) error {
	_, err := d.db.Exec("DELETE FROM clients WHERE client_id = ?", clientID)
	return err
}

func (d *DB) RevokeClientTokens(clientID string) (int64, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	res1, err := tx.Exec("DELETE FROM access_tokens WHERE client_id = ?", clientID)
	if err != nil {
		return 0, err
	}
	res2, err := tx.Exec("DELETE FROM refresh_tokens WHERE client_id = ?", clientID)
	if err != nil {
		return 0, err
	}

	n1, _ := res1.RowsAffected()
	n2, _ := res2.RowsAffected()

	return n1 + n2, tx.Commit()
}

// LockRedirectURI sets the redirect_uri for a client that doesn't have one yet.
// Returns true if it was set, false if the client already had one locked.
func (d *DB) LockRedirectURI(clientID, redirectURI string) (bool, error) {
	res, err := d.db.Exec(
		"UPDATE clients SET redirect_uri = ? WHERE client_id = ? AND redirect_uri IS NULL",
		redirectURI, clientID,
	)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (d *DB) UpsertClient(clientID, secretHash, redirectURI, description string) error {
	_, err := d.db.Exec(
		`INSERT INTO clients (client_id, client_secret_hash, redirect_uri, created_at, description)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(client_id) DO UPDATE SET
		   client_secret_hash = excluded.client_secret_hash,
		   redirect_uri = excluded.redirect_uri,
		   description = excluded.description`,
		clientID, secretHash, redirectURI, time.Now().Unix(), description,
	)
	return err
}
