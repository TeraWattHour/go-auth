package adapters

import (
	"database/sql"
	"errors"
	"github.com/google/uuid"
	"time"
)

// SQLite adapter is used to handle data transfer using the native sql library.
// The database schema is required to have the following schema, which can be extended further:

// CREATE TABLE users (
//     id TEXT PRIMARY KEY,
//     name TEXT,
//     email TEXT UNIQUE,
//     email_verified_at TEXT,
//     avatar TEXT,
//     created_at TEXT NOT NULL DEFAULT (datetime('now')),
//     updated_at TEXT NOT NULL DEFAULT (datetime('now'))
// );
//
// CREATE TABLE accounts (
//     id TEXT PRIMARY KEY,
//     user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
//     provider_id TEXT NOT NULL,
//     provider_account_id TEXT NOT NULL,
//     created_at TEXT NOT NULL DEFAULT (datetime('now')),
//     updated_at TEXT NOT NULL DEFAULT (datetime('now')),
//     UNIQUE (provider_id, provider_account_id)
// );
//
// CREATE TABLE sessions (
//     id TEXT PRIMARY KEY,
//     user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
//     expires_at TEXT NOT NULL,
//     created_at TEXT DEFAULT (datetime('now')),
//     updated_at TEXT DEFAULT (datetime('now'))
// );

type SQLiteAdapter struct {
	db *sql.DB
}

func NewSQLiteAdapter(db *sql.DB) *SQLiteAdapter {
	return &SQLiteAdapter{db: db}
}

func (s *SQLiteAdapter) GetUserIdByEmail(email string) (string, bool, error) {
	row := s.db.QueryRow("SELECT u.id FROM users u WHERE u.email = ?", email)
	if err := row.Err(); err != nil {
		return "", false, err
	}

	var userId string
	if err := row.Scan(&userId); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}

	return userId, true, nil
}

func (s *SQLiteAdapter) GetConnectedUserId(accountId string) (string, error) {
	row := s.db.QueryRow("SELECT a.user_id FROM accounts a WHERE a.id = ?", accountId)
	if err := row.Err(); err != nil {
		return "", err
	}

	var userId string
	if err := row.Scan(&userId); err != nil {
		return "", err
	}

	return userId, nil
}

func (s *SQLiteAdapter) GetAccountId(providerId string, providerAccountId string) (string, bool, error) {
	row := s.db.QueryRow("SELECT a.id FROM accounts a WHERE a.provider_id = ? AND a.provider_account_id = ?", providerId, providerAccountId)
	if err := row.Err(); err != nil {
		return "", false, err
	}

	var accountId string
	if err := row.Scan(&accountId); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}

	return accountId, true, nil
}

func (s *SQLiteAdapter) CreateAccount(userId string, providerId string, providerAccountId string) (string, error) {
	id := uuid.New().String()

	_, err := s.db.Exec("INSERT INTO accounts (id, user_id, provider_id, provider_account_id) VALUES (?, ?, ?, ?)", id, userId, providerId, providerAccountId)
	if err != nil {
		return "", err
	}

	return id, nil
}

func (s *SQLiteAdapter) CreateSession(userId string) (string, time.Time, error) {
	id := uuid.New().String()
	expiresAt := time.Now().Add(time.Hour * 24 * 365)

	_, err := s.db.Exec("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)", id, userId, expiresAt)
	if err != nil {
		return "", time.Now(), err
	}

	return id, expiresAt, nil
}

func (s *SQLiteAdapter) CreateUser(email string, name string, avatar *string) (string, error) {
	id := uuid.New().String()

	_, err := s.db.Exec("INSERT INTO users (id, email, name, avatar) VALUES (?, ?, ?, ?)", id, email, name, avatar)
	if err != nil {
		return "", err
	}

	return id, nil
}

func (s *SQLiteAdapter) GetSession(sessionId string) (string, time.Time, error) {
	row := s.db.QueryRow("SELECT user_id, expires_at FROM sessions WHERE id = ?", sessionId)
	if err := row.Err(); err != nil {
		return "", time.Now(), err
	}

	var userId string
	var expiresAt time.Time

	if err := row.Scan(&userId, &expiresAt); err != nil {
		return "", time.Now(), err
	}

	return userId, expiresAt, nil
}

func (s *SQLiteAdapter) RemoveSession(sessionId string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE id = ?", sessionId)
	return err
}
