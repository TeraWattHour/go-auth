package adapters

import (
	"database/sql"
	"errors"
	"github.com/google/uuid"
	"time"
)

// Postgres adapter is used to handle data transfer using the native sql library.
// The database schema is required to have the following schema, which can be extended further:

// create table users (
//     id text primary key,
//     name text,
//     email text unique,
//     email_verified_at timestamp,
//     avatar text,
//     created_at timestamp not null default now(),
//     updated_at timestamp not null default now()
// );
//
// create table accounts (
//     id text primary key,
//     user_id text not null references users(id) on delete cascade on update cascade,
//
//     provider_id text not null,
//     provider_account_id text not null,
//
//     created_at timestamp not null default now(),
//     updated_at timestamp not null default now(),
//
//     unique (provider_id, provider_account_id)
// );
//
// create table sessions (
//     id text primary key,
//     user_id text not null references users(id) on delete cascade on update cascade,
//     expires_at timestamp not null,
//     created_at timestamp default now(),
//     updated_at timestamp default now()
// );

type PostgresAdapter struct {
	db *sql.DB
}

func NewPostgresAdapter(db *sql.DB) *PostgresAdapter {
	return &PostgresAdapter{db: db}
}

func (p *PostgresAdapter) GetUserIdByEmail(email string) (string, bool, error) {
	row := p.db.QueryRow("SELECT u.id FROM users u WHERE u.email = $1", email)
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

func (p *PostgresAdapter) GetConnectedUserId(accountId string) (string, error) {
	row := p.db.QueryRow("SELECT a.user_id FROM accounts a WHERE a.id = $1", accountId)
	if err := row.Err(); err != nil {
		return "", err
	}

	var userId string
	if err := row.Scan(&userId); err != nil {
		return "", err
	}

	return userId, nil
}

func (p *PostgresAdapter) GetAccountId(providerId string, providerAccountId string) (string, bool, error) {
	row := p.db.QueryRow("SELECT a.id FROM accounts a WHERE a.provider_id = $1 AND a.provider_account_id = $2", providerId, providerAccountId)
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

func (p *PostgresAdapter) CreateAccount(userId string, providerId string, providerAccountId string) (string, error) {
	id := uuid.New().String()

	_, err := p.db.Exec("INSERT INTO accounts (id, user_id, provider_id, provider_account_id) VALUES ($1, $2, $3, $4)", id, userId, providerId, providerAccountId)
	if err != nil {
		return "", err
	}

	return id, nil
}

func (p *PostgresAdapter) CreateSession(userId string) (string, time.Time, error) {
	id := uuid.New().String()
	expiresAt := time.Now().Add(time.Hour * 24 * 365)

	_, err := p.db.Exec("INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, $3)", id, userId, expiresAt)
	if err != nil {
		return "", time.Now(), err
	}

	return id, expiresAt, nil
}

func (p *PostgresAdapter) CreateUser(email string, name string, avatar *string) (string, error) {
	id := uuid.New().String()

	_, err := p.db.Exec("INSERT INTO users (id, email, name, avatar) VALUES ($1, $2, $3, $4)", id, email, name, avatar)
	if err != nil {
		return "", err
	}

	return id, nil
}

func (p *PostgresAdapter) GetSession(sessionId string) (string, time.Time, error) {
	row := p.db.QueryRow("SELECT user_id, expires_at FROM sessions where id = $1", sessionId)
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

func (p *PostgresAdapter) RemoveSession(sessionId string) error {
	_, err := p.db.Exec("DELETE FROM sessions where id = $1", sessionId)
	return err
}
