package test

import (
	"database/sql"
	"github.com/TeraWattHour/go-auth/adapters"
	"os"
	"testing"

	"github.com/TeraWattHour/go-auth"
	"github.com/TeraWattHour/go-auth/providers"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"

	_ "github.com/mattn/go-sqlite3"
)

func TestMiddlewareFiber(t *testing.T) {
	app := fiber.New()

	db, err := sql.Open("sqlite3", "test.sqlite3")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	_, err = db.Exec(`
CREATE TABLE if not exists users (
    id TEXT PRIMARY KEY,
    name TEXT,
    email TEXT UNIQUE,
    email_verified_at TEXT,
    avatar TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE if not exists accounts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    provider_id TEXT NOT NULL,
    provider_account_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (provider_id, provider_account_id)
);

CREATE TABLE if not exists sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);
`)
	if err != nil {
		panic(err)
	}

	adapter := adapters.NewSQLiteAdapter(db)

	auth := goauth.NewAuth("/api/auth", adapter, []goauth.Provider{
		providers.Google(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET"), "http://localhost:8080/api/auth/google/callback"),
	})

	authMiddleware := adaptor.HTTPMiddleware(auth.Middleware)
	app.Use(adaptor.HTTPMiddleware(auth.Handlers))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("hello from /")
	})

	app.Get("/protected", authMiddleware, func(c *fiber.Ctx) error {
		return c.SendString("hello from a protected route")
	})

	app.Listen(":8080")
}
