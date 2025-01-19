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

	_ "github.com/lib/pq"
)

func TestMiddlewareFiber(t *testing.T) {
	app := fiber.New()

	db, err := sql.Open("postgres", os.Getenv("DB"))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	adapter := adapters.NewPostgresAdapter(db)

	auth := goauth.NewAuth("/api/auth", adapter, []goauth.Provider{
		providers.Github(os.Getenv("ClientId"), os.Getenv("ClientSecret")),
	})

	authMiddleware := adaptor.HTTPMiddleware(auth.Middleware)
	app.Use(adaptor.HTTPMiddleware(auth.Handlers))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("hello from /")
	})

	app.Get("/protected", authMiddleware, func(c *fiber.Ctx) error {
		return c.SendString("hello from a protected route")
	})

	app.Listen(":3000")
}
