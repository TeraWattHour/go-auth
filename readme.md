# GoAuth

GoAuth is a library for handling OAuth2 authentication flows server side. 
It provides basic infrastructure to easily incorporate auth into your
HTTP app. The implemented mechanisms mimic the way Auth.js (previously [next-auth](https://github.com/nextauthjs/next-auth)) 
works.

## Installation

```bash
go get github.com/terawatthour/go-auth
```

## Usage

1. Select (or create - its easy) your preferred database adapter and apply its required schema.
```go
import (
    "database/sql"
    "github.com/TeraWattHour/go-auth/adapters"
    _ "github.com/lib/pq"
)

db, _ := sql.Open("postgres", os.Getenv("DB"))
adapter := adapters.NewPostgresAdapter(db)
```

2. Pick the auth providers you want enabled.
```go
import "github.com/TeraWattHour/go-auth"
auth := goauth.NewAuth("/api/auth", adapter, []goauth.Provider{
    providers.Github(os.Getenv("ClientId"), os.Getenv("ClientSecret")),
})
```
Handled route paths will all begin with the chosen prefix, in this example`/api/auth`.

3. Use the provided handlers with your framework of choice, eg. Fiber.
```go
authMiddleware := adaptor.HTTPMiddleware(auth.Middleware)
app.Use(adaptor.HTTPMiddleware(auth.Handlers))
```
