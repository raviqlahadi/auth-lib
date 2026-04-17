# auth-lib

A reusable, framework-agnostic Go authentication library built on Clean Architecture principles.

## Features

| Feature | Details |
|---|---|
| **JWT Management** | Access + Refresh tokens via `golang-jwt/jwt` v5, HMAC-SHA256 |
| **Custom Claims** | Embed arbitrary `map[string]any` data in every token |
| **Dependency Inversion** | `store.SessionStore` interface — bring Redis, SQL, or anything |
| **Functional Options** | `NewAuth(opts ...Option)` — zero-value safe, validated at construction |
| **Framework-agnostic Middleware** | `middleware.Authenticate` works with `net/http`, Gin, Echo, chi, … |
| **Refresh-token Rotation** | `RotateTokens` revokes the old session before issuing a new pair |

## Project Structure

```
auth-lib/
├── auth.go                    # Public API: Auth struct, NewAuth, IssueTokenPair, Rotate…
├── auth_test.go               # Unit tests (zero external test dependencies)
├── go.mod
├── store/
│   └── store.go               # SessionStore interface + ErrNotFound sentinel
├── token/
│   ├── claims.go              # Claims struct (embeds jwt.RegisteredClaims + Custom)
│   └── token.go               # Sign() / Parse() helpers
├── middleware/
│   └── middleware.go          # Authenticate, HTTPMiddleware, context helpers
└── examples/
    └── http_example/
        └── main.go            # Runnable demo with in-memory store
```

## Quick Start

```go
import (
    auth "github.com/raviqlahadi/auth-lib"
    "github.com/raviqlahadi/auth-lib/middleware"
)

a, err := auth.NewAuth(
    auth.WithSecretKey([]byte(os.Getenv("JWT_SECRET"))),   // required, ≥32 bytes
    auth.WithAccessTokenTTL(15 * time.Minute),
    auth.WithRefreshTokenTTL(7 * 24 * time.Hour),
    auth.WithSessionStore(myRedisStore),                    // required
    auth.WithIssuer("my-service"),
)

// Issue tokens on login
pair, err := a.IssueTokenPair(ctx, userID, map[string]any{"role": "admin"})

// Validate in a handler
claims, err := a.ValidateAccessToken(rawToken)

// Wrap any http.Handler
mux.Handle("/api/", middleware.HTTPMiddleware(a, apiRouter))

// Read claims downstream
claims, ok := middleware.ClaimsFromContext(r.Context())
```

## Implementing SessionStore

```go
type RedisStore struct{ client *redis.Client }

func (s *RedisStore) Save(ctx context.Context, key string, sess store.Session) error {
    data, _ := json.Marshal(sess)
    return s.client.Set(ctx, key, data, 7*24*time.Hour).Err()
}
func (s *RedisStore) Get(ctx context.Context, key string) (store.Session, error) {
    data, err := s.client.Get(ctx, key).Bytes()
    if errors.Is(err, redis.Nil) { return store.Session{}, store.ErrNotFound }
    var sess store.Session
    json.Unmarshal(data, &sess)
    return sess, nil
}
func (s *RedisStore) Delete(ctx context.Context, key string) error {
    return s.client.Del(ctx, key).Err()
}
```

## Wrapping for Gin

```go
func AuthMiddleware(a *auth.Auth) gin.HandlerFunc {
    return func(c *gin.Context) {
        claims, err := middleware.Authenticate(a, c.Request)
        if err != nil {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
            return
        }
        ctx := middleware.WithClaims(c.Request.Context(), claims)
        c.Request = c.Request.WithContext(ctx)
        c.Next()
    }
}
```

## Running Tests

```bash
go test ./...
```
