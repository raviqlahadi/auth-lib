// Package middleware provides a framework-agnostic token extractor and
// validator that works with any router that speaks net/http.
//
// Wrap the Authenticate helper inside your framework's own middleware type:
//
//	// Gin example
//	func GinAuthMiddleware(a *auth.Auth) gin.HandlerFunc {
//	    return func(c *gin.Context) {
//	        claims, err := middleware.Authenticate(a, c.Request)
//	        if err != nil {
//	            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
//	            return
//	        }
//	        ctx := middleware.WithClaims(c.Request.Context(), claims)
//	        c.Request = c.Request.WithContext(ctx)
//	        c.Next()
//	    }
//	}
package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/raviqlahadi/auth-lib/token"
)

// claimsKey is the unexported context key used to store Claims values.
// Using a private type prevents collisions with other packages.
type claimsKey struct{}

// Authenticator is the minimal interface that middleware needs from *auth.Auth.
// Accepting an interface (rather than the concrete type) keeps this package
// decoupled and makes it trivial to mock in tests.
type Authenticator interface {
	ValidateAccessToken(tokenStr string) (*token.Claims, error)
}

// Authenticate extracts the Bearer token from the Authorization header of r,
// validates it, and returns the embedded Claims.
//
// It does NOT write any HTTP response — that is the caller's responsibility —
// so it fits naturally into any framework's middleware chain.
func Authenticate(a Authenticator, r *http.Request) (*token.Claims, error) {
	raw, err := extractBearerToken(r)
	if err != nil {
		return nil, err
	}
	return a.ValidateAccessToken(raw)
}

// WithClaims returns a new context that carries the provided Claims.
// Downstream handlers retrieve them via ClaimsFromContext.
func WithClaims(ctx context.Context, claims *token.Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

// ClaimsFromContext retrieves the Claims stored by WithClaims.
// Returns (nil, false) if no Claims are present.
func ClaimsFromContext(ctx context.Context) (*token.Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(*token.Claims)
	return c, ok
}

// HTTPMiddleware wraps a standard http.Handler, rejecting requests that
// carry no valid access token. On success it stores the Claims in the request
// context so that next can read them with ClaimsFromContext.
//
// Use this directly with net/http, chi, gorilla/mux, etc.
//
//	mux.Handle("/api/profile", middleware.HTTPMiddleware(auth, profileHandler))
func HTTPMiddleware(a Authenticator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := Authenticate(a, r)
		if err != nil {
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := WithClaims(r.Context(), claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// extractBearerToken pulls the raw JWT from the Authorization header.
// It expects the standard "Bearer <token>" format.
func extractBearerToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", errors.New("missing Authorization header")
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", errors.New("Authorization header must use Bearer scheme")
	}

	raw := strings.TrimPrefix(header, prefix)
	if raw == "" {
		return "", errors.New("Bearer token is empty")
	}

	return raw, nil
}
