// Package main demonstrates auth-lib wired into a plain net/http server.
// This example ships an in-memory SessionStore so it has zero dependencies
// beyond the standard library and auth-lib itself.
//
// Run:   go run ./examples/http_example
// Then:
//
//	curl -s -X POST http://localhost:8080/login | jq .
//	ACCESS=$(curl -s -X POST http://localhost:8080/login | jq -r .access_token)
//	curl -s -H "Authorization: Bearer $ACCESS" http://localhost:8080/profile | jq .
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	auth "github.com/raviqlahadi/auth-lib"
	"github.com/raviqlahadi/auth-lib/middleware"
	"github.com/raviqlahadi/auth-lib/store"
)

// ---------------------------------------------------------------------------
// In-memory SessionStore (example implementation — not for production)
// ---------------------------------------------------------------------------

type memStore struct {
	mu       sync.RWMutex
	sessions map[string]store.Session
}

func newMemStore() *memStore { return &memStore{sessions: make(map[string]store.Session)} }

func (m *memStore) Save(_ context.Context, key string, s store.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[key] = s
	return nil
}

func (m *memStore) Get(_ context.Context, key string) (store.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[key]
	if !ok {
		return store.Session{}, store.ErrNotFound
	}
	return s, nil
}

func (m *memStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, key)
	return nil
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func loginHandler(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// In a real app: verify credentials from DB here.
		pair, err := a.IssueTokenPair(r.Context(), "user-42", map[string]any{
			"role": "admin",
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"access_token":  pair.AccessToken,
			"refresh_token": pair.RefreshToken,
		})
	}
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "no claims in context", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"user_id": claims.Subject,
		"custom":  claims.Custom,
		"expires": claims.ExpiresAt.Time.Format(time.RFC3339),
	})
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	secret := []byte(os.Getenv("JWT_SECRET"))
	if len(secret) < 32 {
		// Fallback for the demo — never do this in production.
		secret = []byte("super-secret-key-replace-in-prod!")
	}

	a, err := auth.NewAuth(
		auth.WithSecretKey(secret),
		auth.WithAccessTokenTTL(15*time.Minute),
		auth.WithRefreshTokenTTL(7*24*time.Hour),
		auth.WithSessionStore(newMemStore()),
		auth.WithIssuer("auth-lib-example"),
	)
	if err != nil {
		log.Fatal("auth setup:", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", loginHandler(a))
	mux.Handle("/profile", middleware.HTTPMiddleware(a, http.HandlerFunc(profileHandler)))

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
