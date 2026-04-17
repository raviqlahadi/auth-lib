package auth_test

import (
	"context"
	"testing"
	"time"

	auth "github.com/raviqlahadi/auth-lib"
	"github.com/raviqlahadi/auth-lib/store"
)

// ---------------------------------------------------------------------------
// Minimal in-memory store for tests
// ---------------------------------------------------------------------------

type testStore struct{ sessions map[string]store.Session }

func newTestStore() *testStore { return &testStore{sessions: make(map[string]store.Session)} }

func (s *testStore) Save(_ context.Context, key string, sess store.Session) error {
	s.sessions[key] = sess
	return nil
}
func (s *testStore) Get(_ context.Context, key string) (store.Session, error) {
	sess, ok := s.sessions[key]
	if !ok {
		return store.Session{}, store.ErrNotFound
	}
	return sess, nil
}
func (s *testStore) Delete(_ context.Context, key string) error {
	delete(s.sessions, key)
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mustNewAuth(t *testing.T, opts ...auth.Option) *auth.Auth {
	t.Helper()
	base := []auth.Option{
		auth.WithSecretKey([]byte("test-secret-key-must-be-32-bytes!!")),
		auth.WithSessionStore(newTestStore()),
	}
	a, err := auth.NewAuth(append(base, opts...)...)
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	return a
}

// ---------------------------------------------------------------------------
// NewAuth / functional options
// ---------------------------------------------------------------------------

func TestNewAuth_MissingSecretKey(t *testing.T) {
	_, err := auth.NewAuth(auth.WithSessionStore(newTestStore()))
	if err == nil {
		t.Fatal("expected error for missing secret key")
	}
}

func TestNewAuth_ShortSecretKey(t *testing.T) {
	_, err := auth.NewAuth(
		auth.WithSecretKey([]byte("short")),
		auth.WithSessionStore(newTestStore()),
	)
	if err == nil {
		t.Fatal("expected error for key < 32 bytes")
	}
}

func TestNewAuth_MissingSessionStore(t *testing.T) {
	_, err := auth.NewAuth(auth.WithSecretKey([]byte("test-secret-key-must-be-32-bytes!!")))
	if err == nil {
		t.Fatal("expected error for missing session store")
	}
}

func TestNewAuth_ValidConfig(t *testing.T) {
	_ = mustNewAuth(t) // must not panic or error
}

// ---------------------------------------------------------------------------
// IssueTokenPair / ValidateAccessToken
// ---------------------------------------------------------------------------

func TestIssueAndValidateAccessToken(t *testing.T) {
	a := mustNewAuth(t)
	ctx := context.Background()

	pair, err := a.IssueTokenPair(ctx, "user-1", map[string]any{"role": "admin"})
	if err != nil {
		t.Fatalf("IssueTokenPair: %v", err)
	}

	claims, err := a.ValidateAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("subject: got %q, want %q", claims.Subject, "user-1")
	}
	if claims.Custom["role"] != "admin" {
		t.Errorf("custom role: got %v, want admin", claims.Custom["role"])
	}
}

func TestRefreshTokenCannotBeUsedAsAccessToken(t *testing.T) {
	a := mustNewAuth(t)
	ctx := context.Background()

	pair, _ := a.IssueTokenPair(ctx, "user-2", nil)

	_, err := a.ValidateAccessToken(pair.RefreshToken)
	if err == nil {
		t.Fatal("expected error when using refresh token as access token")
	}
}

// ---------------------------------------------------------------------------
// RotateTokens
// ---------------------------------------------------------------------------

func TestRotateTokens(t *testing.T) {
	a := mustNewAuth(t)
	ctx := context.Background()

	pair1, _ := a.IssueTokenPair(ctx, "user-3", nil)

	pair2, err := a.RotateTokens(ctx, pair1.RefreshToken, nil)
	if err != nil {
		t.Fatalf("RotateTokens: %v", err)
	}

	// Old refresh token must be revoked.
	_, err = a.ValidateRefreshToken(ctx, pair1.RefreshToken)
	if err == nil {
		t.Fatal("old refresh token should be invalid after rotation")
	}

	// New pair must work.
	if _, err := a.ValidateAccessToken(pair2.AccessToken); err != nil {
		t.Errorf("new access token invalid: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TTL / expiry
// ---------------------------------------------------------------------------

func TestExpiredAccessToken(t *testing.T) {
	a := mustNewAuth(t, auth.WithAccessTokenTTL(1*time.Millisecond))
	ctx := context.Background()

	pair, _ := a.IssueTokenPair(ctx, "user-4", nil)
	time.Sleep(5 * time.Millisecond)

	_, err := a.ValidateAccessToken(pair.AccessToken)
	if err == nil {
		t.Fatal("expected error for expired access token")
	}
}

// ---------------------------------------------------------------------------
// RevokeRefreshToken
// ---------------------------------------------------------------------------

func TestRevokeRefreshToken(t *testing.T) {
	a := mustNewAuth(t)
	ctx := context.Background()

	pair, _ := a.IssueTokenPair(ctx, "user-5", nil)

	if err := a.RevokeRefreshToken(ctx, pair.RefreshToken); err != nil {
		t.Fatalf("RevokeRefreshToken: %v", err)
	}

	_, err := a.ValidateRefreshToken(ctx, pair.RefreshToken)
	if err == nil {
		t.Fatal("expected error after revoking refresh token")
	}
}
