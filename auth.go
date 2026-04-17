// Package auth is the public entry-point of auth-lib.
//
// Typical usage:
//
//	a, err := auth.NewAuth(
//	    auth.WithSecretKey([]byte(os.Getenv("JWT_SECRET"))),
//	    auth.WithAccessTokenTTL(15*time.Minute),
//	    auth.WithRefreshTokenTTL(7*24*time.Hour),
//	    auth.WithSessionStore(myRedisStore),
//	)
//
// The returned *Auth value is safe for concurrent use.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/raviqlahadi/auth-lib/store"
	"github.com/raviqlahadi/auth-lib/token"
)

// ---------------------------------------------------------------------------
// Configuration & Functional Options
// ---------------------------------------------------------------------------

// config holds all tunable parameters for an Auth instance.
// Zero values are treated as "not set"; NewAuth validates required fields.
type config struct {
	secretKey       []byte
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	sessionStore    store.SessionStore
	issuer          string
}

// defaults returns a config pre-populated with sensible values.
func defaults() config {
	return config{
		accessTokenTTL:  15 * time.Minute,
		refreshTokenTTL: 7 * 24 * time.Hour,
	}
}

// Option is a functional option that mutates the internal config.
// Callers pass one or more Options to NewAuth.
type Option func(*config)

// WithSecretKey sets the HMAC-SHA256 signing secret.
// This option is REQUIRED — NewAuth returns an error if it is absent.
func WithSecretKey(key []byte) Option {
	return func(c *config) { c.secretKey = key }
}

// WithAccessTokenTTL overrides the default access-token lifetime (15 min).
func WithAccessTokenTTL(d time.Duration) Option {
	return func(c *config) { c.accessTokenTTL = d }
}

// WithRefreshTokenTTL overrides the default refresh-token lifetime (7 days).
func WithRefreshTokenTTL(d time.Duration) Option {
	return func(c *config) { c.refreshTokenTTL = d }
}

// WithSessionStore injects the SessionStore implementation.
// This option is REQUIRED — NewAuth returns an error if it is absent.
//
// Provide any type that satisfies store.SessionStore (Redis, SQL, in-memory, …).
func WithSessionStore(s store.SessionStore) Option {
	return func(c *config) { c.sessionStore = s }
}

// WithIssuer sets the "iss" claim on every generated token.
func WithIssuer(iss string) Option {
	return func(c *config) { c.issuer = iss }
}

// ---------------------------------------------------------------------------
// Auth — the public API surface
// ---------------------------------------------------------------------------

// Auth is the central object that issues and validates JWT tokens and manages
// refresh-token sessions via the injected SessionStore.
//
// Create one instance per application and reuse it across handlers.
type Auth struct {
	cfg config
}

// NewAuth constructs an Auth instance, applying each Option in order and then
// validating that all required fields are present.
//
//	a, err := auth.NewAuth(
//	    auth.WithSecretKey(secret),
//	    auth.WithSessionStore(redisStore),
//	)
func NewAuth(options ...Option) (*Auth, error) {
	cfg := defaults()

	for _, opt := range options {
		opt(&cfg)
	}

	// --- validation ---------------------------------------------------------
	if len(cfg.secretKey) == 0 {
		return nil, errors.New("auth-lib: WithSecretKey is required")
	}
	if len(cfg.secretKey) < 32 {
		return nil, errors.New("auth-lib: secret key must be at least 32 bytes")
	}
	if cfg.sessionStore == nil {
		return nil, errors.New("auth-lib: WithSessionStore is required")
	}
	if cfg.accessTokenTTL <= 0 {
		return nil, errors.New("auth-lib: accessTokenTTL must be positive")
	}
	if cfg.refreshTokenTTL <= 0 {
		return nil, errors.New("auth-lib: refreshTokenTTL must be positive")
	}
	// ------------------------------------------------------------------------

	return &Auth{cfg: cfg}, nil
}

// ---------------------------------------------------------------------------
// Token issuance
// ---------------------------------------------------------------------------

// TokenPair bundles an access token and a refresh token together.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

// IssueTokenPair creates a fresh access + refresh token pair for subject
// (typically a user ID or username).
//
// custom may be nil or contain arbitrary caller-defined claims (roles, tenant, …).
// The refresh-token session is persisted to the SessionStore automatically.
func (a *Auth) IssueTokenPair(ctx context.Context, subject string, custom map[string]any) (TokenPair, error) {
	// --- access token -------------------------------------------------------
	accessJTI, err := newJTI()
	if err != nil {
		return TokenPair{}, fmt.Errorf("auth-lib: generate access jti: %w", err)
	}

	accessClaims := token.NewClaims(subject, accessJTI, a.cfg.accessTokenTTL, token.AccessToken, custom)
	if a.cfg.issuer != "" {
		accessClaims.Issuer = a.cfg.issuer
	}

	accessTok, err := token.Sign(accessClaims, a.cfg.secretKey)
	if err != nil {
		return TokenPair{}, err
	}

	// --- refresh token -------------------------------------------------------
	refreshJTI, err := newJTI()
	if err != nil {
		return TokenPair{}, fmt.Errorf("auth-lib: generate refresh jti: %w", err)
	}

	refreshClaims := token.NewClaims(subject, refreshJTI, a.cfg.refreshTokenTTL, token.RefreshToken, nil)
	if a.cfg.issuer != "" {
		refreshClaims.Issuer = a.cfg.issuer
	}

	refreshTok, err := token.Sign(refreshClaims, a.cfg.secretKey)
	if err != nil {
		return TokenPair{}, err
	}

	// --- persist session -----------------------------------------------------
	session := store.Session{
		UserID:       subject,
		RefreshToken: refreshTok,
	}
	if err := a.cfg.sessionStore.Save(ctx, refreshJTI, session); err != nil {
		return TokenPair{}, fmt.Errorf("auth-lib: save session: %w", err)
	}

	return TokenPair{
		AccessToken:  accessTok,
		RefreshToken: refreshTok,
	}, nil
}

// ---------------------------------------------------------------------------
// Token validation
// ---------------------------------------------------------------------------

// ValidateAccessToken parses and validates an access token string,
// returning its Claims on success.
func (a *Auth) ValidateAccessToken(tokenStr string) (*token.Claims, error) {
	return token.Parse(tokenStr, a.cfg.secretKey, token.AccessToken)
}

// ValidateRefreshToken parses the refresh token, verifies it exists in the
// SessionStore, and returns its Claims. Call this before issuing a new pair.
func (a *Auth) ValidateRefreshToken(ctx context.Context, tokenStr string) (*token.Claims, error) {
	claims, err := token.Parse(tokenStr, a.cfg.secretKey, token.RefreshToken)
	if err != nil {
		return nil, err
	}

	// Confirm the session is still live in the store.
	if _, err := a.cfg.sessionStore.Get(ctx, claims.ID); err != nil {
		return nil, fmt.Errorf("auth-lib: refresh session not found or expired: %w", err)
	}

	return claims, nil
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

// RevokeRefreshToken deletes the session identified by the refresh-token's
// jti claim, effectively logging the user out on that device.
func (a *Auth) RevokeRefreshToken(ctx context.Context, tokenStr string) error {
	claims, err := token.Parse(tokenStr, a.cfg.secretKey, token.RefreshToken)
	if err != nil {
		return err
	}
	return a.cfg.sessionStore.Delete(ctx, claims.ID)
}

// RotateTokens validates the incoming refresh token, revokes the old session,
// and issues a brand-new TokenPair — implementing refresh-token rotation to
// limit the damage of a stolen refresh token.
func (a *Auth) RotateTokens(ctx context.Context, refreshTokenStr string, custom map[string]any) (TokenPair, error) {
	claims, err := a.ValidateRefreshToken(ctx, refreshTokenStr)
	if err != nil {
		return TokenPair{}, fmt.Errorf("auth-lib: rotate: %w", err)
	}

	// Revoke old session first (detect reuse attacks).
	if err := a.cfg.sessionStore.Delete(ctx, claims.ID); err != nil {
		return TokenPair{}, fmt.Errorf("auth-lib: rotate: revoke old session: %w", err)
	}

	return a.IssueTokenPair(ctx, claims.Subject, custom)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newJTI generates a cryptographically random 16-byte hex string to use as
// a JWT ID (jti) and session store key.
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
