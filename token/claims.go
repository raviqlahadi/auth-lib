// Package token handles all JWT creation, signing, and validation logic.
package token

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenType distinguishes access tokens from refresh tokens so that
// each cannot be used in place of the other.
type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)

// Claims is the JWT payload used by auth-lib.
//
// It embeds jwt.RegisteredClaims so that standard fields (sub, exp, iat, jti,
// iss, aud) are handled automatically by golang-jwt/jwt.
//
// Custom contains any caller-supplied key/value data that should be embedded
// directly in the token (e.g. roles, tenant, plan). Keep it small — JWTs
// travel in every HTTP request header.
type Claims struct {
	jwt.RegisteredClaims

	// TokenType distinguishes access from refresh tokens.
	TokenType TokenType `json:"token_type"`

	// Custom holds arbitrary caller-defined claims.
	// Example: map[string]any{"role": "admin", "tenant": "acme"}
	Custom map[string]any `json:"custom,omitempty"`
}

// NewClaims builds a Claims value ready to be signed.
//
//   - subject  — the user / entity the token represents (maps to jwt "sub")
//   - jti      — a unique ID for this token, used as the store key for refresh tokens
//   - ttl      — how long until the token expires
//   - ttype    — AccessToken or RefreshToken
//   - custom   — caller-supplied extra claims (may be nil)
func NewClaims(subject, jti string, ttl time.Duration, ttype TokenType, custom map[string]any) Claims {
	now := time.Now()
	return Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		TokenType: ttype,
		Custom:    custom,
	}
}
