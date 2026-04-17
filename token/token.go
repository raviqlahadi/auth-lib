package token

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Sign creates a signed JWT string from the provided Claims using HMAC-SHA256.
func Sign(claims Claims, secretKey []byte) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := t.SignedString(secretKey)
	if err != nil {
		return "", fmt.Errorf("auth-lib: sign token: %w", err)
	}
	return signed, nil
}

// Parse validates the token string and returns the embedded Claims.
// It enforces:
//   - valid HMAC-SHA256 signature
//   - token not expired
//   - expected TokenType (prevents using a refresh token as an access token)
func Parse(tokenStr string, secretKey []byte, expected TokenType) (*Claims, error) {
	var claims Claims

	t, err := jwt.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("auth-lib: unexpected signing method: %v", t.Header["alg"])
		}
		return secretKey, nil
	}, jwt.WithExpirationRequired())

	if err != nil {
		return nil, fmt.Errorf("auth-lib: parse token: %w", err)
	}
	if !t.Valid {
		return nil, errors.New("auth-lib: token is invalid")
	}
	if claims.TokenType != expected {
		return nil, fmt.Errorf("auth-lib: wrong token type: got %q, want %q", claims.TokenType, expected)
	}

	return &claims, nil
}
