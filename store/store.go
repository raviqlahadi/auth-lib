// Package store defines the SessionStore interface for managing refresh-token
// sessions. By depending on this interface rather than a concrete type,
// auth-lib is completely decoupled from any storage backend (Redis, SQL,
// in-memory, etc.). Consumers supply their own implementation.
package store

import "context"

// Session holds the data that is persisted for a single refresh-token session.
type Session struct {
	// UserID is the subject this session belongs to.
	UserID string

	// RefreshToken is the raw signed refresh-token string.
	RefreshToken string

	// Metadata is an open map that callers can use to store anything
	// extra (e.g. device fingerprint, IP address, scopes).
	Metadata map[string]string
}

// SessionStore is the storage abstraction that auth-lib relies on.
// Provide any implementation — Redis, PostgreSQL, in-memory, etc. —
// and pass it via WithSessionStore when constructing an Auth instance.
//
// All methods accept a context so that implementations can respect
// cancellation and deadlines from the calling HTTP handler.
type SessionStore interface {
	// Save persists a Session under the given key (typically the
	// refresh-token ID / jti claim). Implementations should overwrite
	// any existing entry with the same key.
	Save(ctx context.Context, key string, session Session) error

	// Get retrieves the Session associated with key.
	// Returns (session, nil) on success, or (Session{}, ErrNotFound) if
	// the key does not exist or has expired.
	Get(ctx context.Context, key string) (Session, error)

	// Delete removes the Session identified by key. A no-op (nil error)
	// is acceptable when the key is already absent.
	Delete(ctx context.Context, key string) error
}

// ErrNotFound is the canonical sentinel error that SessionStore
// implementations should return from Get when a key is missing.
var ErrNotFound = storeError("session not found")

type storeError string

func (e storeError) Error() string { return string(e) }
