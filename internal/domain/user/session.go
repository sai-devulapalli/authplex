package user

import "time"

// Session represents an authenticated user session.
// Stored server-side (opaque token, not JWT) for instant invalidation.
type Session struct {
	ID        string
	UserID    string
	TenantID  string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// NewSession creates a validated Session.
func NewSession(id, userID, tenantID string, ttl time.Duration) (Session, error) {
	if id == "" {
		return Session{}, &ValidationError{Field: "id", Message: "must not be empty"}
	}
	if userID == "" {
		return Session{}, &ValidationError{Field: "user_id", Message: "must not be empty"}
	}

	now := time.Now().UTC()
	return Session{
		ID:        id,
		UserID:    userID,
		TenantID:  tenantID,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}, nil
}

// IsExpired returns true if the session has passed its TTL.
func (s Session) IsExpired() bool {
	return time.Now().UTC().After(s.ExpiresAt)
}
