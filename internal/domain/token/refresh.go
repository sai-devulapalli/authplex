package token

import "time"

// RefreshToken represents an issued refresh token with rotation tracking.
type RefreshToken struct {
	ID        string
	Token     string
	ClientID  string
	Subject   string
	TenantID  string
	Scope     string
	FamilyID  string // token family for replay detection
	ExpiresAt time.Time
	CreatedAt time.Time
	RevokedAt *time.Time
	Rotated   bool
}

// IsExpiredRefresh returns true if the refresh token has passed its TTL.
func (rt RefreshToken) IsExpiredRefresh() bool {
	return time.Now().UTC().After(rt.ExpiresAt)
}

// IsRevoked returns true if the refresh token has been revoked.
func (rt RefreshToken) IsRevoked() bool {
	return rt.RevokedAt != nil
}
