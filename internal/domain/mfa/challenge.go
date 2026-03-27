package mfa

import "time"

// MFAChallenge represents a pending MFA verification during the authorize flow.
type MFAChallenge struct {
	ID        string
	Subject   string
	TenantID  string
	Methods   []string
	ExpiresAt time.Time
	Verified  bool
	// Original authorize request fields (serialized for completion after MFA)
	OriginalClientID    string
	OriginalRedirectURI string
	OriginalScope       string
	OriginalState       string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
}

// IsExpired returns true if the challenge has expired.
func (c MFAChallenge) IsExpired() bool {
	return time.Now().UTC().After(c.ExpiresAt)
}
