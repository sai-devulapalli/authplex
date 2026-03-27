package identity

import "time"

// OAuthState stores the state for the social login roundtrip (CSRF protection).
type OAuthState struct {
	State               string
	TenantID            string
	ProviderID          string
	OriginalClientID    string
	OriginalRedirectURI string
	OriginalScope       string
	OriginalState       string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	Subject             string
	ExpiresAt           time.Time
}

// IsExpired returns true if the state has passed its TTL.
func (s OAuthState) IsExpired() bool {
	return time.Now().UTC().After(s.ExpiresAt)
}
