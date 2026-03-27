package token

import "time"

// AuthorizationCode represents a stored auth code pending exchange.
type AuthorizationCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	Scope               string
	Subject             string
	TenantID            string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	ExpiresAt           time.Time
}

// IsExpired returns true if the code has passed its TTL.
func (ac AuthorizationCode) IsExpired() bool {
	return time.Now().UTC().After(ac.ExpiresAt)
}
