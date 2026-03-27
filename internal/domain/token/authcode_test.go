package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAuthorizationCode_IsExpired_True(t *testing.T) {
	ac := AuthorizationCode{
		Code:      "code-1",
		ExpiresAt: time.Now().UTC().Add(-1 * time.Minute),
	}

	assert.True(t, ac.IsExpired())
}

func TestAuthorizationCode_IsExpired_False(t *testing.T) {
	ac := AuthorizationCode{
		Code:      "code-1",
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	}

	assert.False(t, ac.IsExpired())
}

func TestAuthorizationCode_Fields(t *testing.T) {
	ac := AuthorizationCode{
		Code:                "code-1",
		ClientID:            "client-1",
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid profile",
		Subject:             "user-123",
		TenantID:            "tenant-1",
		CodeChallenge:       "challenge-abc",
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-xyz",
		ExpiresAt:           time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	assert.Equal(t, "code-1", ac.Code)
	assert.Equal(t, "client-1", ac.ClientID)
	assert.Equal(t, "https://example.com/callback", ac.RedirectURI)
	assert.Equal(t, "openid profile", ac.Scope)
	assert.Equal(t, "user-123", ac.Subject)
	assert.Equal(t, "tenant-1", ac.TenantID)
	assert.Equal(t, "challenge-abc", ac.CodeChallenge)
	assert.Equal(t, "S256", ac.CodeChallengeMethod)
	assert.Equal(t, "nonce-xyz", ac.Nonce)
}
