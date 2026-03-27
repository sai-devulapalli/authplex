package token

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClaims_Fields(t *testing.T) {
	emailVerified := true
	claims := Claims{
		Issuer:        "https://auth.example.com",
		Subject:       "user-123",
		Audience:      []string{"client-1"},
		ExpiresAt:     1700000000,
		IssuedAt:      1699996400,
		JWTID:         "jti-abc",
		Nonce:         "nonce-xyz",
		Email:         "user@example.com",
		EmailVerified: &emailVerified,
		Name:          "Test User",
	}

	assert.Equal(t, "https://auth.example.com", claims.Issuer)
	assert.Equal(t, "user-123", claims.Subject)
	assert.Equal(t, []string{"client-1"}, claims.Audience)
	assert.Equal(t, int64(1700000000), claims.ExpiresAt)
	assert.Equal(t, int64(1699996400), claims.IssuedAt)
	assert.Equal(t, "jti-abc", claims.JWTID)
	assert.Equal(t, "nonce-xyz", claims.Nonce)
	assert.Equal(t, "user@example.com", claims.Email)
	assert.True(t, *claims.EmailVerified)
	assert.Equal(t, "Test User", claims.Name)
}

func TestTokenResponse_Fields(t *testing.T) {
	resp := TokenResponse{
		AccessToken: "at-123",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		IDToken:     "id-456",
		Scope:       "openid profile",
	}

	assert.Equal(t, "at-123", resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, 3600, resp.ExpiresIn)
	assert.Equal(t, "id-456", resp.IDToken)
	assert.Equal(t, "openid profile", resp.Scope)
}
