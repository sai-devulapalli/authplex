package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDiscoveryDocument(t *testing.T) {
	doc := NewDiscoveryDocument("https://auth.example.com")

	assert.Equal(t, "https://auth.example.com", doc.Issuer)
	assert.Equal(t, "https://auth.example.com/authorize", doc.AuthorizationEndpoint)
	assert.Equal(t, "https://auth.example.com/token", doc.TokenEndpoint)
	assert.Equal(t, "https://auth.example.com/jwks", doc.JWKSURI)
}

func TestNewDiscoveryDocument_ResponseTypes(t *testing.T) {
	doc := NewDiscoveryDocument("https://auth.example.com")

	assert.Equal(t, []string{"code"}, doc.ResponseTypesSupported)
}

func TestNewDiscoveryDocument_SubjectTypes(t *testing.T) {
	doc := NewDiscoveryDocument("https://auth.example.com")

	assert.Equal(t, []string{"public"}, doc.SubjectTypesSupported)
}

func TestNewDiscoveryDocument_SigningAlgorithms(t *testing.T) {
	doc := NewDiscoveryDocument("https://auth.example.com")

	assert.Equal(t, []string{"RS256", "ES256"}, doc.IDTokenSigningAlgValuesSupported)
}

func TestNewDiscoveryDocument_Scopes(t *testing.T) {
	doc := NewDiscoveryDocument("https://auth.example.com")

	assert.Equal(t, []string{"openid", "profile", "email"}, doc.ScopesSupported)
}

func TestNewDiscoveryDocument_TokenEndpointAuth(t *testing.T) {
	doc := NewDiscoveryDocument("https://auth.example.com")

	assert.Equal(t, []string{"none"}, doc.TokenEndpointAuthMethodsSupported)
}

func TestNewDiscoveryDocument_CodeChallengeMethods(t *testing.T) {
	doc := NewDiscoveryDocument("https://auth.example.com")

	assert.Equal(t, []string{"S256"}, doc.CodeChallengeMethodsSupported)
}

func TestNewDiscoveryDocument_GrantTypes(t *testing.T) {
	doc := NewDiscoveryDocument("https://auth.example.com")

	assert.Equal(t, []string{"authorization_code"}, doc.GrantTypesSupported)
}

func TestNewDiscoveryDocument_AllRequiredFieldsPresent(t *testing.T) {
	doc := NewDiscoveryDocument("https://auth.example.com")

	assert.NotEmpty(t, doc.Issuer)
	assert.NotEmpty(t, doc.AuthorizationEndpoint)
	assert.NotEmpty(t, doc.TokenEndpoint)
	assert.NotEmpty(t, doc.JWKSURI)
	assert.NotEmpty(t, doc.ResponseTypesSupported)
	assert.NotEmpty(t, doc.SubjectTypesSupported)
	assert.NotEmpty(t, doc.IDTokenSigningAlgValuesSupported)
	assert.NotEmpty(t, doc.ScopesSupported)
	assert.NotEmpty(t, doc.TokenEndpointAuthMethodsSupported)
	assert.NotEmpty(t, doc.CodeChallengeMethodsSupported)
	assert.NotEmpty(t, doc.GrantTypesSupported)
}
