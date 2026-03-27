package discovery

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetDiscoveryDocument_DefaultIssuer(t *testing.T) {
	svc := NewService("https://auth.example.com", slog.Default())

	doc := svc.GetDiscoveryDocument("")

	assert.Equal(t, "https://auth.example.com", doc.Issuer)
	assert.Equal(t, "https://auth.example.com/authorize", doc.AuthorizationEndpoint)
	assert.Equal(t, "https://auth.example.com/token", doc.TokenEndpoint)
	assert.Equal(t, "https://auth.example.com/jwks", doc.JWKSURI)
}

func TestGetDiscoveryDocument_TenantIssuerOverride(t *testing.T) {
	svc := NewService("https://auth.example.com", slog.Default())

	doc := svc.GetDiscoveryDocument("https://tenant1.example.com")

	assert.Equal(t, "https://tenant1.example.com", doc.Issuer)
	assert.Equal(t, "https://tenant1.example.com/authorize", doc.AuthorizationEndpoint)
	assert.Equal(t, "https://tenant1.example.com/token", doc.TokenEndpoint)
	assert.Equal(t, "https://tenant1.example.com/jwks", doc.JWKSURI)
}

func TestGetDiscoveryDocument_RequiredFields(t *testing.T) {
	svc := NewService("https://auth.example.com", slog.Default())

	doc := svc.GetDiscoveryDocument("")

	assert.NotEmpty(t, doc.ResponseTypesSupported)
	assert.NotEmpty(t, doc.SubjectTypesSupported)
	assert.NotEmpty(t, doc.IDTokenSigningAlgValuesSupported)
	assert.NotEmpty(t, doc.ScopesSupported)
	assert.NotEmpty(t, doc.TokenEndpointAuthMethodsSupported)
	assert.NotEmpty(t, doc.CodeChallengeMethodsSupported)
	assert.NotEmpty(t, doc.GrantTypesSupported)
}

func TestGetDiscoveryDocument_GrantTypes(t *testing.T) {
	svc := NewService("https://auth.example.com", slog.Default())

	doc := svc.GetDiscoveryDocument("")

	assert.Contains(t, doc.GrantTypesSupported, "authorization_code")
}

func TestGetDiscoveryDocument_PKCESupport(t *testing.T) {
	svc := NewService("https://auth.example.com", slog.Default())

	doc := svc.GetDiscoveryDocument("")

	assert.Contains(t, doc.CodeChallengeMethodsSupported, "S256")
}
