package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewIdentityProvider_Valid(t *testing.T) {
	tests := []struct {
		name         string
		providerType ProviderType
	}{
		{"google", ProviderGoogle},
		{"github", ProviderGitHub},
		{"microsoft", ProviderMicrosoft},
		{"apple", ProviderApple},
		{"oidc", ProviderOIDC},
		{"oauth2", ProviderOAuth2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewIdentityProvider("p1", "t1", tt.providerType, "client-id", []byte("secret"), []string{"openid"})

			require.NoError(t, err)
			assert.Equal(t, "p1", p.ID)
			assert.Equal(t, tt.providerType, p.ProviderType)
			assert.True(t, p.Enabled)
			assert.NotNil(t, p.ExtraConfig)
		})
	}
}

func TestNewIdentityProvider_EmptyID(t *testing.T) {
	_, err := NewIdentityProvider("", "t1", ProviderGoogle, "cid", nil, nil)
	require.Error(t, err)
	var valErr *ValidationError
	require.ErrorAs(t, err, &valErr)
	assert.Equal(t, "id", valErr.Field)
}

func TestNewIdentityProvider_EmptyTenantID(t *testing.T) {
	_, err := NewIdentityProvider("p1", "", ProviderGoogle, "cid", nil, nil)
	require.Error(t, err)
	var valErr *ValidationError
	require.ErrorAs(t, err, &valErr)
	assert.Equal(t, "tenant_id", valErr.Field)
}

func TestNewIdentityProvider_InvalidType(t *testing.T) {
	_, err := NewIdentityProvider("p1", "t1", ProviderType("facebook"), "cid", nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provider_type")
}

func TestNewIdentityProvider_EmptyClientID(t *testing.T) {
	_, err := NewIdentityProvider("p1", "t1", ProviderGoogle, "", nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_id")
}

func TestValidationError_Error(t *testing.T) {
	err := &ValidationError{Field: "id", Message: "must not be empty"}
	assert.Equal(t, "identity validation: id must not be empty", err.Error())
}
