package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient_Valid(t *testing.T) {
	c, err := NewClient("c1", "t1", "Test App", Public,
		[]string{"https://example.com/callback"},
		[]string{"openid", "profile"},
		[]GrantType{GrantAuthorizationCode})

	require.NoError(t, err)
	assert.Equal(t, "c1", c.ID)
	assert.Equal(t, "t1", c.TenantID)
	assert.Equal(t, "Test App", c.ClientName)
	assert.Equal(t, Public, c.ClientType)
	assert.Equal(t, []string{"https://example.com/callback"}, c.RedirectURIs)
	assert.False(t, c.CreatedAt.IsZero())
	assert.Nil(t, c.DeletedAt)
}

func TestNewClient_Confidential(t *testing.T) {
	c, err := NewClient("c1", "t1", "Server App", Confidential,
		[]string{"https://example.com/callback"},
		[]string{"openid"},
		[]GrantType{GrantAuthorizationCode, GrantClientCredentials, GrantRefreshToken})

	require.NoError(t, err)
	assert.Equal(t, Confidential, c.ClientType)
	assert.Len(t, c.AllowedGrantTypes, 3)
}

func TestNewClient_EmptyID(t *testing.T) {
	_, err := NewClient("", "t1", "App", Public, nil, nil, nil)
	require.Error(t, err)
	var valErr *ValidationError
	require.ErrorAs(t, err, &valErr)
	assert.Equal(t, "id", valErr.Field)
}

func TestNewClient_EmptyTenantID(t *testing.T) {
	_, err := NewClient("c1", "", "App", Public, nil, nil, nil)
	require.Error(t, err)
	var valErr *ValidationError
	require.ErrorAs(t, err, &valErr)
	assert.Equal(t, "tenant_id", valErr.Field)
}

func TestNewClient_EmptyName(t *testing.T) {
	_, err := NewClient("c1", "t1", "", Public, nil, nil, nil)
	require.Error(t, err)
	var valErr *ValidationError
	require.ErrorAs(t, err, &valErr)
	assert.Equal(t, "client_name", valErr.Field)
}

func TestNewClient_InvalidClientType(t *testing.T) {
	_, err := NewClient("c1", "t1", "App", ClientType("hybrid"), nil, nil, nil)
	require.Error(t, err)
	var valErr *ValidationError
	require.ErrorAs(t, err, &valErr)
	assert.Equal(t, "client_type", valErr.Field)
}

func TestNewClient_PublicCannotUseClientCredentials(t *testing.T) {
	_, err := NewClient("c1", "t1", "App", Public,
		nil, nil, []GrantType{GrantClientCredentials})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public clients cannot use client_credentials")
}

func TestNewClient_InvalidGrantType(t *testing.T) {
	_, err := NewClient("c1", "t1", "App", Public,
		nil, nil, []GrantType{GrantType("invalid")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid grant type")
}

func TestNewClient_InvalidRedirectURI(t *testing.T) {
	_, err := NewClient("c1", "t1", "App", Public,
		[]string{"http://evil.com/callback"}, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTPS")
}

func TestNewClient_LocalhostHTTPAllowed(t *testing.T) {
	c, err := NewClient("c1", "t1", "App", Public,
		[]string{"http://localhost:3000/callback"}, nil, nil)
	require.NoError(t, err)
	assert.Len(t, c.RedirectURIs, 1)
}

func TestClient_HasGrantType(t *testing.T) {
	c, _ := NewClient("c1", "t1", "App", Confidential,
		nil, nil, []GrantType{GrantAuthorizationCode, GrantRefreshToken})

	assert.True(t, c.HasGrantType(GrantAuthorizationCode))
	assert.True(t, c.HasGrantType(GrantRefreshToken))
	assert.False(t, c.HasGrantType(GrantClientCredentials))
}

func TestClient_HasRedirectURI(t *testing.T) {
	c, _ := NewClient("c1", "t1", "App", Public,
		[]string{"https://a.com/cb", "https://b.com/cb"}, nil, nil)

	assert.True(t, c.HasRedirectURI("https://a.com/cb"))
	assert.False(t, c.HasRedirectURI("https://evil.com/cb"))
}

func TestClient_HasScope(t *testing.T) {
	c, _ := NewClient("c1", "t1", "App", Public,
		nil, []string{"openid", "profile"}, nil)

	assert.True(t, c.HasScope("openid"))
	assert.False(t, c.HasScope("admin"))
}

func TestClient_IsDeleted(t *testing.T) {
	c, _ := NewClient("c1", "t1", "App", Public, nil, nil, nil)
	assert.False(t, c.IsDeleted())
}

func TestValidateRedirectURI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"valid https", "https://example.com/cb", false},
		{"localhost http", "http://localhost:3000/cb", false},
		{"127.0.0.1 http", "http://127.0.0.1:8080/cb", false},
		{"non-localhost http", "http://evil.com/cb", true},
		{"no scheme", "example.com/cb", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRedirectURI(tt.uri)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestClient_ValidateScopes_AllValid(t *testing.T) {
	c, _ := NewClient("c1", "t1", "App", Public,
		nil, []string{"openid", "profile", "email"}, nil)

	invalid := c.ValidateScopes("openid profile")
	assert.Nil(t, invalid)
}

func TestClient_ValidateScopes_SomeInvalid(t *testing.T) {
	c, _ := NewClient("c1", "t1", "App", Public,
		nil, []string{"openid", "profile"}, nil)

	invalid := c.ValidateScopes("openid admin")
	assert.Equal(t, []string{"admin"}, invalid)
}

func TestClient_ValidateScopes_AllInvalid(t *testing.T) {
	c, _ := NewClient("c1", "t1", "App", Public,
		nil, []string{"openid"}, nil)

	invalid := c.ValidateScopes("admin write")
	assert.Len(t, invalid, 2)
}

func TestClient_ValidateScopes_NoRestrictions(t *testing.T) {
	c, _ := NewClient("c1", "t1", "App", Public, nil, nil, nil)

	invalid := c.ValidateScopes("anything goes")
	assert.Nil(t, invalid)
}

func TestClient_ValidateScopes_EmptyRequest(t *testing.T) {
	c, _ := NewClient("c1", "t1", "App", Public,
		nil, []string{"openid"}, nil)

	invalid := c.ValidateScopes("")
	assert.Nil(t, invalid)
}

func TestValidationError_Error(t *testing.T) {
	err := &ValidationError{Field: "id", Message: "must not be empty"}
	assert.Equal(t, "client validation: id must not be empty", err.Error())
}
