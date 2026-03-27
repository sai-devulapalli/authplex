package tenant

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTenant_Valid(t *testing.T) {
	tests := []struct {
		name string
		alg  Algorithm
	}{
		{"RS256", RS256},
		{"ES256", ES256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenant, err := NewTenant("t1", "example.com", "https://example.com", tt.alg)

			require.NoError(t, err)
			assert.Equal(t, "t1", tenant.ID)
			assert.Equal(t, "example.com", tenant.Domain)
			assert.Equal(t, "https://example.com", tenant.Issuer)
			assert.Equal(t, tt.alg, tenant.SigningConfig.Algorithm)
			assert.Empty(t, tenant.SigningConfig.ActiveKeyID)
			assert.False(t, tenant.CreatedAt.IsZero())
			assert.False(t, tenant.UpdatedAt.IsZero())
		})
	}
}

func TestNewTenant_EmptyID(t *testing.T) {
	_, err := NewTenant("", "example.com", "https://example.com", RS256)

	require.Error(t, err)
	var valErr *ValidationError
	require.ErrorAs(t, err, &valErr)
	assert.Equal(t, "id", valErr.Field)
}

func TestNewTenant_EmptyDomain(t *testing.T) {
	_, err := NewTenant("t1", "", "https://example.com", RS256)

	require.Error(t, err)
	var valErr *ValidationError
	require.ErrorAs(t, err, &valErr)
	assert.Equal(t, "domain", valErr.Field)
}

func TestNewTenant_EmptyIssuer(t *testing.T) {
	_, err := NewTenant("t1", "example.com", "", RS256)

	require.Error(t, err)
	var valErr *ValidationError
	require.ErrorAs(t, err, &valErr)
	assert.Equal(t, "issuer", valErr.Field)
}

func TestNewTenant_InvalidAlgorithm(t *testing.T) {
	_, err := NewTenant("t1", "example.com", "https://example.com", Algorithm("PS256"))

	require.Error(t, err)
	var valErr *ValidationError
	require.ErrorAs(t, err, &valErr)
	assert.Equal(t, "algorithm", valErr.Field)
}

func TestValidationError_Error(t *testing.T) {
	err := &ValidationError{Field: "domain", Message: "must not be empty"}
	assert.Equal(t, "tenant validation: domain must not be empty", err.Error())
}

func TestTenant_IsDeleted_False(t *testing.T) {
	tenant, err := NewTenant("t1", "example.com", "https://example.com", RS256)
	require.NoError(t, err)
	assert.False(t, tenant.IsDeleted())
}

func TestTenant_IsDeleted_True(t *testing.T) {
	tenant, err := NewTenant("t1", "example.com", "https://example.com", RS256)
	require.NoError(t, err)
	now := time.Now().UTC()
	tenant.DeletedAt = &now
	assert.True(t, tenant.IsDeleted())
}

func TestMFAPolicy_IsMFARequired(t *testing.T) {
	assert.True(t, MFAPolicy{Required: "required"}.IsMFARequired())
	assert.False(t, MFAPolicy{Required: "optional"}.IsMFARequired())
	assert.False(t, MFAPolicy{Required: "none"}.IsMFARequired())
	assert.False(t, MFAPolicy{}.IsMFARequired())
}
