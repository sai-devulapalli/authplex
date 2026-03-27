package jwk

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeyPair_Valid(t *testing.T) {
	tests := []struct {
		name    string
		keyType KeyType
		alg     string
	}{
		{"RSA/RS256", RSA, "RS256"},
		{"EC/ES256", EC, "ES256"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp, err := NewKeyPair("kid-1", "tenant-1", tt.keyType, tt.alg, []byte("priv"), []byte("pub"))

			require.NoError(t, err)
			assert.Equal(t, "kid-1", kp.ID)
			assert.Equal(t, "tenant-1", kp.TenantID)
			assert.Equal(t, tt.keyType, kp.KeyType)
			assert.Equal(t, tt.alg, kp.Algorithm)
			assert.Equal(t, Sig, kp.Use)
			assert.Equal(t, []byte("priv"), kp.PrivateKey)
			assert.Equal(t, []byte("pub"), kp.PublicKey)
			assert.True(t, kp.Active)
			assert.False(t, kp.CreatedAt.IsZero())
			assert.Nil(t, kp.ExpiresAt)
		})
	}
}

func TestNewKeyPair_EmptyID(t *testing.T) {
	_, err := NewKeyPair("", "tenant-1", RSA, "RS256", []byte("priv"), []byte("pub"))

	require.Error(t, err)
	var valErr *ValidationError
	require.ErrorAs(t, err, &valErr)
	assert.Equal(t, "id", valErr.Field)
}

func TestNewKeyPair_EmptyTenantID(t *testing.T) {
	_, err := NewKeyPair("kid-1", "", RSA, "RS256", []byte("priv"), []byte("pub"))

	require.Error(t, err)
	var valErr *ValidationError
	require.ErrorAs(t, err, &valErr)
	assert.Equal(t, "tenant_id", valErr.Field)
}

func TestNewKeyPair_InvalidKeyType(t *testing.T) {
	_, err := NewKeyPair("kid-1", "tenant-1", KeyType("OKP"), "EdDSA", []byte("priv"), []byte("pub"))

	require.Error(t, err)
	var valErr *ValidationError
	require.ErrorAs(t, err, &valErr)
	assert.Equal(t, "key_type", valErr.Field)
}

func TestNewKeyPair_EmptyPrivateKey(t *testing.T) {
	_, err := NewKeyPair("kid-1", "tenant-1", RSA, "RS256", nil, []byte("pub"))

	require.Error(t, err)
	var valErr *ValidationError
	require.ErrorAs(t, err, &valErr)
	assert.Equal(t, "private_key", valErr.Field)
}

func TestNewKeyPair_EmptyPublicKey(t *testing.T) {
	_, err := NewKeyPair("kid-1", "tenant-1", RSA, "RS256", []byte("priv"), nil)

	require.Error(t, err)
	var valErr *ValidationError
	require.ErrorAs(t, err, &valErr)
	assert.Equal(t, "public_key", valErr.Field)
}

func TestValidationError_Error(t *testing.T) {
	err := &ValidationError{Field: "id", Message: "must not be empty"}
	assert.Equal(t, "jwk validation: id must not be empty", err.Error())
}

func TestPublicJWK_JSONFields(t *testing.T) {
	jwk := PublicJWK{
		KTY: "RSA",
		Use: "sig",
		KID: "kid-1",
		ALG: "RS256",
		N:   "modulus",
		E:   "exponent",
	}

	assert.Equal(t, "RSA", jwk.KTY)
	assert.Equal(t, "sig", jwk.Use)
	assert.Equal(t, "kid-1", jwk.KID)
	assert.Equal(t, "RS256", jwk.ALG)
	assert.Equal(t, "modulus", jwk.N)
	assert.Equal(t, "exponent", jwk.E)
	assert.Empty(t, jwk.CRV)
	assert.Empty(t, jwk.X)
	assert.Empty(t, jwk.Y)
}

func TestSet_EmptyKeys(t *testing.T) {
	set := Set{Keys: []PublicJWK{}}
	assert.Empty(t, set.Keys)
}
