package crypto

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWKConverter_RSA(t *testing.T) {
	gen := NewKeyGenerator()
	conv := NewJWKConverter()

	_, pubPEM, err := gen.GenerateRSA()
	require.NoError(t, err)

	jwk, err := conv.PEMToPublicJWK(pubPEM, "rsa-kid-1", "RS256")

	require.NoError(t, err)
	assert.Equal(t, "RSA", jwk.KTY)
	assert.Equal(t, "sig", jwk.Use)
	assert.Equal(t, "rsa-kid-1", jwk.KID)
	assert.Equal(t, "RS256", jwk.ALG)
	assert.NotEmpty(t, jwk.N)
	assert.NotEmpty(t, jwk.E)
	assert.Empty(t, jwk.CRV)
	assert.Empty(t, jwk.X)
	assert.Empty(t, jwk.Y)
}

func TestJWKConverter_EC(t *testing.T) {
	gen := NewKeyGenerator()
	conv := NewJWKConverter()

	_, pubPEM, err := gen.GenerateEC()
	require.NoError(t, err)

	jwk, err := conv.PEMToPublicJWK(pubPEM, "ec-kid-1", "ES256")

	require.NoError(t, err)
	assert.Equal(t, "EC", jwk.KTY)
	assert.Equal(t, "sig", jwk.Use)
	assert.Equal(t, "ec-kid-1", jwk.KID)
	assert.Equal(t, "ES256", jwk.ALG)
	assert.Equal(t, "P-256", jwk.CRV)
	assert.NotEmpty(t, jwk.X)
	assert.NotEmpty(t, jwk.Y)
	assert.Empty(t, jwk.N)
	assert.Empty(t, jwk.E)
}

func TestJWKConverter_RSA_Base64URLEncoded(t *testing.T) {
	gen := NewKeyGenerator()
	conv := NewJWKConverter()

	_, pubPEM, err := gen.GenerateRSA()
	require.NoError(t, err)

	jwk, err := conv.PEMToPublicJWK(pubPEM, "kid", "RS256")
	require.NoError(t, err)

	// N and E must be valid base64url
	_, err = base64.RawURLEncoding.DecodeString(jwk.N)
	assert.NoError(t, err)
	_, err = base64.RawURLEncoding.DecodeString(jwk.E)
	assert.NoError(t, err)
}

func TestJWKConverter_EC_Base64URLEncoded(t *testing.T) {
	gen := NewKeyGenerator()
	conv := NewJWKConverter()

	_, pubPEM, err := gen.GenerateEC()
	require.NoError(t, err)

	jwk, err := conv.PEMToPublicJWK(pubPEM, "kid", "ES256")
	require.NoError(t, err)

	// X and Y must be valid base64url with 32-byte values (P-256)
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	assert.NoError(t, err)
	assert.Equal(t, 32, len(xBytes))

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	assert.NoError(t, err)
	assert.Equal(t, 32, len(yBytes))
}

func TestJWKConverter_InvalidPEM(t *testing.T) {
	conv := NewJWKConverter()

	_, err := conv.PEMToPublicJWK([]byte("not-a-pem"), "kid", "RS256")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")
}

func TestJWKConverter_InvalidDER(t *testing.T) {
	conv := NewJWKConverter()

	badPEM := []byte("-----BEGIN PUBLIC KEY-----\nZm9v\n-----END PUBLIC KEY-----\n")
	_, err := conv.PEMToPublicJWK(badPEM, "kid", "RS256")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse public key")
}
