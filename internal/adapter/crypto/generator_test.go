package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyGenerator_GenerateRSA(t *testing.T) {
	gen := NewKeyGenerator()

	privPEM, pubPEM, err := gen.GenerateRSA()

	require.NoError(t, err)
	assert.NotEmpty(t, privPEM)
	assert.NotEmpty(t, pubPEM)

	// Verify PEM structure
	privBlock, _ := pem.Decode(privPEM)
	require.NotNil(t, privBlock)
	assert.Equal(t, "PRIVATE KEY", privBlock.Type)

	pubBlock, _ := pem.Decode(pubPEM)
	require.NotNil(t, pubBlock)
	assert.Equal(t, "PUBLIC KEY", pubBlock.Type)

	// Parse and verify key size
	privKey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	require.NoError(t, err)
	rsaKey, ok := privKey.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, 2048, rsaKey.N.BitLen())
}

func TestKeyGenerator_GenerateEC(t *testing.T) {
	gen := NewKeyGenerator()

	privPEM, pubPEM, err := gen.GenerateEC()

	require.NoError(t, err)
	assert.NotEmpty(t, privPEM)
	assert.NotEmpty(t, pubPEM)

	// Verify PEM structure
	privBlock, _ := pem.Decode(privPEM)
	require.NotNil(t, privBlock)
	assert.Equal(t, "PRIVATE KEY", privBlock.Type)

	pubBlock, _ := pem.Decode(pubPEM)
	require.NotNil(t, pubBlock)
	assert.Equal(t, "PUBLIC KEY", pubBlock.Type)

	// Parse and verify curve
	privKey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	require.NoError(t, err)
	ecKey, ok := privKey.(*ecdsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, elliptic.P256(), ecKey.Curve)
}

func TestKeyGenerator_RSA_PublicKeyParseable(t *testing.T) {
	gen := NewKeyGenerator()

	_, pubPEM, err := gen.GenerateRSA()
	require.NoError(t, err)

	pubBlock, _ := pem.Decode(pubPEM)
	require.NotNil(t, pubBlock)

	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	require.NoError(t, err)

	_, ok := pub.(*rsa.PublicKey)
	assert.True(t, ok)
}

func TestKeyGenerator_EC_PublicKeyParseable(t *testing.T) {
	gen := NewKeyGenerator()

	_, pubPEM, err := gen.GenerateEC()
	require.NoError(t, err)

	pubBlock, _ := pem.Decode(pubPEM)
	require.NotNil(t, pubBlock)

	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	require.NoError(t, err)

	_, ok := pub.(*ecdsa.PublicKey)
	assert.True(t, ok)
}

func TestKeyGenerator_UniqueKeys(t *testing.T) {
	gen := NewKeyGenerator()

	priv1, _, err := gen.GenerateRSA()
	require.NoError(t, err)
	priv2, _, err := gen.GenerateRSA()
	require.NoError(t, err)

	assert.NotEqual(t, priv1, priv2)
}
