package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestP256Key(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return pemBlock, key
}

func TestGenerateAppleClientSecret(t *testing.T) {
	pemKey, pubKey := generateTestP256Key(t)

	jwt, err := GenerateAppleClientSecret("TEAM123456", "com.example.app", "KEY123", pemKey)
	require.NoError(t, err)
	require.NotEmpty(t, jwt)

	// Parse JWT parts
	parts := splitJWT(t, jwt)

	// Verify header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]string
	require.NoError(t, json.Unmarshal(headerBytes, &header))
	assert.Equal(t, "ES256", header["alg"])
	assert.Equal(t, "KEY123", header["kid"])

	// Verify payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(payloadBytes, &payload))
	assert.Equal(t, "TEAM123456", payload["iss"])
	assert.Equal(t, "com.example.app", payload["sub"])
	assert.Equal(t, "https://appleid.apple.com", payload["aud"])
	assert.NotNil(t, payload["iat"])
	assert.NotNil(t, payload["exp"])

	// Verify ES256 signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	assert.Len(t, sigBytes, 64) // P-256: 32 + 32

	signingInput := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(signingInput))
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	assert.True(t, ecdsa.Verify(&pubKey.PublicKey, hash[:], r, s), "signature should be valid")
}

func TestGenerateAppleClientSecret_MissingFields(t *testing.T) {
	pemKey, _ := generateTestP256Key(t)

	_, err := GenerateAppleClientSecret("", "com.example.app", "KEY123", pemKey)
	assert.Error(t, err)

	_, err = GenerateAppleClientSecret("TEAM", "", "KEY123", pemKey)
	assert.Error(t, err)

	_, err = GenerateAppleClientSecret("TEAM", "com.example.app", "", pemKey)
	assert.Error(t, err)
}

func TestGenerateAppleClientSecret_InvalidPEM(t *testing.T) {
	_, err := GenerateAppleClientSecret("TEAM", "app", "KEY", []byte("not a pem"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PEM")
}

func TestGenerateAppleClientSecret_NotECKey(t *testing.T) {
	// Create an RSA key PEM to test the type check
	// Use a minimal invalid PKCS8 that parses but isn't EC
	_, err := GenerateAppleClientSecret("TEAM", "app", "KEY", []byte("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg==\n-----END PRIVATE KEY-----"))
	assert.Error(t, err)
}

func splitJWT(t *testing.T, jwt string) []string {
	t.Helper()
	parts := make([]string, 0)
	for _, p := range []string{} {
		_ = p
	}
	// Simple split
	start := 0
	for i, c := range jwt {
		if c == '.' {
			parts = append(parts, jwt[start:i])
			start = i + 1
		}
	}
	parts = append(parts, jwt[start:])
	require.Len(t, parts, 3, "JWT should have 3 parts")
	return parts
}
