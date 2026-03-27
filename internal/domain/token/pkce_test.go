package token

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyPKCE_ValidS256(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	// Compute expected challenge
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	assert.True(t, VerifyPKCE(verifier, challenge, "S256"))
}

func TestVerifyPKCE_WrongVerifier(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	assert.False(t, VerifyPKCE("wrong-verifier", challenge, "S256"))
}

func TestVerifyPKCE_UnsupportedMethod(t *testing.T) {
	assert.False(t, VerifyPKCE("verifier", "challenge", "plain"))
}

func TestVerifyPKCE_EmptyVerifier(t *testing.T) {
	assert.False(t, VerifyPKCE("", "challenge", "S256"))
}

func TestVerifyPKCE_EmptyChallenge(t *testing.T) {
	assert.False(t, VerifyPKCE("verifier", "", "S256"))
}

func TestVerifyPKCE_KnownTestVector(t *testing.T) {
	// RFC 7636 Appendix B test vector
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	expectedChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	assert.True(t, VerifyPKCE(verifier, expectedChallenge, "S256"))
}

func TestVerifyPKCE_ConstantTimeCompare(t *testing.T) {
	// Ensure timing-safe comparison by verifying correct challenge works
	verifier := "test-verifier-12345678901234567890123456789012345"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	assert.True(t, VerifyPKCE(verifier, challenge, "S256"))

	// Flip one character in challenge
	modified := []byte(challenge)
	modified[0] ^= 0x01
	assert.False(t, VerifyPKCE(verifier, string(modified), "S256"))
}
