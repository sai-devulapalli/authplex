package token

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// VerifyPKCE validates the code_verifier against the stored code_challenge.
// Only S256 method is supported (RFC 7636).
func VerifyPKCE(verifier, challenge, method string) bool {
	if method != "S256" {
		return false
	}
	if verifier == "" || challenge == "" {
		return false
	}

	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])

	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}
