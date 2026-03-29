package mfa

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWebAuthnCredential_Validate_Valid(t *testing.T) {
	cred := WebAuthnCredential{
		ID:           "cred-1",
		Subject:      "user-1",
		TenantID:     "t1",
		CredentialID: []byte("credid"),
		PublicKey:    []byte("pubkey"),
		CreatedAt:    time.Now().UTC(),
	}
	assert.Nil(t, cred.Validate())
}

func TestWebAuthnCredential_Validate_MissingSubject(t *testing.T) {
	cred := WebAuthnCredential{
		TenantID:     "t1",
		CredentialID: []byte("credid"),
		PublicKey:    []byte("pubkey"),
	}
	err := cred.Validate()
	assert.NotNil(t, err)
	assert.Equal(t, "subject", err.Field)
}

func TestWebAuthnCredential_Validate_MissingTenantID(t *testing.T) {
	cred := WebAuthnCredential{
		Subject:      "user-1",
		CredentialID: []byte("credid"),
		PublicKey:    []byte("pubkey"),
	}
	err := cred.Validate()
	assert.NotNil(t, err)
	assert.Equal(t, "tenant_id", err.Field)
}

func TestWebAuthnCredential_Validate_MissingCredentialID(t *testing.T) {
	cred := WebAuthnCredential{
		Subject:  "user-1",
		TenantID: "t1",
		PublicKey: []byte("pubkey"),
	}
	err := cred.Validate()
	assert.NotNil(t, err)
	assert.Equal(t, "credential_id", err.Field)
}

func TestWebAuthnCredential_Validate_MissingPublicKey(t *testing.T) {
	cred := WebAuthnCredential{
		Subject:      "user-1",
		TenantID:     "t1",
		CredentialID: []byte("credid"),
	}
	err := cred.Validate()
	assert.NotNil(t, err)
	assert.Equal(t, "public_key", err.Field)
}
