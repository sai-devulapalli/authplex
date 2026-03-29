package mfa

import "time"

// WebAuthnCredential represents a stored WebAuthn/FIDO2 credential for a user.
type WebAuthnCredential struct {
	ID              string
	Subject         string
	TenantID        string
	CredentialID    []byte
	PublicKey       []byte
	AAGUID          []byte
	SignCount       uint32
	AttestationType string
	DisplayName     string
	CreatedAt       time.Time
}

// Validate checks that the credential has the minimum required fields.
func (c WebAuthnCredential) Validate() *ValidationError {
	if c.Subject == "" {
		return &ValidationError{Field: "subject", Message: "is required"}
	}
	if c.TenantID == "" {
		return &ValidationError{Field: "tenant_id", Message: "is required"}
	}
	if len(c.CredentialID) == 0 {
		return &ValidationError{Field: "credential_id", Message: "is required"}
	}
	if len(c.PublicKey) == 0 {
		return &ValidationError{Field: "public_key", Message: "is required"}
	}
	return nil
}
