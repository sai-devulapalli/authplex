package jwk

import "time"

// KeyType represents the cryptographic key type (RFC 7517).
type KeyType string

const (
	RSA KeyType = "RSA"
	EC  KeyType = "EC"
)

// KeyUse represents the intended use of the key (RFC 7517).
type KeyUse string

const (
	Sig KeyUse = "sig"
)

// KeyPair holds a cryptographic key pair for JWT signing.
type KeyPair struct {
	ID         string
	TenantID   string
	KeyType    KeyType
	Algorithm  string
	Use        KeyUse
	PrivateKey []byte
	PublicKey  []byte
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	Active     bool
}

// NewKeyPair creates a validated KeyPair.
func NewKeyPair(id, tenantID string, keyType KeyType, algorithm string, privateKey, publicKey []byte) (KeyPair, error) {
	if id == "" {
		return KeyPair{}, &ValidationError{Field: "id", Message: "must not be empty"}
	}
	if tenantID == "" {
		return KeyPair{}, &ValidationError{Field: "tenant_id", Message: "must not be empty"}
	}
	switch keyType {
	case RSA, EC:
		// valid
	default:
		return KeyPair{}, &ValidationError{Field: "key_type", Message: "must be RSA or EC"}
	}
	if len(privateKey) == 0 {
		return KeyPair{}, &ValidationError{Field: "private_key", Message: "must not be empty"}
	}
	if len(publicKey) == 0 {
		return KeyPair{}, &ValidationError{Field: "public_key", Message: "must not be empty"}
	}

	return KeyPair{
		ID:         id,
		TenantID:   tenantID,
		KeyType:    keyType,
		Algorithm:  algorithm,
		Use:        Sig,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		CreatedAt:  time.Now().UTC(),
		Active:     true,
	}, nil
}

// PublicJWK is the JSON Web Key representation for the JWKS response (RFC 7517).
type PublicJWK struct {
	KTY string `json:"kty"`
	Use string `json:"use"`
	KID string `json:"kid"`
	ALG string `json:"alg"`
	// RSA fields
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// EC fields
	CRV string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// Set is the JWKS document (RFC 7517 Section 5).
type Set struct {
	Keys []PublicJWK `json:"keys"`
}
