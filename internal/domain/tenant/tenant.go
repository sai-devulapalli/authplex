package tenant

import "time"

// Algorithm represents a JWT signing algorithm.
type Algorithm string

const (
	RS256 Algorithm = "RS256"
	ES256 Algorithm = "ES256"
)

// SigningConfig holds the tenant's JWT signing configuration.
type SigningConfig struct {
	Algorithm   Algorithm
	ActiveKeyID string
}

// MFAPolicy defines the MFA configuration for a tenant.
type MFAPolicy struct {
	Required string   `json:"required"` // "none", "optional", "required"
	Methods  []string `json:"methods"`  // e.g., ["totp"]
}

// IsMFARequired returns true if MFA is required for this tenant.
func (p MFAPolicy) IsMFARequired() bool {
	return p.Required == "required"
}

// Tenant represents an isolated identity provider tenant.
type Tenant struct {
	ID            string
	Domain        string
	Issuer        string
	SigningConfig SigningConfig
	MFA           MFAPolicy
	TokenVersion  int
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     *time.Time
}

// IsDeleted returns true if the tenant has been soft-deleted.
func (t Tenant) IsDeleted() bool {
	return t.DeletedAt != nil
}

// NewTenant creates a new Tenant with the given parameters.
// Validates required fields and returns an error if invalid.
func NewTenant(id, domain, issuer string, alg Algorithm) (Tenant, error) {
	if id == "" {
		return Tenant{}, &ValidationError{Field: "id", Message: "must not be empty"}
	}
	if domain == "" {
		return Tenant{}, &ValidationError{Field: "domain", Message: "must not be empty"}
	}
	if issuer == "" {
		return Tenant{}, &ValidationError{Field: "issuer", Message: "must not be empty"}
	}
	switch alg {
	case RS256, ES256:
		// valid
	default:
		return Tenant{}, &ValidationError{Field: "algorithm", Message: "must be RS256 or ES256"}
	}

	now := time.Now().UTC()
	return Tenant{
		ID:     id,
		Domain: domain,
		Issuer: issuer,
		SigningConfig: SigningConfig{
			Algorithm: alg,
		},
		TokenVersion: 1,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}
