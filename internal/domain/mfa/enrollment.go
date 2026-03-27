package mfa

import "time"

// TOTPEnrollment represents a TOTP enrollment for a user.
type TOTPEnrollment struct {
	ID        string
	Subject   string
	TenantID  string
	Secret    []byte // raw secret bytes
	Confirmed bool
	CreatedAt time.Time
}

// MFARequirement defines the MFA requirement level for a tenant.
type MFARequirement string

const (
	MFANone     MFARequirement = "none"
	MFAOptional MFARequirement = "optional"
	MFARequired MFARequirement = "required"
)

// MFAPolicy defines the MFA configuration for a tenant.
type MFAPolicy struct {
	Required MFARequirement `json:"required"`
	Methods  []string       `json:"methods"`
}

// IsRequired returns true if MFA is required.
func (p MFAPolicy) IsRequired() bool {
	return p.Required == MFARequired
}

// HasMethod checks if a method is enabled.
func (p MFAPolicy) HasMethod(method string) bool {
	for _, m := range p.Methods {
		if m == method {
			return true
		}
	}
	return false
}
