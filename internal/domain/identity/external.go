package identity

import "time"

// ExternalIdentity links an external provider identity to an internal subject.
type ExternalIdentity struct {
	ID              string
	ProviderID      string
	ExternalSubject string
	InternalSubject string
	TenantID        string
	Email           string
	Name            string
	ProfileData     map[string]any
	LinkedAt        time.Time
	UpdatedAt       time.Time
}

// NewExternalIdentity creates a new ExternalIdentity.
func NewExternalIdentity(id, providerID, externalSubject, internalSubject, tenantID string) (ExternalIdentity, error) {
	if id == "" {
		return ExternalIdentity{}, &ValidationError{Field: "id", Message: "must not be empty"}
	}
	if providerID == "" {
		return ExternalIdentity{}, &ValidationError{Field: "provider_id", Message: "must not be empty"}
	}
	if externalSubject == "" {
		return ExternalIdentity{}, &ValidationError{Field: "external_subject", Message: "must not be empty"}
	}
	if internalSubject == "" {
		return ExternalIdentity{}, &ValidationError{Field: "internal_subject", Message: "must not be empty"}
	}

	now := time.Now().UTC()
	return ExternalIdentity{
		ID:              id,
		ProviderID:      providerID,
		ExternalSubject: externalSubject,
		InternalSubject: internalSubject,
		TenantID:        tenantID,
		ProfileData:     make(map[string]any),
		LinkedAt:        now,
		UpdatedAt:       now,
	}, nil
}
