package identity

import "context"

// ProviderRepository is the port interface for identity provider persistence.
type ProviderRepository interface {
	Create(ctx context.Context, p IdentityProvider) error
	GetByID(ctx context.Context, id string, tenantID string) (IdentityProvider, error)
	GetByType(ctx context.Context, tenantID string, providerType ProviderType) (IdentityProvider, error)
	List(ctx context.Context, tenantID string) ([]IdentityProvider, error)
	Update(ctx context.Context, p IdentityProvider) error
	Delete(ctx context.Context, id string, tenantID string) error
}

// ExternalIdentityRepository is the port interface for external identity persistence.
type ExternalIdentityRepository interface {
	Create(ctx context.Context, ei ExternalIdentity) error
	GetByExternalSubject(ctx context.Context, providerID, externalSubject string) (ExternalIdentity, error)
	GetByInternalSubject(ctx context.Context, tenantID, internalSubject string) ([]ExternalIdentity, error)
	Update(ctx context.Context, ei ExternalIdentity) error
}

// StateRepository stores and retrieves OAuth state for social login roundtrips.
type StateRepository interface {
	Store(ctx context.Context, s OAuthState) error
	Consume(ctx context.Context, state string) (OAuthState, error)
}
