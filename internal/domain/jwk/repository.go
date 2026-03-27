package jwk

import "context"

// Repository is the port interface for JWK key pair persistence.
type Repository interface {
	Store(ctx context.Context, kp KeyPair) error
	GetActive(ctx context.Context, tenantID string) (KeyPair, error)
	GetAllPublic(ctx context.Context, tenantID string) ([]KeyPair, error)
	Deactivate(ctx context.Context, keyID string) error
}
