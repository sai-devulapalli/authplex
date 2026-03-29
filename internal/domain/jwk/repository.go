package jwk

import (
	"context"
	"time"
)

// Repository is the port interface for JWK key pair persistence.
type Repository interface {
	Store(ctx context.Context, kp KeyPair) error
	GetActive(ctx context.Context, tenantID string) (KeyPair, error)
	GetAllPublic(ctx context.Context, tenantID string) ([]KeyPair, error)
	Deactivate(ctx context.Context, keyID string) error
	GetAllActiveTenantIDs(ctx context.Context) ([]string, error)
	DeleteInactive(ctx context.Context, olderThan time.Time) (int64, error)
}
