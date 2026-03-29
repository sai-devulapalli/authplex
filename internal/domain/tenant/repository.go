package tenant

import "context"

// Repository is the port interface for tenant persistence.
type Repository interface {
	GetByID(ctx context.Context, id string) (Tenant, error)
	GetByDomain(ctx context.Context, domain string) (Tenant, error)
	Create(ctx context.Context, tenant Tenant) error
	Update(ctx context.Context, tenant Tenant) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, offset, limit int) ([]Tenant, int, error)
	IncrementTokenVersion(ctx context.Context, id string) error
}
