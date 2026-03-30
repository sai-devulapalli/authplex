package webhook

import "context"

// Repository is the port interface for webhook persistence.
type Repository interface {
	Create(ctx context.Context, w Webhook) error
	GetByID(ctx context.Context, id, tenantID string) (Webhook, error)
	List(ctx context.Context, tenantID string) ([]Webhook, error)
	Delete(ctx context.Context, id, tenantID string) error
	ListByEvent(ctx context.Context, tenantID, eventType string) ([]Webhook, error)
}
