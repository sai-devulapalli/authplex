package shared

import "context"

type contextKey string

const tenantIDKey contextKey = "tenant_id"

// TenantFromContext extracts the tenant ID from context.
func TenantFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(tenantIDKey).(string)
	return id, ok
}

// WithTenant returns a context with the tenant ID set.
func WithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantIDKey, tenantID)
}
