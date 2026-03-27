package shared

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithTenant_AndTenantFromContext(t *testing.T) {
	ctx := WithTenant(context.Background(), "tenant-123")

	id, ok := TenantFromContext(ctx)

	assert.True(t, ok)
	assert.Equal(t, "tenant-123", id)
}

func TestTenantFromContext_Missing(t *testing.T) {
	id, ok := TenantFromContext(context.Background())

	assert.False(t, ok)
	assert.Empty(t, id)
}

func TestTenantFromContext_EmptyString(t *testing.T) {
	ctx := WithTenant(context.Background(), "")

	id, ok := TenantFromContext(ctx)

	assert.True(t, ok)
	assert.Empty(t, id)
}

func TestWithTenant_Override(t *testing.T) {
	ctx := WithTenant(context.Background(), "tenant-1")
	ctx = WithTenant(ctx, "tenant-2")

	id, ok := TenantFromContext(ctx)

	assert.True(t, ok)
	assert.Equal(t, "tenant-2", id)
}
