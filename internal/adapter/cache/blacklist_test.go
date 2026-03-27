package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlacklist_RevokeAndCheck(t *testing.T) {
	bl := NewInMemoryBlacklist()
	ctx := context.Background()

	require.NoError(t, bl.Revoke(ctx, "jti-123", time.Now().Add(1*time.Hour)))

	revoked, err := bl.IsRevoked(ctx, "jti-123")
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestBlacklist_NotRevoked(t *testing.T) {
	bl := NewInMemoryBlacklist()
	ctx := context.Background()

	revoked, err := bl.IsRevoked(ctx, "jti-unknown")
	require.NoError(t, err)
	assert.False(t, revoked)
}
