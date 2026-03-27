package cache

import (
	"context"
	"testing"

	"github.com/authcore/internal/domain/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshRepo_StoreAndGet(t *testing.T) {
	repo := NewInMemoryRefreshRepository()
	ctx := context.Background()

	rt := token.RefreshToken{
		Token:    "rt-123",
		ClientID: "c1",
		Subject:  "user-1",
		FamilyID: "fam-1",
	}
	require.NoError(t, repo.Store(ctx, rt))

	got, err := repo.GetByToken(ctx, "rt-123")
	require.NoError(t, err)
	assert.Equal(t, "c1", got.ClientID)
	assert.Equal(t, "fam-1", got.FamilyID)
}

func TestRefreshRepo_GetNotFound(t *testing.T) {
	repo := NewInMemoryRefreshRepository()
	_, err := repo.GetByToken(context.Background(), "nonexistent")
	require.Error(t, err)
}

func TestRefreshRepo_RevokeByToken(t *testing.T) {
	repo := NewInMemoryRefreshRepository()
	ctx := context.Background()

	rt := token.RefreshToken{Token: "rt-123"}
	repo.Store(ctx, rt) //nolint:errcheck

	require.NoError(t, repo.RevokeByToken(ctx, "rt-123"))

	got, _ := repo.GetByToken(ctx, "rt-123")
	assert.True(t, got.IsRevoked())
}

func TestRefreshRepo_RevokeFamily(t *testing.T) {
	repo := NewInMemoryRefreshRepository()
	ctx := context.Background()

	repo.Store(ctx, token.RefreshToken{Token: "rt-1", FamilyID: "fam-1"}) //nolint:errcheck
	repo.Store(ctx, token.RefreshToken{Token: "rt-2", FamilyID: "fam-1"}) //nolint:errcheck
	repo.Store(ctx, token.RefreshToken{Token: "rt-3", FamilyID: "fam-2"}) //nolint:errcheck

	require.NoError(t, repo.RevokeFamily(ctx, "fam-1"))

	rt1, _ := repo.GetByToken(ctx, "rt-1")
	assert.True(t, rt1.IsRevoked())
	rt2, _ := repo.GetByToken(ctx, "rt-2")
	assert.True(t, rt2.IsRevoked())
	rt3, _ := repo.GetByToken(ctx, "rt-3")
	assert.False(t, rt3.IsRevoked())
}
