package cache

import (
	"context"
	"testing"

	"github.com/authcore/internal/domain/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWKRepo_StoreAndGetActive(t *testing.T) {
	repo := NewInMemoryJWKRepository()
	ctx := context.Background()

	kp, _ := jwk.NewKeyPair("kid-1", "t1", jwk.RSA, "RS256", []byte("priv"), []byte("pub"))
	require.NoError(t, repo.Store(ctx, kp))

	active, err := repo.GetActive(ctx, "t1")
	require.NoError(t, err)
	assert.Equal(t, "kid-1", active.ID)
}

func TestJWKRepo_GetActive_NotFound(t *testing.T) {
	repo := NewInMemoryJWKRepository()
	_, err := repo.GetActive(context.Background(), "nonexistent")
	require.Error(t, err)
}

func TestJWKRepo_GetAllPublic(t *testing.T) {
	repo := NewInMemoryJWKRepository()
	ctx := context.Background()
	kp1, _ := jwk.NewKeyPair("k1", "t1", jwk.RSA, "RS256", []byte("p"), []byte("p"))
	kp2, _ := jwk.NewKeyPair("k2", "t1", jwk.EC, "ES256", []byte("p"), []byte("p"))
	repo.Store(ctx, kp1) //nolint:errcheck
	repo.Store(ctx, kp2) //nolint:errcheck

	pairs, err := repo.GetAllPublic(ctx, "t1")
	require.NoError(t, err)
	assert.Len(t, pairs, 2)
}

func TestJWKRepo_Deactivate(t *testing.T) {
	repo := NewInMemoryJWKRepository()
	ctx := context.Background()
	kp, _ := jwk.NewKeyPair("k1", "t1", jwk.RSA, "RS256", []byte("p"), []byte("p"))
	repo.Store(ctx, kp) //nolint:errcheck

	require.NoError(t, repo.Deactivate(ctx, "k1"))
	_, err := repo.GetActive(ctx, "t1")
	require.Error(t, err)
}

func TestJWKRepo_Deactivate_NotFound(t *testing.T) {
	repo := NewInMemoryJWKRepository()
	err := repo.Deactivate(context.Background(), "nonexistent")
	require.Error(t, err)
}
