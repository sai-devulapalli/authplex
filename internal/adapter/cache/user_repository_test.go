package cache

import (
	"context"
	"testing"

	"github.com/authcore/internal/domain/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserRepo_CreateAndGetByID(t *testing.T) {
	repo := NewInMemoryUserRepository()
	ctx := context.Background()

	u, _ := user.NewUser("u1", "t1", "user@example.com", "Test")
	require.NoError(t, repo.Create(ctx, u))

	got, err := repo.GetByID(ctx, "u1", "t1")
	require.NoError(t, err)
	assert.Equal(t, "u1", got.ID)
	assert.Equal(t, "user@example.com", got.Email)
}

func TestUserRepo_GetByEmail(t *testing.T) {
	repo := NewInMemoryUserRepository()
	ctx := context.Background()

	u, _ := user.NewUser("u1", "t1", "user@example.com", "Test")
	repo.Create(ctx, u) //nolint:errcheck

	got, err := repo.GetByEmail(ctx, "user@example.com", "t1")
	require.NoError(t, err)
	assert.Equal(t, "u1", got.ID)
}

func TestUserRepo_GetByEmail_CaseInsensitive(t *testing.T) {
	repo := NewInMemoryUserRepository()
	ctx := context.Background()

	u, _ := user.NewUser("u1", "t1", "user@example.com", "Test")
	repo.Create(ctx, u) //nolint:errcheck

	got, err := repo.GetByEmail(ctx, "USER@EXAMPLE.COM", "t1")
	require.NoError(t, err)
	assert.Equal(t, "u1", got.ID)
}

func TestUserRepo_DuplicateEmail_SameTenant(t *testing.T) {
	repo := NewInMemoryUserRepository()
	ctx := context.Background()

	u1, _ := user.NewUser("u1", "t1", "user@example.com", "User 1")
	require.NoError(t, repo.Create(ctx, u1))

	u2, _ := user.NewUser("u2", "t1", "user@example.com", "User 2")
	err := repo.Create(ctx, u2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestUserRepo_SameEmail_DifferentTenants(t *testing.T) {
	repo := NewInMemoryUserRepository()
	ctx := context.Background()

	u1, _ := user.NewUser("u1", "t1", "user@example.com", "User 1")
	u2, _ := user.NewUser("u2", "t2", "user@example.com", "User 2")

	require.NoError(t, repo.Create(ctx, u1))
	require.NoError(t, repo.Create(ctx, u2))
}

func TestUserRepo_GetByID_NotFound(t *testing.T) {
	repo := NewInMemoryUserRepository()
	_, err := repo.GetByID(context.Background(), "nonexistent", "t1")
	require.Error(t, err)
}

func TestUserRepo_GetByID_WrongTenant(t *testing.T) {
	repo := NewInMemoryUserRepository()
	ctx := context.Background()

	u, _ := user.NewUser("u1", "t1", "a@b.com", "Name")
	repo.Create(ctx, u) //nolint:errcheck

	_, err := repo.GetByID(ctx, "u1", "t2")
	require.Error(t, err)
}

func TestUserRepo_Update(t *testing.T) {
	repo := NewInMemoryUserRepository()
	ctx := context.Background()

	u, _ := user.NewUser("u1", "t1", "a@b.com", "Old")
	repo.Create(ctx, u) //nolint:errcheck

	u.Name = "New"
	require.NoError(t, repo.Update(ctx, u))

	got, _ := repo.GetByID(ctx, "u1", "t1")
	assert.Equal(t, "New", got.Name)
}

func TestUserRepo_Delete(t *testing.T) {
	repo := NewInMemoryUserRepository()
	ctx := context.Background()

	u, _ := user.NewUser("u1", "t1", "a@b.com", "Name")
	repo.Create(ctx, u) //nolint:errcheck

	require.NoError(t, repo.Delete(ctx, "u1", "t1"))

	_, err := repo.GetByID(ctx, "u1", "t1")
	require.Error(t, err)
}
