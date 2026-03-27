package user

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUser_Valid(t *testing.T) {
	u, err := NewUser("u1", "t1", "user@example.com", "Test User")

	require.NoError(t, err)
	assert.Equal(t, "u1", u.ID)
	assert.Equal(t, "t1", u.TenantID)
	assert.Equal(t, "user@example.com", u.Email)
	assert.Equal(t, "Test User", u.Name)
	assert.False(t, u.EmailVerified)
	assert.True(t, u.Enabled)
	assert.False(t, u.CreatedAt.IsZero())
	assert.Nil(t, u.DeletedAt)
}

func TestNewUser_EmailNormalized(t *testing.T) {
	u, err := NewUser("u1", "t1", "  User@EXAMPLE.com  ", "Name")

	require.NoError(t, err)
	assert.Equal(t, "user@example.com", u.Email)
}

func TestNewUser_EmptyID(t *testing.T) {
	_, err := NewUser("", "t1", "a@b.com", "Name")
	require.Error(t, err)
	var valErr *ValidationError
	require.ErrorAs(t, err, &valErr)
	assert.Equal(t, "id", valErr.Field)
}

func TestNewUser_EmptyTenantID(t *testing.T) {
	_, err := NewUser("u1", "", "a@b.com", "Name")
	require.Error(t, err)
}

func TestNewUser_EmptyEmail(t *testing.T) {
	_, err := NewUser("u1", "t1", "", "Name")
	require.Error(t, err)
}

func TestNewUser_InvalidEmail(t *testing.T) {
	tests := []string{"notanemail", "missing@", "@nodomain", "no@dot"}
	for _, email := range tests {
		t.Run(email, func(t *testing.T) {
			_, err := NewUser("u1", "t1", email, "Name")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "email")
		})
	}
}

func TestNewUser_EmptyName(t *testing.T) {
	_, err := NewUser("u1", "t1", "a@b.com", "")
	require.Error(t, err)
}

func TestUser_IsDeleted(t *testing.T) {
	u, _ := NewUser("u1", "t1", "a@b.com", "Name")
	assert.False(t, u.IsDeleted())

	now := time.Now()
	u.DeletedAt = &now
	assert.True(t, u.IsDeleted())
}

func TestUser_IsActive(t *testing.T) {
	u, _ := NewUser("u1", "t1", "a@b.com", "Name")
	assert.True(t, u.IsActive())

	u.Enabled = false
	assert.False(t, u.IsActive())

	u.Enabled = true
	now := time.Now()
	u.DeletedAt = &now
	assert.False(t, u.IsActive())
}

func TestValidationError_Error(t *testing.T) {
	err := &ValidationError{Field: "email", Message: "invalid format"}
	assert.Equal(t, "user validation: email invalid format", err.Error())
}

func TestIsValidEmail(t *testing.T) {
	assert.True(t, isValidEmail("user@example.com"))
	assert.True(t, isValidEmail("a@b.co"))
	assert.False(t, isValidEmail(""))
	assert.False(t, isValidEmail("noat"))
	assert.False(t, isValidEmail("@no.com"))
	assert.False(t, isValidEmail("no@dot"))
}
