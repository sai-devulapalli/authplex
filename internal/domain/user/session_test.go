package user

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSession_Valid(t *testing.T) {
	s, err := NewSession("sess-1", "user-1", "t1", 24*time.Hour)

	require.NoError(t, err)
	assert.Equal(t, "sess-1", s.ID)
	assert.Equal(t, "user-1", s.UserID)
	assert.Equal(t, "t1", s.TenantID)
	assert.False(t, s.CreatedAt.IsZero())
	assert.True(t, s.ExpiresAt.After(s.CreatedAt))
}

func TestNewSession_EmptyID(t *testing.T) {
	_, err := NewSession("", "user-1", "t1", time.Hour)
	require.Error(t, err)
}

func TestNewSession_EmptyUserID(t *testing.T) {
	_, err := NewSession("sess-1", "", "t1", time.Hour)
	require.Error(t, err)
}

func TestSession_IsExpired(t *testing.T) {
	s, _ := NewSession("s1", "u1", "t1", 1*time.Hour)
	assert.False(t, s.IsExpired())

	s.ExpiresAt = time.Now().UTC().Add(-1 * time.Minute)
	assert.True(t, s.IsExpired())
}
