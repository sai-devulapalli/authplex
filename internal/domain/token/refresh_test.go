package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRefreshToken_IsExpiredRefresh(t *testing.T) {
	rt := RefreshToken{ExpiresAt: time.Now().UTC().Add(-1 * time.Minute)}
	assert.True(t, rt.IsExpiredRefresh())

	rt2 := RefreshToken{ExpiresAt: time.Now().UTC().Add(1 * time.Hour)}
	assert.False(t, rt2.IsExpiredRefresh())
}

func TestRefreshToken_IsRevoked(t *testing.T) {
	rt := RefreshToken{}
	assert.False(t, rt.IsRevoked())

	now := time.Now()
	rt.RevokedAt = &now
	assert.True(t, rt.IsRevoked())
}
